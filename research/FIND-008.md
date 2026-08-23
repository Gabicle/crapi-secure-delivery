# FIND-008: Forget-Password Enumeration + Missing Rate Limiting

**CVSS Score:** 5.3 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**CWE:** CWE-204: Observable Response Discrepancy (primary, for the
enumeration dimension); CWE-307: Improper Restriction of Excessive
Authentication Attempts (secondary, for the missing rate limiting)
**OWASP API Category:** API2:2023: Broken Authentication
**Status:** Confirmed
**Date found:** 2026-08-22

## Summary

The forget-password endpoint returns a distinct response depending on
whether the submitted email is registered, confirming account existence.
No rate limiting was observed on repeated requests. This is the third
confirmed instance of the identical weakness across the `identity`
service, following FIND-006 (signup) and FIND-007 (login), indicating a
systemic gap rather than three isolated bugs.

## Affected Endpoint

```
POST /identity/api/auth/forget-password
```

## Steps to Reproduce

1. Send a request with a known, real registered email. Note the response.
2. Send a request with a fabricated, never-registered email. Note the
   response.
3. Compare: the two responses differ in both status code and message,
   directly confirming registration status.
4. Send repeated requests in succession. Observe whether any throttling
   is applied.

## Evidence

### Request 1: real, registered email

```json
{
  "email": "usera@test.com"
}
```

Response: `200 OK`

```json
{
  "message": "OTP Sent on the provided email, usera@test.com",
  "status": 200
}
```

### Request 2: fabricated, unregistered email

```json
{
  "email": "doesnotexist@test.com"
}
```

Response: `404 Not Found`

```json
{
  "message": "Given Email is not registered! doesnotexist@test.com",
  "status": 404
}
```

No rate limiting observed across repeated requests.

## Systemic pattern across FIND-006, FIND-007, FIND-008

The same two weaknesses, response-based enumeration and absent rate
limiting, have now been independently confirmed on three separate
`identity` service endpoints (signup, login, forget-password). This
elevates the issue beyond three unrelated bugs: it indicates the service
lacks any centralized rate-limiting or generic-error-response policy for
authentication-adjacent endpoints, meaning any other similar endpoint not
yet tested should be assumed vulnerable to the same pattern until proven
otherwise, and any endpoint-specific fix should be paired with a
service-wide fix (see Recommended Fix).

## Impact

Beyond the enumeration itself (a third independent oracle for the same
underlying account data confirmed in FIND-006 and FIND-007), this
endpoint has a distinct secondary risk the other two don't share: a
successful request actually triggers a real side effect, an OTP email
being sent. With no rate limiting, an attacker can trigger unlimited OTP
emails to a target's real inbox, a notification-bombing / harassment
vector, and depending on the email provider's own abuse detection, may
risk the sending domain's deliverability or reputation if abused at
volume.

## Root Cause

Same as FIND-006 and FIND-007: the endpoint returns a message that
differs based on whether the email lookup succeeds, and no rate limiting
is applied to repeated requests.

## Recommended Fix

1. Return an identical, generic message regardless of whether the email
   is registered (e.g. "If this email is registered, an OTP has been
   sent"), the standard, widely-used pattern for this exact scenario.
2. Apply rate limiting to this endpoint, same recommendation as FIND-006
   and FIND-007.
3. Given this is the third confirmed instance of the same gap, address
   this as a single, service-wide fix (shared middleware/rate-limiting
   layer applied to all `identity` auth-adjacent endpoints) rather than
   three individual patches, and audit any remaining auth-related
   endpoints not yet tested for the same pattern.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** No special access needed, trivially discovered,
and confirmed exploitable at volume given no observed rate limiting.

**Business Impact: Medium.** Primarily reconnaissance value (a third
enumeration oracle), plus a distinct secondary nuisance/abuse vector
(unlimited OTP email triggering) not present in FIND-006 or FIND-007.

**Overall Severity: High** (High Likelihood x Medium Impact).
