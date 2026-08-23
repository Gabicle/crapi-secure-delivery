# FIND-006: User Enumeration via Signup Endpoint, No Rate Limiting

**CVSS Score:** 5.3 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**CWE:** CWE-204: Observable Response Discrepancy (primary, for the
enumeration itself); CWE-307: Improper Restriction of Excessive
Authentication Attempts (secondary, for the missing rate limiting)
**OWASP API Category:** API2:2023: Broken Authentication
**Status:** Confirmed
**Date found:** 2026-08-23

## Summary

The signup endpoint returns a distinct, specific error message when
either the submitted email or phone number is already registered,
explicitly echoing back the matched value and which field matched. This
allows an unauthenticated attacker to determine whether a given email
address or phone number belongs to a registered account, without needing
to guess a password or log in. No rate limiting was observed on repeated
signup attempts, making mass enumeration practical to automate.

## Affected Endpoint

```
POST /identity/api/auth/signup
```

## Steps to Reproduce

1. Send a signup request using a known, real registered email, paired
   with a fabricated phone number. Observe the response.
2. Send a second signup request using a fabricated email, paired with a
   known, real registered phone number. Observe the response.
3. Compare both responses: each independently confirms which specific
   field is already registered, with the value echoed back.
4. Send multiple rapid signup attempts in succession with varied
   email/number combinations. Observe whether any throttling,
   lockout, or delay is applied.

## Evidence

### Request 1: real email, fabricated number

```json
{
  "name": "usera",
  "email": "usera@test.com",
  "number": "2234567899",
  "password": "userA123!"
}
```

Response:

```json
{
  "message": "Email already registered! Email: usera@test.com",
  "status": 403
}
```

### Request 2: real number, fabricated other fields

```json
{
  "name": "usera",
  "email": "usera@test.com",
  "number": "1234567890",
  "password": "userA123!"
}
```

Response:

```json
{
  "message": "Number already registered! Number: 1234567890",
  "status": 403
}
```

### Rate limiting check

Multiple signup attempts sent in rapid succession with varied
email/number values. No throttling, lockout, or increasing delay was
observed at any point.

## Impact

An attacker can determine, with certainty, whether a specific email
address or phone number is associated with a registered account on this
platform, without needing any valid credentials. Combined with the
absence of rate limiting, this is fully automatable: an attacker could
feed in a list of emails or phone numbers (e.g. from a leaked database
elsewhere, or a generated list of likely values) and mass-confirm which
ones are active accounts here. This has real downstream value to an
attacker beyond simple curiosity: confirmed-valid accounts are higher-
value targets for credential-stuffing attacks (using passwords leaked
from other breaches) since effort isn't wasted on non-existent accounts,
and confirmed phone numbers/emails are more valuable for targeted
phishing or SIM-swap-adjacent social engineering than an unconfirmed
guess.

## Root Cause

The signup handler performs its uniqueness check on email and phone
number sequentially, and returns a specific, field-differentiated error
message immediately upon the first match, rather than a generic response
that doesn't disclose which field (or whether either field) matched an
existing record. Separately, no rate limiting or throttling is applied
to this endpoint at all.

## Recommended Fix

1. Return a generic, non-differentiating message for any signup
   validation failure related to existing accounts (e.g. "Unable to
   complete signup with the provided information") rather than
   confirming which specific field matched an existing record.
2. Apply rate limiting to the signup endpoint (e.g. per-IP and/or
   per-target-value throttling) independent of the message-wording fix,
   since even a generic error message doesn't fully prevent enumeration
   if unlimited attempts are still possible via timing or other side
   channels; rate limiting is the more durable mitigation.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** No special skill or access needed at all, not even
an existing account, trivially discoverable by simply attempting signup
with a known value, and confirmed exploitable at volume given the
absence of any rate limiting.

**Business Impact: Medium.** Enables targeted attacks against confirmed-
real accounts (credential stuffing, phishing) rather than directly
compromising any account itself; a meaningful reconnaissance capability
for an attacker rather than a direct breach on its own.

**Overall Severity: High** (High Likelihood x Medium Impact).
