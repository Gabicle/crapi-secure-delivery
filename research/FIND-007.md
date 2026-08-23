# FIND-007: Login Enumeration + Missing Rate Limiting (Brute-Force)

**CVSS Score:** 5.3 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**CWE:** CWE-204: Observable Response Discrepancy (primary, for the
enumeration dimension); CWE-307: Improper Restriction of Excessive
Authentication Attempts (secondary, for the missing rate limiting)
**OWASP API Category:** API2:2023: Broken Authentication
**Status:** Confirmed
**Date found:** 2026-08-23

## Summary

The login endpoint returns a distinct error message depending on whether
the submitted email is registered or not, allowing account enumeration
independent of FIND-006's signup-based enumeration. Separately, and more
severely, no rate limiting or lockout is applied to repeated failed login
attempts against the same account, allowing unlimited password guesses.
Combined, an attacker can confirm which accounts exist and then
brute-force their passwords with no throttling in the way.

## Affected Endpoint

```
POST /identity/api/auth/login
```

## Steps to Reproduce

1. Send a login request using a known, real registered email with an
   incorrect password. Note the response message.
2. Send a login request using a fabricated, never-registered email with
   any password. Note the response message.
3. Compare the two messages: they are distinct and disclose which case
   occurred.
4. Send repeated login requests with a fixed real email and an incorrect
   password, in rapid succession. Observe whether any throttling,
   lockout, or delay is applied.

## Evidence

### Request 1: real email, wrong password

```json
{
  "email": "usera@test.com",
  "password": "fakepassword"
}
```

Response: `401 Unauthorized`

```json
{
  "token": null,
  "type": "",
  "message": "Invalid Credentials",
  "mfaRequired": false
}
```

### Request 2: fabricated, unregistered email

```json
{
  "email": "totallyfakeuser99999@nowhere.com",
  "password": "anything"
}
```

Response:

```json
{
  "token": null,
  "type": "",
  "message": "Given Email is not registered! ",
  "mfaRequired": false
}
```

The two messages are distinct ("Invalid Credentials" versus "Given Email
is not registered!"), directly confirming whether a given email belongs
to a registered account.

### Rate limiting check

20 identical failed login attempts sent against the same real account in
a tight loop:

```bash
for i in {1..20}; do
  curl -k -s -o /dev/null -w "%{http_code}\n" -X POST https://localhost:8443/identity/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"usera@test.com","password":"fakepassword"}'
done
```

Result: `401` returned on all 20 attempts, with no change in behavior,
status code, or response timing across the sequence.

## Impact

This finding compounds two problems into a practical account-takeover
path. First, the login endpoint provides a second, independent
enumeration oracle beyond FIND-006's signup-based one, an attacker can
confirm real accounts via either endpoint. Second, and more severely,
the complete absence of rate limiting on login means that once an
account is confirmed to exist (via this endpoint, FIND-006, or any other
source such as a prior data breach), an attacker can attempt unlimited
password guesses against it with no lockout, delay, or CAPTCHA
challenge. This moves beyond reconnaissance into a direct credential
brute-force path toward full account compromise. Note that the login
response includes an `mfaRequired` field, suggesting MFA exists as a
capability in the system, but it was not triggered or enforced during
this testing, worth flagging as a separate question of whether MFA is
consistently required for all accounts or only under certain conditions.

## Root Cause

Two independent, compounding gaps: (1) the login handler returns a
message that differs depending on whether the email lookup itself
succeeds or fails, rather than a single generic failure message covering
both "email not found" and "password incorrect" cases; and (2) no rate
limiting, lockout, or backoff is applied to repeated failed login
attempts, whether scoped per-account or per-source.

## Recommended Fix

1. Return an identical, generic message ("Invalid email or password")
   regardless of whether the email exists or the password was wrong,
   eliminating the enumeration signal entirely.
2. Implement account lockout or progressive rate limiting after a
   defined number of failed attempts (e.g. exponential backoff, temporary
   lockout, or a CAPTCHA challenge past a threshold). This is a higher
   priority than the equivalent fix on FIND-006's signup endpoint, since
   an unthrottled login endpoint enables direct credential compromise,
   not just reconnaissance.
3. Investigate whether MFA (referenced by the `mfaRequired` response
   field) can be consistently enforced as an additional layer of
   protection against successful brute-force attempts, independent of
   fixing the rate-limiting gap itself.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** No special access needed, trivially discovered by
comparing two ordinary login attempts, and confirmed fully automatable
with no observed friction across 20 rapid repeated attempts.

**Business Impact: High.** Unlike FIND-006, this isn't limited to
reconnaissance value. Combined with no rate limiting, this represents a
direct, practical path to credential compromise and full account
takeover via brute force, not merely a signal usable in some other
attack.

**Overall Severity: Critical** (High Likelihood x High Impact).
