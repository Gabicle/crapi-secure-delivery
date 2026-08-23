# FIND-010: Unhandled Exception Information Disclosure on check-otp Endpoints

**CVSS Score:** 5.3 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**CWE:** CWE-209: Generation of Error Message Containing Sensitive
Information (primary, for the disclosure itself); CWE-204: Observable
Response Discrepancy (secondary, this is also the fourth confirmed
enumeration oracle on this service)
**OWASP API Category:** API8:2023: Security Misconfiguration (primary,
improper error handling); API2:2023: Broken Authentication (compounding)
**Status:** Confirmed
**Date found:** 2026-08-23

## Summary

Submitting a check-otp request for an email that isn't registered
triggers an unhandled backend exception. Instead of the application's
normal JSON error response, the raw exception message is returned
directly to the client as plain text, disclosing internal implementation
details (entity field names, exception structure) and, as a side effect,
serving as a fourth independent confirmation that this service leaks
account-existence information via differentiated error responses.
Affects both the vulnerable (v2) and secured (v3) check-otp endpoints
identically, since both call the same underlying method where the
exception is thrown.

## Affected Endpoints

```
POST /identity/api/auth/v2/check-otp
POST /identity/api/auth/v3/check-otp
```

## Steps to Reproduce

1. Send a check-otp request using an email address that is not
   registered in the system, any OTP and password value.
2. Compare against a check-otp request using a real, registered email
   with a wrong OTP.
3. Observe the two responses differ not just in content but in format
   entirely, one is a normal JSON error, the other is raw, unwrapped
   exception text.

## Evidence

### Wrong OTP, real registered email (normal application error handling)

```json
{
  "message": "Invalid OTP! Please try again..",
  "status": 500
}
```

### Nonexistent email (unhandled exception leaks directly to client)

```bash
curl -k -i -X POST https://localhost:8443/identity/api/auth/v2/check-otp \
  -H "Content-Type: application/json" \
  -d '{"otp":"0000","password":"x","email":"userg@test.com"}'
```

```
HTTP/1.1 500
Content-Type: text/plain;charset=UTF-8
Content-Length: 60

User was not found for parameters {userEmail=userg@test.com}
```

Confirmed identical behavior on `/v3/check-otp` as well.

## Root Cause

`OtpServiceImpl.validateOTPAndEmail`, the shared helper method called by
both `validateOtp` (v2) and `secureValidateOtp` (v3), throws an
`EntityNotFoundException` when the lookup for the given email returns no
user, with no surrounding try/catch and no global exception handler
(e.g. a `@ControllerAdvice`) configured to intercept it. Spring Boot's
default fallback error handler serializes the raw exception instead,
returning its default `toString()`-style message directly to the client
as plain text, bypassing the application's normal `CRAPIResponse` JSON
error format entirely.

## Impact

Two distinct consequences from one root cause. First, information
disclosure: the raw exception reveals internal implementation details
(the entity field name `userEmail`, the use of a JPA-style repository
pattern, and the general shape of the backend's error handling) that
have no legitimate reason to be exposed to a client, and are useful
reconnaissance for an attacker refining further attacks against this
service. Second, this is a fourth independent enumeration oracle on the
`identity` service (following FIND-006 signup, FIND-007 login, and
FIND-008 forget-password), further reinforcing that account-existence
leakage is a pervasive, unaddressed pattern across this service rather
than an isolated oversight.

## Recommended Fix

1. Add a global exception handler (`@ControllerAdvice` /
   `@ExceptionHandler`) to the `identity` service that catches unhandled
   exceptions and returns the application's standard JSON error format,
   with a generic message, never a raw exception's default output.
2. Specifically for this code path, align with the same fix recommended
   in FIND-006/007/008: return an identical, generic response regardless
   of whether the email is registered, rather than allowing the
   distinction to surface at all, whether via a crafted message or an
   unhandled exception.
3. Given this is now the fourth instance of the same underlying pattern
   found independently on four different endpoints, this strongly
   supports treating it as a single, service-wide remediation item
   rather than four separate patches (see the cross-finding note already
   captured in FIND-008).

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** Trivially discovered by simply submitting an
invalid email, no special access or tooling required.

**Business Impact: Medium.** Primarily an information-disclosure and
enumeration issue rather than a direct compromise path on its own,
though the internal details leaked could meaningfully assist an attacker
in developing further attacks against this service.

**Overall Severity: High** (High Likelihood x Medium Impact).
