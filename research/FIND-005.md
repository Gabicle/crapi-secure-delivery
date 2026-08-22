# FIND-005: Broken Function Level Authorization + Missing Input Validation: Unrestricted Coupon Creation

**CVSS Score:** 6.5 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
**CWE:** CWE-862: Missing Authorization (primary, for the function-level
access dimension); CWE-20: Improper Input Validation (secondary, for the
unbounded/negative amount dimension)
**OWASP API Category:** API5:2023: Broken Function Level Authorization
(primary); API6:2023: Unrestricted Access to Sensitive Business Flows
(compounding, since the lack of validation means this business function
can be abused at scale, not just accessed by the wrong role)
**Status:** Confirmed
**Date found:** 2026-08-22

## Summary

Any authenticated user, not just an admin or merchant, can create
discount coupons with an arbitrary code and amount via the coupon
creation endpoint. The `amount` field additionally accepts values with no
bounds validation at all, including unrealistically large values and
negative values, neither of which should be valid for a discount amount.

## Affected Endpoint

```
POST /community/api/v2/coupon/new-coupon
```

## Steps to Reproduce

1. Authenticate as any regular (`ROLE_USER`) account, no admin/merchant
   role.
2. Send a request to create a coupon with a normal-looking amount.
   Observe success.
3. Repeat with an extreme value (e.g. `"999999"`) in place of a realistic
   discount amount. Observe success, with no server-side rejection.
4. Repeat with a negative value (e.g. `"-50"`). Observe success, with no
   server-side rejection.

## Evidence

### Request 1: baseline

```
POST {{baseUrl}}/community/api/v2/coupon/new-coupon
Authorization: Bearer <regular user token>
Content-Type: application/json

{
  "coupon_code": "SCHOOL95",
  "amount": "95"
}
```

Response:

```json
"Coupon Added in database"
{
  "coupon_code": "SCHOOL95",
  "amount": "95",
  "CreatedAt": "2026-08-22T21:16:50.702Z"
}
```

### Request 2: unbounded value

```json
{
  "coupon_code": "SCHOOLH",
  "amount": "999999"
}
```

Response: success, identical shape.

```json
{
  "coupon_code": "SCHOOLH",
  "amount": "999999",
  "CreatedAt": "2026-08-22T21:19:44.51Z"
}
```

### Request 3: negative value

```json
{
  "coupon_code": "SCHOOLN",
  "amount": "-50"
}
```

Response: success, identical shape.

```json
{
  "coupon_code": "SCHOOLN",
  "amount": "-50",
  "CreatedAt": "2026-08-22T21:20:04.919Z"
}
```

## Impact

Any registered user, without any elevated privilege, can mint an
unlimited number of discount coupons of arbitrary value, including
unrealistically large discounts. This is a direct financial-fraud vector
if these coupons can subsequently be applied to a real purchase (the
`apply-coupon` flow was not successfully tested in this pass and is
tracked separately as a follow-up; this finding is scored on the
confirmed creation behavior alone, not on unconfirmed downstream
exploitation). Separately, the negative-value case is worth flagging as a
specific concern: depending on how a "negative discount" is later applied
in a total-calculation, this could behave as an _increase_ to a user's
balance or an order total reduction beyond the item's value, rather than
a simple discount, though this is not confirmed here. It's a reasonable
question for whoever picks up the "apply coupon" follow-up test.

## Root Cause

Two independent, compounding gaps: (1) the coupon creation endpoint
performs no role check, there is no verification that the requesting
user holds a merchant/admin role before allowing coupon creation, a
function that should reasonably be privileged given its direct financial
impact; and (2) the `amount` field has no server-side validation at all,
no minimum, no maximum, no rejection of negative values.

## Recommended Fix

1. Restrict coupon creation to a merchant/admin role, following the same
   pattern recommended in FIND-003 for the video-deletion endpoint: add
   role-based access control before the handler logic runs.
2. Independently, add input validation on `amount`: reject negative
   values, and enforce a sane maximum aligned with actual business rules
   (e.g. a percentage cap, or an absolute currency ceiling).
3. Audit the `apply-coupon` flow specifically for reuse and calculation
   handling once it's functioning, given the direct relationship to this
   finding.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** No special skill or access needed beyond any
standard account, trivially discoverable by simply using the feature as
intended and noticing no role restriction exists, and no evidence of
validation or monitoring on coupon creation volume or value.

**Business Impact: High.** Direct potential for financial fraud at
scale if downstream coupon application isn't independently guarded;
even considered in isolation (creation alone), this represents a
complete breakdown of a financially-sensitive business function's access
control.

**Overall Severity: High** (High Likelihood × High Impact).
