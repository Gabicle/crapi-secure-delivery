# FIND-001: Broken Object Level Authorization — Vehicle Location Disclosure

**CVSS Score:** 6.5 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
**OWASP API Category:** API1:2023 — Broken Object Level Authorization
**Status:** Confirmed
**Date found:** 21/08/2026

## Summary

The vehicle location endpoint does not verify that the requesting user owns
the vehicle identified by `vehicleId`. Any authenticated user can retrieve
another user's real-time vehicle GPS coordinates, full name, and email
address by supplying that user's `vehicleId`, regardless of who owns it.

## Affected Endpoint

```
GET /identity/api/v2/vehicle/:vehicleId/location
```

## Steps to Reproduce

1. Authenticate as User A ("Test", test@example.com). Note User A's
   `carId`: `1929186d-8b67-4163-a208-de52a41f7301` (obtained from
   [source of this ID — which endpoint returned it to User A originally?]).
2. Authenticate as User B, obtaining a separate valid access token.
3. Using **User B's token**, send `GET /identity/api/v2/vehicle/1929186d-8b67-4163-a208-de52a41f7301/location`.
4. Observe: the server returns User A's vehicle location and personal
   details in full, despite the request being made by User B.

## Evidence

### Request

```
GET {{baseUrl}}/identity/api/v2/vehicle/1929186d-8b67-4163-a208-de52a41f7301/location
Authorization: Bearer <User B's token>
```

### Response

```json
{
  "carId": "1929186d-8b67-4163-a208-de52a41f7301",
  "vehicleLocation": {
    "id": 4,
    "latitude": "38.206348",
    "longitude": "-84.270172"
  },
  "fullName": "Test",
  "email": "test@example.com"
}
```

## Impact

An attacker with any valid crAPI account can retrieve the real-time GPS location, full name, and email address of any other user by supplying their vehicleId. Beyond the direct privacy violation, real-time location data creates a physical safety risk. An attacker can determine whether a target is home, track their movements, or use it to facilitate stalking or harassment. Because the endpoint is not rate-limited and requires no prior knowledge of the victim beyond a vehicleId, this is scalable: an attacker could enumerate or harvest location data for many users, not just one. It also chains with other findings in this project — a leaked vehicleId (e.g., from the "Get Post" excessive-data-exposure finding) is enough on its own to pull a stranger's live location.

## Root Cause

The endpoint conflates authentication with authorization: it correctly verifies that the request carries a valid token (authentication), but never checks whether the vehicleId in the URL actually belongs to the user identified by that token (authorization). The lookup is performed using the client-supplied vehicleId alone, with no comparison against the requester's own user ID. This is a textbook instance of CWE-639.

## Recommended Fix

Before returning vehicleLocation, the backend must verify that the vehicleId in the request belongs to the authenticated user making the request (e.g., a query scoped to WHERE vehicleId = ? AND ownerId = ?, returning 403/404 on mismatch, rather than a lookup on vehicleId alone). This ownership check should be enforced at the data-access layer, not just in application logic, and applied consistently across every "get resource by ID" endpoint in the identity/workshop services. Also this is likely a systemic pattern, not a single-endpoint bug, and other endpoints should be audited for the same missing check.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High** - low skill required, no special access needed, easy to
discover (ID visible in normal traffic), no evidence of detection/logging.

**Business Impact: Medium** - read-only confidentiality issue, but touches regulated PII (privacy/compliance exposure) and real reputational risk.

**Overall Severity: High**
