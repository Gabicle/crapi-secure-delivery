# FIND-003: Broken Function Level Authorization + BOLA - Cross-User Video Deletion

**CVSS Score:** 6.5 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
**CWE:** CWE-862 - Missing Authorization (primary, for the BFLA dimension);
CWE-639 - Authorization Bypass Through User-Controlled Key (secondary, for
the BOLA dimension)
**OWASP API Category:** API5:2023 - Broken Function Level Authorization
(primary); API1:2023 - Broken Object Level Authorization (compounding)
**Status:** Confirmed
**Date found:** 2026-08-22

## Summary

The video deletion endpoint, despite living under an `/admin/` path prefix,
performs no role check and no ownership check. Any authenticated regular
user (`ROLE_USER`) can delete _any other user's_ video, with neither party
holding admin privileges. This is a compound failure: a function-level
authorization bypass (regular user reaching an admin-only-by-name endpoint)
stacked with an object-level authorization bypass (no check that the video
belongs to the requester).

## Affected Endpoint

```
DELETE /identity/api/v2/admin/videos/{videoId}
```

## Steps to Reproduce

1. Authenticate as User B. Upload a video via
   `POST /identity/api/v2/user/videos`. Note the returned video `id`.
2. Authenticate as User A - a separate, non-admin (`ROLE_USER`) account.
3. Using **User A's token**, send
   `DELETE /identity/api/v2/admin/videos/{User B's video id}`.
4. Observe: request succeeds (200). User B's video is deleted, despite
   User A having no admin role and no ownership relationship to the video.
5. Confirmed independently in two forms: (a) a user deleting their _own_
   video through this admin-path endpoint (proves the missing role check
   alone - BFLA), and (b) a user deleting _another user's_ video through
   the same endpoint (proves the missing role check _and_ missing
   ownership check together - BFLA + BOLA).

## Evidence

### Part A - Own-video deletion via admin-path endpoint (BFLA in isolation)

Captured from `crapi-web` access logs, same authenticated non-admin session
throughout:

```
"POST /identity/api/v2/user/videos HTTP/1.1" 200          <- video uploaded, id=6
"GET /identity/api/v2/user/videos/6 HTTP/1.1" 200          <- confirmed as own video
"DELETE /identity/api/v2/admin/videos/6 HTTP/1.1" 200      <- deleted via admin-path endpoint, non-admin token
```

### Part B - Cross-user deletion (BFLA + BOLA combined)

```
Request:
DELETE {{baseUrl}}/identity/api/v2/admin/videos/52
Authorization: Bearer <User A's token>

(video id 52 belongs to User B, uploaded separately under User B's
authenticated session - User A has no ownership relationship to it and
holds no admin role)

Response:
{
  "message": "User video deleted successfully.",
  "status": 200
}
```

Neither User A nor User B holds an admin role in either test - confirming
the endpoint's `/admin/` path enforces no actual role restriction.

### Part B - Persistence confirmation

As User B, attempting to retrieve the same video after deletion:

```
Request:
GET {{baseUrl}}/identity/api/v2/user/videos/52
Authorization: Bearer <User B's token>

Response:
{
  "message": "Video not found.",
  "status": 404
}
```

Confirms the deletion was real and persistent and not a false-positive 200
with no actual effect.

## Impact

Any authenticated user - no elevated privileges required - can permanently
delete any other user's uploaded video content. At scale, this allows an
attacker to systematically destroy other users' data across the entire
platform, not just their own. Unlike a read-only data leak, this is a
destructive integrity impact: the victim's data is gone, not just exposed.
Combined with the missing role check, this also indicates the `/admin/`
path prefix carries no actual enforcement — worth flagging as a signal to
audit every other endpoint under that prefix for the same missing check.

## Root Cause

The endpoint handler for `DELETE /identity/api/v2/admin/videos/{videoId}`
appears to perform two checks that are both missing: (1) no verification
that the requesting user's role is actually `ROLE_ADMIN` before proceeding

- the `/admin/` path is naming convention only, not an enforced boundary;
  and (2) no verification that the `videoId` being deleted belongs to the
  requesting user, the same class of missing check identified in FIND-001.

## Recommended Fix

1. Add role-based access control middleware/annotation to every route
   under `/admin/`, rejecting any request where the authenticated user's
   role is not `ROLE_ADMIN`, before the handler logic runs at all.
2. Independently of the role check, add an ownership check: before
   deleting a video, verify the requesting user either owns it or holds
   an admin role - the two checks should not be conflated, since a
   correctly-scoped admin function legitimately needs to act on other
   users' resources, whereas a regular-user-facing deletion function needs
   the ownership check instead.
3. Audit all other `/admin/` routes in the `identity` service for the same
   missing role check, given this same gap likely wasn't limited to just
   the video-deletion route.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High** - trivially discoverable (the path itself hints at
admin-only intent, inviting a quick test of whether that's enforced), no
special access needed beyond any standard account, and no evidence of
logging/alerting on cross-role or cross-user admin-path access.

**Business Impact: High** - unauthorized, irreversible destruction of user
data at scale; a real trust and reliability failure for any platform
storing user-generated content, with likely legal/compliance exposure
depending on what the destroyed data represented.

**Overall Severity: High** (High Likelihood × High Impact).
