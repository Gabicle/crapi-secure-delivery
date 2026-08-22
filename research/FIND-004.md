# FIND-004: Broken Object Property Level Authorization — Community Post PII Exposure

**CVSS Score:** 6.5 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**CWE:** CWE-213 - Exposure of Sensitive Information Due to Incompatible Policy
**OWASP API Category:** API3:2023 - Broken Object Property Level Authorization
_(Note: crAPI's own challenges.md and OWASP's 2019 API Top 10 call this
"Excessive Data Exposure" - the current 2023 edition merged that concept
into the renamed, broader BOPLA category. Same underlying bug class,
current terminology used here.)_
**Status:** Confirmed
**Date found:** 2026-08-22

## Summary

The community post retrieval endpoint returns the full author/commenter
object i.e nickname, email address, `vehicleid`, profile picture URL, and
account creation timestamp to any authenticated user who views the
post, regardless of whether they have any relationship to the post or its
participants. Authentication is correctly enforced (a request with no
token is rejected), but the response body is not scoped to omit fields
that shouldn't be visible to arbitrary readers.

## Affected Endpoint

```
GET /community/api/v2/community/posts/{postId}
```

## Steps to Reproduce

1. Authenticate as User A. Create a post via
   `POST /community/api/v2/community/posts`.
2. Authenticate as User B. Comment on User A's post via
   `POST /community/api/v2/community/posts/{postId}/comment`.
3. Authenticate as User C - an account with no relationship to the post or
   either participant.
4. Using User C's own token, request
   `GET /community/api/v2/community/posts/{postId}`.
5. Observe: the response includes `author.email`, `author.vehicleid`,
   `author.profile_pic_url`, and `author.created_at` (User A's real data),
   and the same full object under `comments[].author` (User B's real
   data) — fully visible to User C despite no connection to either user.

## Evidence

### Baseline: request rejected with no authentication (confirms auth is

### enforced — the bug is authorization/data scoping, not missing auth)

```
$ curl -k -i https://localhost:8443/community/api/v2/community/posts/RftQ4PKiJa7wmYRiKLTG4k

HTTP/1.1 401 Unauthorized
```

### Request with User C's valid, unrelated token

```
$ curl -k -i https://localhost:8443/community/api/v2/community/posts/RftQ4PKiJa7wmYRiKLTG4k \
  -H "Authorization: Bearer <User C's token>"

HTTP/1.1 200 OK
{
  "id": "RftQ4PKiJa7wmYRiKLTG4k",
  "title": "UserA posting.",
  "content": "Est maiores voluptas velit. Necessitatibus vero veniam quos nobis.",
  "author": {
    "nickname": "usera",
    "email": "usera@test.com",
    "vehicleid": "",
    "profile_pic_url": "",
    "created_at": "2026-08-22T19:38:16.381Z"
  },
  "comments": [
    {
      "content": "comment from user b.",
      "author": {
        "nickname": "userb",
        "email": "userb@test.com"
      }
    }
  ],
  "authorid": 8
}
```

## Impact

Any registered user without needing any relationship to a post's author
or commenters can harvest real email addresses and other PII simply by
browsing or enumerating posts (the `/posts/recent` listing endpoint
returns this same data across many posts at once, compounding the
exposure). At scale, this allows systematic collection of the platform's
user base email addresses, enabling targeted phishing, spam, or
credential-stuffing attacks using harvested-but-verified real accounts.

**Chained impact with FIND-001:** the leaked `author.vehicleid` field is
particularly severe. This endpoint hands an attacker a user's `vehicleId`
for free - no need to interact with the vehicle system at all, just read
a post that user commented on. That `vehicleId` can then be fed directly
into FIND-001 (BOLA on `/vehicle/{carId}/location`) to retrieve that
user's live GPS location, name, and email. In other words, this finding
provides the reconnaissance step (harvesting valid vehicle IDs at scale
from public content) that makes FIND-001 practically exploitable against
arbitrary users, rather than requiring an attacker to already know a
target's specific ID. The two findings should be read together as a
single attack chain, not in isolation.

## Root Cause

The endpoint's response serialization includes the full author object
(and full author objects nested inside each comment) without filtering
out fields that should be scoped to the object owner only. The API
appears to reuse the same internal user/author representation for both
"data the owner should see about themselves" and "data any reader of a
public post should see about that post's participants," with no
distinction applied at the serialization layer.

## Recommended Fix

Introduce a separate, restricted "public author" representation
(nickname, profile picture — not email, not other PII) used specifically
when serializing posts/comments for readers who are not the resource
owner. This should be enforced at the API/serialization layer, not left
to the frontend to selectively decide what to display — the raw API
response itself should never contain the excess fields in the first
place, since anyone can bypass the UI and call the endpoint directly (as
demonstrated here).

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High** - trivially discoverable (a single normal use of the
app reveals it, no special testing required), no special access beyond a
standard account, and no evidence of rate-limiting or monitoring on
repeated post-fetching that would catch bulk harvesting.

Business Impact: Medium - real privacy violation and compliance exposure (email and vehicleId are regulated PII under most privacy frameworks), and a concrete enabler for downstream phishing, credential-stuffing, and location-tracking campaigns (see Chained Impact above). Scored here on this finding's own standalone impact - data exposure, not destruction or direct account compromise per standard practice of scoring each finding independently and documenting chained risk narratively rather than folding it into a single finding's score.

**Overall Severity: High** (High Likelihood × Medium Impact).
