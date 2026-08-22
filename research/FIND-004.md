# FIND-004: Broken Object Property Level Authorization: Community Post PII Exposure

**CVSS Score:** 6.5 (Medium)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**CWE:** CWE-213: Exposure of Sensitive Information Due to Incompatible Policy
**OWASP API Category:** API3:2023: Broken Object Property Level Authorization
_(Note: crAPI's own challenges.md and OWASP's 2019 API Top 10 call this
"Excessive Data Exposure." The current 2023 edition merged that concept
into the renamed, broader BOPLA category. Same underlying bug class,
current terminology used here.)_
**Status:** Confirmed
**Date found:** 2026-08-22

## Summary

Two related community endpoints return the full author/commenter object
(nickname, email address, `vehicleid`, profile picture URL, and account
creation timestamp) to any authenticated user, regardless of whether they
have any relationship to the content or its participants. Authentication
is correctly enforced (a request with no token is rejected), but the
response body is not scoped to omit fields that shouldn't be visible to
arbitrary readers. One of the two endpoints returns this data in bulk
across every post in a single call, making it a significantly more
efficient harvesting vector than the other.

## Affected Endpoints

```
GET /community/api/v2/community/posts/{postId}
GET /community/api/v2/community/posts/recent
```

## Steps to Reproduce

### Endpoint 1: single post

1. Authenticate as User A. Create a post via
   `POST /community/api/v2/community/posts`.
2. Authenticate as User B. Comment on User A's post via
   `POST /community/api/v2/community/posts/{postId}/comment`.
3. Authenticate as User C, an account with no relationship to the post or
   either participant.
4. Using User C's own token, request
   `GET /community/api/v2/community/posts/{postId}`.
5. Observe: the response includes `author.email`, `author.vehicleid`,
   `author.profile_pic_url`, and `author.created_at` (User A's real data),
   and the same full object under `comments[].author` (User B's real
   data), fully visible to User C despite no connection to either user.

### Endpoint 2: bulk listing

1. Using any authenticated user's token, request
   `GET /community/api/v2/community/posts/recent`.
2. Observe: the response returns the same full author object for every
   post in the system in a single call, including seeded accounts with
   real, populated `vehicleid` values (not just the empty-string values
   seen on freshly created test accounts).

## Evidence

### Baseline: request rejected with no authentication

Confirms auth is enforced. The bug is authorization/data scoping, not
missing auth.

```
$ curl -k -i https://localhost:8443/community/api/v2/community/posts/RftQ4PKiJa7wmYRiKLTG4k

HTTP/1.1 401 Unauthorized
```

### Endpoint 1: request with User C's valid, unrelated token

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

### Endpoint 2: bulk listing with real vehicleId values exposed

```
GET {{baseUrl}}/community/api/v2/community/posts/recent
Authorization: Bearer <any authenticated user's token>
```

Response excerpt, three seeded accounts with real (non-empty) vehicle IDs
returned in a single call:

```json
{
  "author": { "nickname": "Robot", "email": "robot001@example.com", "vehicleid": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5" }
},
{
  "author": { "nickname": "Pogba", "email": "pogba006@example.com", "vehicleid": "cd515c12-0fc1-48ae-8b61-9230b70a845b" }
},
{
  "author": { "nickname": "Adam", "email": "adam007@example.com", "vehicleid": "f89b5f21-7829-45cb-a650-299a61090378" }
}
```

## Impact

Any registered user, without needing any relationship to a post's author
or commenters, can harvest real email addresses and other PII simply by
browsing or enumerating posts. The `/posts/recent` endpoint makes this
significantly worse than a single-post leak: one unauthenticated
relationship, one call, and an attacker gets PII for every post's
participants at once, rather than needing to know or guess individual
post IDs. At scale, this allows systematic collection of the platform's
user base email addresses, enabling targeted phishing, spam, or
credential-stuffing attacks using harvested-but-verified real accounts.

**Chained impact with FIND-001:** the leaked `author.vehicleid` field is
particularly severe, and this is now backed by real evidence, not just
theoretical reasoning. The `/posts/recent` response above shows three
real, populated vehicle IDs harvested in a single call with no
relationship to any of the three accounts. Each of those IDs can be fed
directly into FIND-001 (BOLA on `/vehicle/{carId}/location`) to retrieve
that user's live GPS location, name, and email. In other words, this
finding provides the reconnaissance step (harvesting valid vehicle IDs at
scale from public content, with a single bulk-listing call doing the work
of many individual lookups) that makes FIND-001 practically exploitable
against arbitrary users, rather than requiring an attacker to already
know a target's specific ID. The two findings should be read together as
a single attack chain, not in isolation.

## Root Cause

Both endpoints' response serialization includes the full author object
(and, for the single-post endpoint, full author objects nested inside
each comment) without filtering out fields that should be scoped to the
object owner only. The API appears to reuse the same internal
user/author representation for "data the owner should see about
themselves," "data any reader of a public post should see about that
post's participants," and "data returned in a bulk listing," with no
distinction applied at the serialization layer in any of the three
contexts.

## Recommended Fix

Introduce a separate, restricted "public author" representation
(nickname, profile picture, not email, not vehicleid, not other PII)
used when serializing posts and comments for any context where the
reader is not the resource owner, including bulk listings. This should
be enforced at the API/serialization layer, not left to the frontend to
selectively decide what to display. The raw API response itself should
never contain the excess fields in the first place, since anyone can
bypass the UI and call either endpoint directly, as demonstrated here.
The listing endpoint in particular should be prioritized, since it
exposes the same data at far greater efficiency per request.

## Likelihood & Business Impact (OWASP Risk Rating)

**Likelihood: High.** Trivially discoverable (a single normal use of the
app reveals it, no special testing required), no special access beyond a
standard account, and no evidence of rate-limiting or monitoring on
repeated post-fetching or listing calls that would catch bulk
harvesting. The bulk-listing endpoint makes mass harvesting especially
low-effort.

**Business Impact: Medium.** Real privacy violation and compliance
exposure (email and vehicleId are regulated PII under most privacy
frameworks), and a concrete enabler for downstream phishing,
credential-stuffing, and location-tracking campaigns (see Chained Impact
above). Scored here on this finding's own standalone impact, data
exposure, not destruction or direct account compromise, per standard
practice of scoring each finding independently and documenting chained
risk narratively rather than folding it into a single finding's score.

**Overall Severity: High** (High Likelihood x Medium Impact).
