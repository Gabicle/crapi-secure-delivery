# Manual Verification Candidates

Findings surfaced by automated tooling that look like real, exploitable
issues rather than noise or vendored-cert artifacts. Not yet manually
verified. Each one that's confirmed becomes its own `research/FIND-XXX.md`

- [ ] **Unverified JWT decode** — `app/services/workshop/utils/jwt.py:61`.
      Semgrep: JWT decoded with `verify=False`, bypassing signature
      verification. Test: can a forged/tampered token be accepted by an
      endpoint using this path?

- [ ] **SQL injection (raw query)** — `app/services/workshop/crapi/shop/views.py:388`.
      Semgrep: raw SQL string built via concatenation with untrusted input.

- [ ] **SQL injection (tainted string)** — `app/services/workshop/crapi/shop/views.py:389`.
      Semgrep: user input used to manually construct a SQL string. Likely
      related to the finding above (same file, adjacent line) — verify
      whether these are the same underlying issue or two distinct sinks.

- [ ] **Disabled TLS certificate validation** — 4 locations:
  - `app/services/workshop/core/management/commands/seed_database.py:220`
  - `app/services/workshop/crapi/merchant/views.py:87`
  - `app/services/workshop/crapi/shop/views.py:141`
  - `app/services/workshop/utils/jwt.py:53`

  Semgrep: certificate verification explicitly disabled on outbound
  requests. Likely intentional for the local self-signed cert setup
  (see `security/policy.yml` cert suppressions) — worth confirming
  whether this is dev-only convenience or a broader pattern that would
  also disable validation against real external services.

## SCA (Trivy) — Vendored Dependency Findings

115 findings (7 Critical, 108 High) in `app/`'s pinned dependency tree,
scoped out of the `sca` gate (`ignore_paths` in `security/policy.yml`) —
gating on pre-existing findings in a vendored, pinned target is the
"blocking on legacy debt" anti-pattern real SCA gates avoid.

Root cause and fix path were identified for the 5 Critical findings
(remediation is a version bump, not a logic fix, since these are
dependency CVEs rather than app code flaws). Bumps were deliberately
**not applied** to the submodule — the goal of this project is
demonstrating detection, triage, and gating discipline, not maintaining
a patched fork of crAPI. Documented here as a completed triage decision:

- [ ] `fastmcp` (SSRF via path traversal) — fix path identified, not applied
- [ ] `langchain-core` (RCE via serialization) — fix path identified, not applied
- [ ] `unstructured` (path traversal → arbitrary file write) — fix path identified, not applied
- [ ] `shell-quote` (RCE via command injection) — fix path identified, not applied
- [ ] `websocket-driver` (DoS) — fix path identified, not applied

Remaining 108 High findings (mostly Go/npm transitive dependencies,
largely DoS-class) are tracked as known debt, not individually triaged.
