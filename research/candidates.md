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
