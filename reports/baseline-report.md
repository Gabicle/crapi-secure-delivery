# Baseline Security Report

**Target:** OWASP crAPI, pinned to `v1.1.6` (commit `700f03d12a392d9e408260b4beae72ed02a4a1a4`)
**Date:** 16-08-2026
**Scope:** Full ungated scan across every tool in the pipeline matrix, run manually and locally against the `app/` submodule and the running crAPI stack. Nothing in this pass was triaged, suppressed, or fixed. These are raw, as-is numbers representing the application's starting security posture before any pipeline gates, fixes, or custom detection rules were introduced.

This report is the "before" snapshot. It will be compared against `final-report.md` once the gated CI/CD pipeline, remediations, and detection rules (for manually discovered business-logic findings) are complete.

---

## Summary

| Tool      | Layer              | Findings                                                     |
| --------- | ------------------ | ------------------------------------------------------------ |
| Gitleaks  | Secrets            | 11                                                           |
| Semgrep   | SAST               | 111                                                          |
| Trivy     | SCA (dependencies) | 220 (7 Critical / 108 High / 84 Medium / 20 Low / 1 Unknown) |
| Checkov   | IaC                | 454 failed checks (informational, see scope note below)      |
| OWASP ZAP | DAST (passive)     | 37 alerts (0 High / 2 Medium / 31 Low)                       |

---

## Detail by tool

### Gitleaks (Secrets) - 11 findings

7 TLS private keys/certs (one per service: chatbot, community, gateway, identity ×2, web, workshop), plus 4 hardcoded JWTs inside the bundled Postman collection. These appear to be intentional local-dev artifacts (self-signed certs, example tokens) rather than a genuine leak of production credentials but flagged as-is per the ungated baseline rule of "run everything, fix nothing yet."

### Semgrep (SAST) - 111 findings

726 rules run across 497 tracked files (auto-detected rule sets across crAPI's Go, Java, Python, and TypeScript services). Not yet triaged for true/false positives.

### Trivy (SCA) - 220 findings

Dependency vulnerabilities across 5 manifests (Python `requirements.txt` files, npm, Go modules, Maven). Severity breakdown: 7 Critical, 108 High, 84 Medium, 20 Low, 1 Unknown.

_Note:_ Trivy's `fs` scan also runs a built-in secret detector, which separately flagged 10 secrets materially the same certs Gitleaks caught. Not counted twice in the summary table above; noted here for transparency.

### Checkov (IaC) - 454 failed checks

| Check type           | Passed | Failed |
| -------------------- | ------ | ------ |
| Kubernetes manifests | 728    | 207    |
| Helm charts          | 713    | 211    |
| Dockerfiles          | 768    | 14     |
| Secrets              | 0      | 13     |
| GitHub Actions       | 389    | 3      |
| OpenAPI spec         | 4      | 6      |

**Scope note:** This scan ran against crAPI's own vendored infrastructure (Helm charts, K8s manifests, Dockerfiles shipped by the upstream project), not infrastructure authored for this project. The actual gated IaC scan later in this project targets only project-authored files under `infra/`. This baseline number is informational context only and is **not** a target for remediation.

**Known overlap:** Kubernetes and Helm findings likely double-count significantly, since Helm templates render into the Kubernetes manifests also being scanned. The same misconfiguration can surface once as a Helm-chart finding and once as its rendered K8s equivalent. The raw total (454) should not be read as 454 independent issues.

### OWASP ZAP (DAST, passive) - 37 findings

Baseline (passive) scan only. The app was observed via crawl/traffic inspection, not actively attacked. 13 distinct alert types, 37 total instances, concentrated almost entirely in missing/misconfigured HTTP security headers (CSP, HSTS, X-Content-Type-Options, CORS-related headers, clickjacking protection) plus minor information disclosure (server version header, Unix timestamps). No High-risk findings expected, since passive mode doesn't attempt exploitation. Deeper authorization/business-logic issues are addressed separately via manual research (see `research/`), not by this scan.

---

## Cross-tool overlap summary

Several tools independently perform secret detection, which inflates the apparent "secrets" finding count if read naively:

| Tool               | Secrets found |
| ------------------ | ------------- |
| Gitleaks           | 11            |
| Trivy (built-in)   | 10            |
| Checkov (built-in) | 13            |

These are not three independent issue sets, they substantially overlap on the same underlying certs/keys. Total unique secret-related issues is closer to Gitleaks' 11 than to the naive sum of 34.

---

## What happens next

This baseline will be revisited after:

1. The gated CI/CD pipeline is built.
2. Findings are triaged: fixed, or suppressed with documented owner + justification + expiry.
3. Manual research identifies business-logic/authorization flaws the automated tools structurally can't catch, each documented in `research/FIND-XXX.md`.
4. Custom detection rules are added where relevant so the manually found classes of issue would be caught automatically going forward.

The resulting `final-report.md` will present the same tool-by-tool comparison, showing the delta.
