"""
security/scripts/gate.py

Generalized policy gate: reads a tool's findings report, normalizes it via a
per-tool adapter, checks each finding against security/policy.yml, and exits
non-zero if any finding is blocking (not suppressed, and meets/exceeds the
tool's configured block threshold).

Usage:
    python3 security/scripts/gate.py <tool_key> <report_path>

Example:
    python3 security/scripts/gate.py secrets gitleaks-report.json
    python3 security/scripts/gate.py sast reports/raw/semgrep-baseline.json

Adding a new tool later means writing one new adapt_<tool>() function and
adding it to ADAPTERS. evaluate() should never need to change.
"""

import json
import sys
import yaml

POLICY_PATH = "security/policy.yml"


def load_policy(path=POLICY_PATH):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def suppressed_ids(policy):
    return {s["id"] for s in policy.get("suppressions", [])}


# --- Adapters: one per tool. Each returns a list of dicts shaped like: ---
# --- {"id": str, "severity": str | None, "description": str}          ---


def adapt_gitleaks(report_path):
    try:
        with open(report_path, encoding="utf-8") as f:
            findings = json.load(f)
    except FileNotFoundError:
        # Gitleaks doesn't write a report file when it finds nothing
        return []

    return [
        {
            "id": f["Fingerprint"],
            "severity": None,  # Gitleaks findings are treated as block:any
            "description": f.get("Description", ""),
        }
        for f in findings
    ]


def adapt_semgrep(report_path):
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for r in data.get("results", []):
        # Strip the container mount prefix so IDs stay stable across local
        # docker runs and CI runs (both should resolve to the same path).
        path = r["path"].removeprefix("/repo/")

        # NOTE: Semgrep's stable fingerprint (extra.fingerprint) requires a
        # Semgrep Pro/AppSec login and is not available on the OSS tier used
        # here ("requires login" is the literal value returned). This
        # synthetic id (path:rule:line) is a reasonable substitute at this
        # project's scale, but it is fragile to line drift: if a file is
        # edited and a suppressed finding's line number shifts, this id will
        # stop matching and the finding will re-block until re-suppressed.
        findings.append(
            {
                "id": f"{path}:{r['check_id']}:{r['start']['line']}",
                "severity": r["extra"]["severity"],
                "description": r["extra"].get("message", ""),
            }
        )
    return findings


def adapt_trivy(report_path):
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for result in data.get("Results", []):
        if result.get("Class") != "lang-pkgs":
            continue  # skip Trivy's own secret-scan results — Gitleaks
                      # already owns the secrets stage; including these
                      # here would duplicate that gate under a third
                      # tool's ID namespace instead of adding real coverage.

        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "id": f"{target}:{v['VulnerabilityID']}:{v['PkgName']}",
                    "severity": v.get("Severity"),
                    "description": v.get("Title", ""),
                }
            )
    return findings


def adapt_checkov(report_path):
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    # NOTE: Checkov's OSS/free-tier CLI does not populate `severity` at all
    # (always returns None) — real severity data requires a Bridgecrew/
    # Prisma Cloud platform account, which this project doesn't have. Same
    # class of limitation as Semgrep's paid-only fingerprint. Because of
    # this, policy.yml's `iac` policy uses block: any rather than
    # severity tiers — there's no real severity data here to tier on.
    findings = []
    for block in data if isinstance(data, list) else [data]:
        if block.get("check_type") == "secrets":
            continue  # overlaps with Gitleaks/Trivy/Semgrep secret detection

        for c in block.get("results", {}).get("failed_checks", []):
            findings.append(
                {
                    "id": f"{c.get('file_path')}:{c.get('check_id')}:{c.get('resource')}",
                    "severity": c.get("severity"),
                    "description": c.get("check_name", ""),
                }
            )
    return findings


ADAPTERS = {
    "secrets": adapt_gitleaks,
    "sast": adapt_semgrep,
    "sca": adapt_trivy,
    "iac": adapt_checkov,
}


# --- Core gate logic. Should not need to change when a new tool is added. ---


def evaluate(tool_key, report_path, policy):
    if tool_key not in ADAPTERS:
        raise ValueError(f"No adapter registered for tool_key '{tool_key}'")

    findings = ADAPTERS[tool_key](report_path)
    ids_already_suppressed = suppressed_ids(policy)
    rules = policy["policies"].get(tool_key, {})
    block_rule = rules.get("block")
    ignore_paths = rules.get("ignore_paths", [])

    blocking = []
    for f in findings:
        if f["id"] in ids_already_suppressed:
            continue

        # Vendored/third-party paths are scanned for visibility but never
        # block the build — see the ignore_paths comment in policy.yml.
        if any(f["id"].startswith(p) for p in ignore_paths):
            continue

        if block_rule == "any":
            blocking.append(f)
        elif isinstance(block_rule, list) and f["severity"] in block_rule:
            blocking.append(f)

    return findings, blocking


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 security/scripts/gate.py <tool_key> <report_path>")
        sys.exit(2)

    tool_key, report_path = sys.argv[1], sys.argv[2]
    policy = load_policy()
    findings, blocking = evaluate(tool_key, report_path, policy)

    print(f"[{tool_key}] Total findings: {len(findings)}")
    print(f"[{tool_key}] Not blocking (suppressed, ignored path, or below threshold): {len(findings) - len(blocking)}")
    print(f"[{tool_key}] Blocking (unreviewed or over threshold): {len(blocking)}")

    if blocking:
        print(f"\nThe following {tool_key} findings are blocking the build:\n")
        for f in blocking:
            sev = f"[{f['severity']}] " if f["severity"] else ""
            print(f"  - {sev}{f['id']}  ({f['description']})")
        sys.exit(1)

    print(f"\nAll {tool_key} findings are suppressed or none were found. Passing.")
    sys.exit(0)


if __name__ == "__main__":
    main()