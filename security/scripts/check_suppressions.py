import json
import sys
import yaml

REPORT_PATH = "gitleaks-report.json"
POLICY_PATH = "security/policy.yml"


def load_findings(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        # Gitleaks doesn't write a report file when it finds nothing
        return []


def load_suppressed_ids(path):
    with open(path) as f:
        policy = yaml.safe_load(f)
    return {s["id"] for s in policy.get("suppressions", [])}


def main():
    findings = load_findings(REPORT_PATH)
    suppressed_ids = load_suppressed_ids(POLICY_PATH)

    blocking = [f for f in findings if f.get("Fingerprint") not in suppressed_ids]

    print(f"Total findings: {len(findings)}")
    print(f"Suppressed (reviewed): {len(findings) - len(blocking)}")
    print(f"Blocking (unreviewed): {len(blocking)}")

    if blocking:
        print("\nThe following findings are NOT suppressed and are blocking the build:\n")
        for f in blocking:
            print(f"  - {f.get('Fingerprint')}  ({f.get('Description')})")
        sys.exit(1)

    print("\nAll findings are suppressed or none were found. Passing.")
    sys.exit(0)


if __name__ == "__main__":
    main()