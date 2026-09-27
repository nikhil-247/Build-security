from __future__ import annotations
import argparse
from .mapping import enrich_findings
from .models import AssessmentResult
from .world_monitor import attack_surface_summary
from .http_checks import assess_target
from .authz import compare_authorized_identities
from .report import save_report, utc_now

def parse_header(values: list[str]) -> dict[str, str]:
    out = {}
    for item in values:
        if ":" not in item:
            raise SystemExit(f"Invalid --header value: {item!r}. Use 'Name: Value'.")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out

def main():
    p = argparse.ArgumentParser(description="World Monitor authorized security assessment tool")
    p.add_argument("--target", required=True)
    p.add_argument("--endpoint", action="append", default=[])
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--auth-a")
    p.add_argument("--auth-b")
    p.add_argument("--authorization-check", action="store_true")
    p.add_argument("--output", default="reports/assessment")
    args = p.parse_args()

    started = utc_now()
    headers = parse_header(args.header)
    findings, checks = assess_target(args.target, args.endpoint, headers)
    notes = [
        "Automated findings are candidates and require manual confirmation before being reported as confirmed vulnerabilities.",
        "Only configured GET endpoints were tested by the automated scanner.",
        "No brute-force, exploit-chain, write, delete, or production-impacting actions were performed.",
    ]

    if args.authorization_check:
        if not (args.auth_a and args.auth_b):
            raise SystemExit("--authorization-check requires --auth-a and --auth-b test credentials.")
        findings.extend(compare_authorized_identities(args.target, args.endpoint, args.auth_a, args.auth_b))
        checks.append("authorized two-identity GET differential check")

    findings = enrich_findings(findings)
    result = AssessmentResult(target=args.target, started_at=started, finished_at=utc_now(), findings=findings, checks_run=checks, notes=notes, attack_surface=attack_surface_summary(findings))
    json_path, html_path = save_report(result, args.output)
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    print(f"Findings: {len(findings)}")

if __name__ == "__main__":
    main()
