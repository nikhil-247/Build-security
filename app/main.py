from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scanner.authz import compare_authorized_identities
from scanner.http_checks import assess_target
from scanner.mapping import enrich_findings
from scanner.models import AssessmentResult
from scanner.poc import run_local_poc
from scanner.report import save_report, utc_now
from scanner.world_monitor import attack_surface_summary, profile_for_target

app = FastAPI(
    title="Build Security | World Monitor Security Assessment",
    version="1.0.0",
    description="Authorized, non-destructive security assessment workspace for SIH 2026 PS 26163.",
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC = BASE_DIR / "app" / "static"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

REPORT_NAME = re.compile(r"^[A-Za-z0-9_.-]+\.(json|html)$")


class AssessRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    endpoints: list[str] = Field(default_factory=list, max_length=100)
    headers: dict[str, str] = Field(default_factory=dict, max_length=30)
    auth_a: str | None = Field(default=None, max_length=4096)
    auth_b: str | None = Field(default=None, max_length=4096)
    authorization_check: bool = False
    authorized: bool = False


def _summary(result: AssessmentResult) -> dict:
    counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Info")}
    categories: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        categories[finding.category] = categories.get(finding.category, 0) + 1

    unique = {}
    for finding in result.findings:
        key = (finding.title, finding.severity)
        unique[key] = finding
    unique_counts = {severity: 0 for severity in counts}
    for _, finding in unique.items():
        unique_counts[finding.severity] += 1

    penalty = (
        unique_counts["Critical"] * 35
        + unique_counts["High"] * 20
        + unique_counts["Medium"] * 9
        + unique_counts["Low"] * 3
    )
    score = max(5, min(100, 100 - penalty))
    label = "Strong" if score >= 85 else "Watch" if score >= 65 else "At Risk" if score >= 40 else "Critical"
    return {
        "score": score,
        "label": label,
        "counts": counts,
        "categories": categories,
        "findings": len(result.findings),
        "checks": len(result.checks_run),
        "endpoints": 0,
    }


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "build-security", "version": app.version}


@app.get("/api/info")
def info():
    return {
        "name": "Build Security",
        "assessment_profile": profile_for_target("https://www.worldmonitor.app"),
        "subtitle": "World Monitor Security Assessment",
        "sih": "Smart India Hackathon 2026",
        "problem_statement": "26163",
        "mode": "authorized / non-destructive",
        "methods": ["GET"],
        "capabilities": [
            "security headers",
            "session cookies",
            "CORS",
            "transport / TLS",
            "API endpoint review",
            "authorized two-identity differential check",
            "JSON and HTML evidence reports",
        ],
    }


@app.post("/api/assess")
def assess(request: AssessRequest):
    if not request.authorized:
        raise HTTPException(403, "Confirm that you are authorized to assess this target before starting a scan.")
    if not request.target.startswith(("http://", "https://")):
        raise HTTPException(400, "Target must be an HTTP or HTTPS URL.")
    if request.authorization_check and not (request.auth_a and request.auth_b):
        raise HTTPException(400, "authorization_check requires auth_a and auth_b.")

    started = utc_now()
    timer = perf_counter()
    findings, checks = assess_target(request.target, request.endpoints, request.headers)
    notes = [
        "Assessment executed in authorized mode.",
        "Automated results are candidate findings and require manual validation.",
        "The scanner uses GET-only checks and does not perform destructive actions.",
        "Authorization differential testing uses only explicitly supplied test identities and endpoints.",
    ]

    if request.authorization_check:
        findings.extend(
            compare_authorized_identities(
                request.target,
                request.endpoints,
                request.auth_a or "",
                request.auth_b or "",
            )
        )
        checks.append("authorized two-identity GET differential check")

    findings = enrich_findings(findings)
    result = AssessmentResult(
        target=request.target,
        started_at=started,
        finished_at=utc_now(),
        findings=findings,
        checks_run=checks,
        notes=notes,
        attack_surface=attack_surface_summary(findings),
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = str(REPORTS_DIR / f"assessment-{stamp}")
    json_path, html_path = save_report(result, base)
    elapsed_ms = round((perf_counter() - timer) * 1000, 1)
    summary = _summary(result)
    summary["duration_ms"] = elapsed_ms
    summary["endpoints"] = len(request.endpoints)

    return {
        "result": result.model_dump(),
        "summary": summary,
        "reports": {
            "json": f"/api/report/{Path(json_path).name}",
            "html": f"/api/report/{Path(html_path).name}",
        },
    }


@app.get("/api/world-monitor/profile")
def world_monitor_profile():
    return profile_for_target("https://www.worldmonitor.app")

@app.post("/api/poc/{poc_id}")
def run_poc(poc_id: str, target: str = "http://127.0.0.1:8001"):
    try:
        return run_local_poc(poc_id, target)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"Controlled PoC failed: {exc}")

@app.get("/api/report/{filename}")
def get_report(filename: str):
    if not REPORT_NAME.match(filename):
        raise HTTPException(400, "Invalid report name.")
    path = (REPORTS_DIR / filename).resolve()
    if path.parent != REPORTS_DIR.resolve() or not path.exists():
        raise HTTPException(404, "Report not found.")
    media_type = "application/json" if path.suffix == ".json" else "text/html"
    return FileResponse(path, media_type=media_type, filename=path.name)
