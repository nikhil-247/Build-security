from __future__ import annotations
from .models import Finding
from .risk import profile_for

SCOPE_BY_CWE = {
    "CWE-862": "Authorization and access control",
    "CWE-942": "API security",
    "CWE-319": "Secure communication mechanisms",
    "CWE-614": "Authentication and session management",
    "CWE-1004": "Authentication and session management",
    "CWE-1275": "Authentication and session management",
    "CWE-693": "Client-side security controls",
    "CWE-200": "Data storage and privacy protections",
}

OWASP_WEB_BY_CWE = {
    "CWE-862": "A01:2025 Broken Access Control",
    "CWE-942": "A02:2025 Security Misconfiguration",
    "CWE-319": "A04:2025 Cryptographic Failures",
    "CWE-614": "A07:2025 Authentication Failures",
    "CWE-1004": "A07:2025 Authentication Failures",
    "CWE-1275": "A07:2025 Authentication Failures",
    "CWE-693": "A02:2025 Security Misconfiguration",
    "CWE-200": "A02:2025 Security Misconfiguration",
}

OWASP_API_BY_CWE = {
    "CWE-862": ["API1:2023 Broken Object Level Authorization", "API5:2023 Broken Function Level Authorization"],
    "CWE-942": ["API8:2023 Security Misconfiguration"],
    "CWE-319": ["API2:2023 Broken Authentication"],
    "CWE-614": ["API2:2023 Broken Authentication"],
    "CWE-1004": ["API2:2023 Broken Authentication"],
    "CWE-1275": ["API2:2023 Broken Authentication"],
}

POC_BY_CWE = {
    "CWE-942": {
        "id": "cors-wildcard-lab",
        "mode": "local-lab",
        "title": "CORS policy observation",
        "steps": ["Start the included vulnerable lab on 127.0.0.1:8001.", "Send a GET request with Origin: https://assessment.invalid.", "Capture Access-Control-Allow-Origin in the response.", "Confirm that the lab returns the wildcard policy without modifying any data."],
        "expected": "The local lab returns Access-Control-Allow-Origin: *.",
    },
    "CWE-614": {
        "id": "cookie-secure-lab",
        "mode": "local-lab",
        "title": "Session cookie flag observation",
        "steps": ["Start the included vulnerable lab.", "Send GET /.", "Inspect the Set-Cookie header.", "Verify whether Secure is present; do not reuse the cookie against any other target."],
        "expected": "The local lab sets a demo cookie without Secure.",
    },
    "CWE-1004": {
        "id": "cookie-httponly-lab",
        "mode": "local-lab",
        "title": "HttpOnly flag observation",
        "steps": ["Start the included vulnerable lab.", "Send GET /.", "Inspect the Set-Cookie header.", "Verify whether HttpOnly is absent."],
        "expected": "The local lab sets a demo cookie without HttpOnly.",
    },
    "CWE-1275": {
        "id": "cookie-samesite-lab",
        "mode": "local-lab",
        "title": "SameSite flag observation",
        "steps": ["Start the included vulnerable lab.", "Send GET /.", "Inspect the Set-Cookie header.", "Verify whether SameSite is absent."],
        "expected": "The local lab sets a demo cookie without SameSite.",
    },
    "CWE-862": {
        "id": "idor-differential-lab",
        "mode": "local-lab",
        "title": "Two-identity authorization differential",
        "steps": ["Use two controlled identities in a staging/lab environment.", "Request the same object endpoint with identity A and identity B.", "Compare status, object identifiers and ownership fields.", "Treat identical successful access as a review signal, not proof, until authorization policy is manually confirmed."],
        "expected": "A genuine authorization defect would permit identity B to read data outside its documented authorization boundary.",
    },
}

def attack_surface_for(finding: Finding) -> str:
    title = finding.title.lower()
    if "cookie" in title or "session" in title:
        return "Auth / Session"
    if "cors" in title or "endpoint" in title or "authorization" in title:
        return "REST API"
    if "transport" in finding.category.lower() or "https" in title or "hsts" in title:
        return "Web / Transport"
    if "client" in finding.category.lower():
        return "Web Client"
    return "Application Core"

def enrich_finding(finding: Finding) -> Finding:
    cwe = finding.cwe
    finding.ps_scope = finding.ps_scope or SCOPE_BY_CWE.get(cwe, "Cross-cutting security posture")
    finding.owasp_web = finding.owasp_web or OWASP_WEB_BY_CWE.get(cwe)
    finding.owasp_api = finding.owasp_api or OWASP_API_BY_CWE.get(cwe, [])
    finding.attack_surface = finding.attack_surface or attack_surface_for(finding)

    risk = profile_for(cwe, finding.title)
    finding.cvss_style = {
        "version": risk.version,
        "vector": risk.vector,
        "score": risk.score,
        "severity": risk.severity,
        "label": risk.label,
        "metrics": risk.metrics,
    }
    if not finding.poc:
        finding.poc = POC_BY_CWE.get(cwe)
    return finding

def enrich_findings(findings: list[Finding]) -> list[Finding]:
    return [enrich_finding(f) for f in findings]
