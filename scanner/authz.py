from __future__ import annotations
from urllib.parse import urljoin
import requests
from .models import Finding

def compare_authorized_identities(target: str, endpoints: list[str], auth_a: str, auth_b: str) -> list[Finding]:
    findings: list[Finding] = []
    base = target.rstrip("/") + "/"
    headers_a = {"Authorization": auth_a, "User-Agent": "WorldMonitor-Security-Assessment/1.0"}
    headers_b = {"Authorization": auth_b, "User-Agent": "WorldMonitor-Security-Assessment/1.0"}

    for endpoint in endpoints:
        url = urljoin(base, endpoint.lstrip("/"))
        try:
            a = requests.get(url, headers=headers_a, timeout=8, allow_redirects=True)
            b = requests.get(url, headers=headers_b, timeout=8, allow_redirects=True)
        except requests.RequestException as exc:
            findings.append(Finding(
                title="Authorization differential check failed",
                category="Authorization and access control",
                severity="Info", confidence="High",
                affected_component=url,
                description="The GET-only comparison could not complete.",
                evidence=[str(exc)],
                remediation=["Verify the two authorized test identities and endpoint availability."],
                verification="Repeat the same comparison after restoring connectivity.",
            ))
            continue

        if a.status_code == 200 and b.status_code == 200 and a.text == b.text and len(a.text) > 0:
            findings.append(Finding(
                title="Potential authorization policy overlap",
                category="Authorization and access control",
                severity="Medium", confidence="Low",
                affected_component=url,
                description="Two distinct authorized identities received byte-identical successful responses for an endpoint that may contain user/role-specific data. This is a review signal, not proof of IDOR or privilege escalation.",
                evidence=[f"Identity A status: {a.status_code}", f"Identity B status: {b.status_code}", f"Response length: {len(a.text)} bytes"],
                remediation=["Review the endpoint's authorization policy and verify that responses are scoped to the caller's permitted resources."],
                verification="Compare the endpoint against documented role/tenant expectations using known test data and confirm that each identity receives only its authorized records.",
                cwe="CWE-862",
            ))
    return findings
