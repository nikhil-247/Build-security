from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
import requests
from .models import Finding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("Medium", "Restrict script/style/frame sources to reduce browser-side injection impact."),
    "X-Content-Type-Options": ("Low", "Prevent MIME sniffing with `X-Content-Type-Options: nosniff`."),
    "Referrer-Policy": ("Low", "Set an explicit restrictive Referrer-Policy."),
    "Permissions-Policy": ("Low", "Disable browser capabilities that the application does not need."),
}

def inspect_headers(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    for header, (severity, remediation) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append(Finding(
                title=f"Missing {header}",
                category="Client-side security",
                severity=severity, confidence="High",
                affected_component=str(response.url),
                description=f"The response does not advertise {header}.",
                evidence=[f"HTTP {response.status_code} from {response.url}", f"{header} header not present"],
                remediation=[remediation],
                verification=f"Re-run the GET request and confirm {header} is present with an appropriate value.",
                cwe="CWE-693",
            ))

    if urlparse(str(response.url)).scheme == "https" and "strict-transport-security" not in headers:
        findings.append(Finding(
            title="Missing HSTS",
            category="Secure communication",
            severity="Medium", confidence="High",
            affected_component=str(response.url),
            description="HTTPS is in use but the response does not set Strict-Transport-Security.",
            evidence=["Scheme: https", "Strict-Transport-Security header not present"],
            remediation=["Set a suitable HSTS policy after verifying the deployment is HTTPS-only."],
            verification="Confirm HSTS is present on HTTPS responses and, where applicable, on all production subdomains.",
            cwe="CWE-319",
        ))

    if "x-powered-by" in headers:
        findings.append(Finding(
            title="Technology fingerprinting header exposed",
            category="Information disclosure",
            severity="Low", confidence="High",
            affected_component=str(response.url),
            description="The response exposes an implementation-identifying X-Powered-By header.",
            evidence=[f"X-Powered-By: {headers['x-powered-by']}"],
            remediation=["Remove or normalize implementation-identifying response headers at the application or reverse proxy layer."],
            verification="Repeat the request and confirm the identifying header is absent.",
            cwe="CWE-200",
        ))
    return findings

def inspect_cookies(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    raw = response.headers.get("Set-Cookie")
    if not raw:
        return findings
    cookies = re.split(r",\s*(?=[^;,=]+=[^;,]+(?:;|$))", raw)
    for cookie in cookies:
        pair = cookie.split(";", 1)[0].strip()
        name = pair.split("=", 1)[0].strip() if "=" in pair else "unknown"
        lowered = cookie.lower()
        if "secure" not in lowered and urlparse(str(response.url)).scheme == "https":
            findings.append(Finding(
                title=f"Session cookie missing Secure flag: {name}",
                category="Authentication and session management",
                severity="Medium", confidence="High",
                affected_component=str(response.url),
                description="A cookie is set over HTTPS without the Secure attribute.",
                evidence=[f"Set-Cookie observed for {name}"],
                remediation=["Set Secure on session/authentication cookies so they are only sent over HTTPS."],
                verification="Confirm the cookie includes Secure in a response from the HTTPS deployment.",
                cwe="CWE-614",
            ))
        if "httponly" not in lowered:
            findings.append(Finding(
                title=f"Cookie missing HttpOnly flag: {name}",
                category="Authentication and session management",
                severity="Low", confidence="High",
                affected_component=str(response.url),
                description="The cookie can be read by browser JavaScript unless other browser controls prevent it.",
                evidence=[f"HttpOnly not observed for {name}"],
                remediation=["Set HttpOnly on session/authentication cookies unless client-side JavaScript access is explicitly required."],
                verification="Confirm HttpOnly is present for session cookies.",
                cwe="CWE-1004",
            ))
        if "samesite" not in lowered:
            findings.append(Finding(
                title=f"Cookie missing SameSite attribute: {name}",
                category="Authentication and session management",
                severity="Low", confidence="High",
                affected_component=str(response.url),
                description="The cookie does not declare an explicit SameSite policy.",
                evidence=[f"SameSite not observed for {name}"],
                remediation=["Set an explicit SameSite policy appropriate for the application's cross-site requirements."],
                verification="Confirm the Set-Cookie attribute matches the intended cross-site behavior.",
                cwe="CWE-1275",
            ))
    return findings

def inspect_cors(response: requests.Response, request_origin: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    acao = response.headers.get("Access-Control-Allow-Origin")
    if not acao:
        return findings
    if acao.strip() == "*":
        findings.append(Finding(
            title="Wildcard CORS policy",
            category="API security",
            severity="Medium", confidence="Medium",
            affected_component=str(response.url),
            description="The API permits cross-origin reads from any origin for responses where browser CORS applies.",
            evidence=[f"Access-Control-Allow-Origin: {acao}"],
            remediation=["Allow only trusted application origins. Avoid wildcard origin policies for sensitive endpoints."],
            verification="Test an untrusted Origin and confirm the API does not grant cross-origin read access.",
            cwe="CWE-942",
        ))
    if request_origin and acao.strip() == request_origin:
        findings.append(Finding(
            title="Origin reflection requires review",
            category="API security",
            severity="Medium", confidence="Low",
            affected_component=str(response.url),
            description="The response reflects the supplied Origin. Reflection is not automatically vulnerable, but it warrants validation of the allowlist logic and credential behavior.",
            evidence=[f"Origin sent: {request_origin}", f"Access-Control-Allow-Origin returned: {acao}", f"Access-Control-Allow-Credentials: {response.headers.get('Access-Control-Allow-Credentials', 'not set')}"],
            remediation=["Use an explicit trusted-origin allowlist and ensure credentialed CORS is never granted to attacker-controlled origins."],
            verification="Repeat with an untrusted Origin and verify it is rejected rather than reflected.",
            cwe="CWE-942",
        ))
    return findings

def inspect_https(target: str) -> list[Finding]:
    parsed = urlparse(target)
    if parsed.scheme != "https":
        return [Finding(
            title="Target is accessed over HTTP",
            category="Secure communication",
            severity="High", confidence="High",
            affected_component=target,
            description="The configured assessment target uses plain HTTP.",
            evidence=[f"Scheme: {parsed.scheme}"],
            remediation=["Use HTTPS for authentication, session traffic, API calls, and sensitive data. Redirect HTTP to HTTPS where appropriate."],
            verification="Run the same assessment against the HTTPS deployment and confirm sensitive requests are never sent over plaintext HTTP.",
            cwe="CWE-319",
        )]
    return []

def request_target(target: str, extra_headers: dict[str, str] | None = None) -> tuple[requests.Response | None, str | None]:
    headers = {"User-Agent": "WorldMonitor-Security-Assessment/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        response = requests.get(target, headers=headers, timeout=8, allow_redirects=True)
        return response, None
    except requests.RequestException as exc:
        return None, str(exc)

def assess_target(target: str, endpoints: list[str], headers: dict[str, str] | None = None) -> tuple[list[Finding], list[str]]:
    findings = inspect_https(target)
    checks = ["transport", "headers"]
    base = target.rstrip("/") + "/"
    response, error = request_target(base, headers)
    if error:
        findings.append(Finding(
            title="Target could not be reached",
            category="Assessment execution",
            severity="Info", confidence="High",
            affected_component=base,
            description="The target did not return a response to the assessment request.",
            evidence=[error],
            remediation=["Confirm the test endpoint is reachable and that network controls allow the assessment source."],
            verification="Repeat the assessment when the authorized target is reachable.",
        ))
        return findings, checks
    findings.extend(inspect_headers(response))
    findings.extend(inspect_cookies(response))
    origin = "https://assessment.invalid"
    cors_resp, _ = request_target(base, {**(headers or {}), "Origin": origin})
    if cors_resp:
        findings.extend(inspect_cors(cors_resp, origin))
    checks.extend(["cookies", "cors"])
    for endpoint in endpoints:
        url = urljoin(base, endpoint.lstrip("/"))
        resp, error = request_target(url, headers)
        if error:
            findings.append(Finding(
                title="Endpoint request failed",
                category="API security",
                severity="Info", confidence="High",
                affected_component=url,
                description="A configured GET endpoint could not be reached.",
                evidence=[error],
                remediation=["Verify endpoint path, availability, and authorization before treating this as an application issue."],
                verification="Repeat the GET request manually in the authorized environment.",
            ))
            continue
        findings.extend(inspect_headers(resp))
        findings.extend(inspect_cookies(resp))
        cors_resp, _ = request_target(url, {**(headers or {}), "Origin": origin})
        if cors_resp:
            findings.extend(inspect_cors(cors_resp, origin))
    checks.append("configured GET endpoints")
    return findings, checks
