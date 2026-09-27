from __future__ import annotations
from urllib.parse import urlparse
import requests

def _assert_local(target: str):
    parsed = urlparse(target)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Controlled PoCs are restricted to the included local lab.")

def run_local_poc(poc_id: str, target: str) -> dict:
    _assert_local(target)
    base = target.rstrip("/")
    if poc_id == "client-header-lab":
        r = requests.get(base + "/", timeout=5)
        return {"id": poc_id, "status": r.status_code, "observed": {"content_security_policy": r.headers.get("Content-Security-Policy"), "x_content_type_options": r.headers.get("X-Content-Type-Options"), "referrer_policy": r.headers.get("Referrer-Policy"), "permissions_policy": r.headers.get("Permissions-Policy")}}
    if poc_id == "transport-lab":
        r = requests.get(base + "/", timeout=5)
        return {"id": poc_id, "status": r.status_code, "observed": {"scheme": urlparse(r.url).scheme, "strict_transport_security": r.headers.get("Strict-Transport-Security")}}
    if poc_id == "fingerprint-lab":
        r = requests.get(base + "/", timeout=5)
        return {"id": poc_id, "status": r.status_code, "observed": {"x_powered_by": r.headers.get("X-Powered-By")}}
    if poc_id == "cors-wildcard-lab":
        r = requests.get(base + "/", headers={"Origin": "https://assessment.invalid"}, timeout=5)
        return {"id": poc_id, "status": r.status_code, "observed": {"access_control_allow_origin": r.headers.get("Access-Control-Allow-Origin")}}
    if poc_id in {"cookie-secure-lab", "cookie-httponly-lab", "cookie-samesite-lab"}:
        r = requests.get(base + "/", timeout=5)
        return {"id": poc_id, "status": r.status_code, "observed": {"set_cookie": r.headers.get("Set-Cookie")}}
    if poc_id == "idor-differential-lab":
        r1 = requests.get(base + "/api/reports/1", timeout=5)
        r2 = requests.get(base + "/api/reports/2", timeout=5)
        return {"id": poc_id, "status": 200, "observed": {"identity_a_demo_object": r1.json(), "identity_b_demo_object": r2.json()}}
    raise ValueError("Unknown PoC.")
