from fastapi.testclient import TestClient
from lab.vulnerable_app import app
from scanner.http_checks import inspect_headers, inspect_cookies

client = TestClient(app)

def test_lab_reachable():
    r = client.get("/")
    assert r.status_code == 200
    findings = inspect_headers(r)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles

def test_idor_lab_endpoint():
    r = client.get("/api/reports/2")
    assert r.status_code == 200
    assert r.json()["owner"] == "bob"
