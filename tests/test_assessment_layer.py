from scanner.mapping import enrich_finding
from scanner.models import Finding
from scanner.world_monitor import WORLD_MONITOR_PROFILE, attack_surface_summary

def test_world_monitor_mapping():
    finding = Finding(
        title="Wildcard CORS policy",
        category="API security",
        severity="Medium",
        confidence="High",
        affected_component="http://127.0.0.1:8001/",
        description="test",
        evidence=["Access-Control-Allow-Origin: *"],
        remediation=["Use an allowlist."],
        verification="Repeat with an untrusted origin.",
        cwe="CWE-942",
    )
    enriched = enrich_finding(finding)
    assert enriched.ps_scope == "API security"
    assert enriched.owasp_web == "A02:2025 Security Misconfiguration"
    assert "API8:2023 Security Misconfiguration" in enriched.owasp_api
    assert enriched.cvss_style["vector"].startswith("CVSS:4.0-STYLE/")
    assert enriched.poc["id"] == "cors-wildcard-lab"

def test_attack_surface_profile():
    surface = attack_surface_summary([])
    assert len(surface["nodes"]) == 6
    assert len(surface["edges"]) == 7
    assert surface["finding_counts"]["rest"] == 0
