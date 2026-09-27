from __future__ import annotations
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from .models import AssessmentResult

CVSS_CALCULATOR = "https://www.first.org/cvss/calculator/4-0"

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def save_report(result: AssessmentResult, base_path: str) -> tuple[str, str]:
    base = Path(base_path)
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = str(base.with_suffix(".json"))
    html_path = str(base.with_suffix(".html"))
    Path(json_path).write_text(result.model_dump_json(indent=2), encoding="utf-8")

    counts = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    surface_rows = []
    for node in result.attack_surface.get("nodes", []):
        count = result.attack_surface.get("finding_counts", {}).get(node["id"], 0)
        surface_rows.append(
            f"<tr><td>{escape(node['label'])}</td><td>{escape(node['host'])}</td><td>{escape(node['scope'])}</td><td>{count}</td></tr>"
        )

    rows = []
    details = []
    for idx, f in enumerate(result.findings, 1):
        cvss = f.cvss_style or {}
        owasp_api = ", ".join(f.owasp_api) if f.owasp_api else "N/A"
        rows.append(
            f"<tr><td>F-{idx:03d}</td><td>{escape(f.severity)}</td><td>{escape(f.title)}</td>"
            f"<td>{escape(str(cvss.get('score','N/A')))}</td><td>{escape(str(f.owasp_web or 'N/A'))}</td></tr>"
        )
        poc = f.poc or {}
        details.append(f"""
        <section class="finding">
          <div class="finding-title"><span>F-{idx:03d}</span><h2>{escape(f.title)}</h2></div>
          <p><b>PS 26163 scope:</b> {escape(f.ps_scope or 'Cross-cutting')}<br>
          <b>Affected component:</b> {escape(f.affected_component)}<br>
          <b>Attack surface:</b> {escape(f.attack_surface or 'N/A')}</p>
          <div class="metric-grid">
            <div><small>Severity</small><strong>{escape(f.severity)}</strong></div>
            <div><small>CVSS-style</small><strong>{escape(str(cvss.get('score','N/A')))}/10</strong></div>
            <div><small>Confidence</small><strong>{escape(f.confidence)}</strong></div>
            <div><small>CWE</small><strong>{escape(f.cwe or 'N/A')}</strong></div>
          </div>
          <p><b>OWASP Web:</b> {escape(f.owasp_web or 'N/A')}<br><b>OWASP API:</b> {escape(owasp_api)}</p>
          <p>{escape(f.description)}</p>
          <h3>Evidence</h3><ul>{''.join('<li>'+escape(x)+'</li>' for x in f.evidence)}</ul>
          <h3>Controlled PoC</h3><p><b>{escape(str(poc.get('title','Not available')))}</b> · {escape(str(poc.get('mode','manual-validation')))}</p>
          <ol>{''.join('<li>'+escape(x)+'</li>' for x in poc.get('steps', []))}</ol>
          <p><b>Expected:</b> {escape(str(poc.get('expected','')))}</p>
          <h3>Remediation</h3><ul>{''.join('<li>'+escape(x)+'</li>' for x in f.remediation)}</ul>
          <p><b>Verification:</b> {escape(f.verification)}</p>
          <details><summary>CVSS-style vector and metrics</summary><p><code>{escape(str(cvss.get('vector','')))}</code></p><pre>{escape(json.dumps(cvss.get('metrics', {}), indent=2))}</pre></details>
        </section>""")

    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Build Security — World Monitor Assessment</title>
    <style>
    :root{{--bg:#071018;--panel:#0d1a25;--line:#294458;--text:#edf5fa;--muted:#8da5b5;--a:#52d6a8}}
    body{{font-family:Inter,Arial,sans-serif;max-width:1250px;margin:0 auto;padding:35px 22px;background:var(--bg);color:var(--text);line-height:1.55}}
    h1{{font-size:40px;margin-bottom:4px}}h2{{margin-bottom:5px}}h3{{color:#a9c0cd;font-size:14px;text-transform:uppercase;letter-spacing:.8px}}
    .kicker{{color:var(--a);font-weight:800;letter-spacing:1.5px;text-transform:uppercase;font-size:12px}}
    .hero,.finding,.box{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin:18px 0}}
    .metric-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin:15px 0}}
    .metric-grid>div{{background:#091620;border:1px solid #1d3647;border-radius:10px;padding:12px}}small{{display:block;color:var(--muted)}}strong{{font-size:17px}}
    table{{border-collapse:collapse;width:100%;margin-top:12px}}th,td{{border:1px solid var(--line);padding:9px;text-align:left;font-size:12px}}
    code,pre{{background:#07131c;color:#7fdec0;padding:8px;border-radius:8px;display:block;overflow:auto}}
    a{{color:#78d7ff}}.finding-title{{display:flex;gap:10px;align-items:center}}.finding-title span{{color:#6b8596;font-family:monospace}}
    </style></head><body>
    <div class='kicker'>Smart India Hackathon 2026 · PS 26163</div>
    <h1>World Monitor Security Assessment</h1>
    <div class='hero'><p><b>Target:</b> {escape(result.target)}<br><b>Started:</b> {escape(result.started_at)}<br><b>Finished:</b> {escape(result.finished_at)}</p>
    <p>This evidence pack is designed for an authorized, non-destructive assessment. Automated signals require manual confirmation.</p>
    <p><b>Scoring:</b> Build Security uses a transparent CVSS v4.0-inspired worksheet for triage. It is not an official FIRST CVSS score. For official scoring use the <a href='{CVSS_CALCULATOR}'>{CVSS_CALCULATOR}</a>.</p></div>

    <div class='box'><h2>Executive snapshot</h2><p><b>Finding counts:</b> {escape(json.dumps(counts, sort_keys=True))}</p>
    <table><thead><tr><th>Finding</th><th>Severity</th><th>CVSS-style</th><th>OWASP Web</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=4>No findings</td></tr>'}</tbody></table></div>

    <div class='box'><h2>Attack surface map</h2>
    <table><thead><tr><th>Surface</th><th>Host / entry point</th><th>PS 26163 scope</th><th>Findings</th></tr></thead><tbody>{''.join(surface_rows)}</tbody></table></div>

    <div class='box'><h2>Findings and evidence</h2>{''.join(details) or '<p>No findings.</p>'}</div>
    <div class='box'><h2>Assessment notes</h2><ul>{''.join('<li>'+escape(x)+'</li>' for x in result.notes)}</ul></div>
    <footer><small>Build Security · World Monitor assessment profile · OWASP Top 10:2025 · OWASP API Security Top 10:2023</small></footer>
    </body></html>"""
    Path(html_path).write_text(html, encoding="utf-8")
    return json_path, html_path
