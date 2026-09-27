from __future__ import annotations
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from .models import AssessmentResult

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
    rows = []
    for f in result.findings:
        rows.append(f"<tr><td>{escape(f.severity)}</td><td>{escape(f.title)}</td><td>{escape(f.category)}</td><td>{escape(f.affected_component)}</td><td>{escape(f.confidence)}</td></tr>")
    details = []
    for f in result.findings:
        details.append(f"""
        <section class="finding">
          <h2>{escape(f.title)}</h2>
          <p><b>Severity:</b> {escape(f.severity)} &nbsp; <b>Confidence:</b> {escape(f.confidence)}</p>
          <p><b>Category:</b> {escape(f.category)}<br><b>Affected component:</b> {escape(f.affected_component)}</p>
          <p>{escape(f.description)}</p>
          <h3>Evidence</h3><ul>{''.join('<li>'+escape(x)+'</li>' for x in f.evidence)}</ul>
          <h3>Remediation</h3><ul>{''.join('<li>'+escape(x)+'</li>' for x in f.remediation)}</ul>
          <p><b>Verification:</b> {escape(f.verification)}</p>
        </section>""")
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>World Monitor Security Assessment</title>
    <style>body{{font-family:Arial,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px;background:#071018;color:#e9f1f7}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #264256;padding:8px;text-align:left}}.finding{{border:1px solid #264256;padding:18px;margin:18px 0;border-radius:8px;background:#0d1a25}}code{{background:#102331;padding:2px 5px}}</style></head><body>
    <h1>World Monitor Security Assessment</h1><p><b>Target:</b> {escape(result.target)}<br><b>Started:</b> {escape(result.started_at)}<br><b>Finished:</b> {escape(result.finished_at)}</p>
    <p><b>Finding counts:</b> {escape(json.dumps(counts, sort_keys=True))}</p>
    <table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Affected Component</th><th>Confidence</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=5>No findings</td></tr>'}</tbody></table>
    {''.join(details)}
    <h2>Assessment notes</h2><ul>{''.join('<li>'+escape(x)+'</li>' for x in result.notes)}</ul>
    </body></html>"""
    Path(html_path).write_text(html, encoding="utf-8")
    return json_path, html_path
