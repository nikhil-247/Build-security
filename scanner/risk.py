from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class CvssStyle:
    version: str
    vector: str
    score: float
    severity: str
    label: str
    metrics: dict[str, str]

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
AT = {"N": 0.85, "P": 0.62}
PR = {"N": 0.85, "L": 0.62, "H": 0.27}
UI = {"N": 0.85, "P": 0.62, "A": 0.50}
IMPACT = {"H": 0.95, "L": 0.35, "N": 0.0}

# This is a transparent CVSS v4-inspired worksheet used by Build Security.
# It is intentionally NOT represented as an official FIRST CVSS score.
def build_cvss_style(
    *,
    av: str = "N",
    ac: str = "L",
    at: str = "N",
    pr: str = "N",
    ui: str = "N",
    vc: str = "L",
    vi: str = "L",
    va: str = "N",
    sc: str = "N",
    si: str = "N",
    sa: str = "N",
) -> CvssStyle:
    exploit = (AV[av] * AC[ac] * AT[at] * PR[pr] * UI[ui]) ** 0.20
    vuln_impact = (IMPACT[vc] + IMPACT[vi] + IMPACT[va]) / 3
    subsequent_impact = (IMPACT[sc] + IMPACT[si] + IMPACT[sa]) / 3
    impact = 0.70 * vuln_impact + 0.30 * subsequent_impact
    score = round(min(10.0, max(0.0, (3.8 * exploit) + (6.2 * impact))), 1)

    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    elif score > 0:
        severity = "Low"
    else:
        severity = "None"

    metrics = {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
    }
    vector = "CVSS:4.0-STYLE/" + "/".join(f"{k}:{v}" for k, v in metrics.items())
    return CvssStyle(
        version="4.0-style",
        vector=vector,
        score=score,
        severity=severity,
        label="Build Security CVSS-style worksheet",
        metrics=metrics,
    )

def profile_for(cwe: str | None, title: str) -> CvssStyle:
    t = title.lower()
    if cwe in {"CWE-862", "CWE-942"} or "authorization" in t or "cors" in t:
        return build_cvss_style(pr="L", vc="H", vi="H", va="L", sc="L")
    if cwe == "CWE-319" or "http" in t.lower() or "hsts" in t.lower():
        return build_cvss_style(vc="H", vi="H", va="L")
    if cwe in {"CWE-614", "CWE-1004", "CWE-1275"}:
        return build_cvss_style(vc="H", vi="L", pr="L")
    if cwe == "CWE-693":
        return build_cvss_style(vc="L", vi="L")
    return build_cvss_style(vc="L", vi="L", va="L")
