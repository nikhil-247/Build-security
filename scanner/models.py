from pydantic import BaseModel, Field
from typing import Literal, Optional, Any

Severity = Literal["Info", "Low", "Medium", "High", "Critical"]

class Finding(BaseModel):
    title: str
    category: str
    severity: Severity
    confidence: Literal["Low", "Medium", "High"]
    affected_component: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    verification: str
    cwe: Optional[str] = None

    # PS 26163 assessment layer
    ps_scope: Optional[str] = None
    owasp_web: Optional[str] = None
    owasp_api: list[str] = Field(default_factory=list)
    attack_surface: Optional[str] = None
    cvss_style: Optional[dict[str, Any]] = None
    poc: Optional[dict[str, Any]] = None

class AssessmentResult(BaseModel):
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    checks_run: list[str]
    notes: list[str]
    framework: dict[str, Any] = Field(default_factory=lambda: {
        "problem_statement": "26163",
        "sih_scope": [
            "Authentication and session management",
            "Authorization and access control",
            "Input validation and data handling",
            "API security",
            "Client-side security controls",
            "Secure communication mechanisms",
            "Data storage and privacy protections",
        ],
        "owasp_web": "OWASP Top 10:2025",
        "owasp_api": "OWASP API Security Top 10:2023",
        "cvss_style": "CVSS v4.0-inspired transparent worksheet; not an official FIRST CVSS score.",
    })
    attack_surface: dict[str, Any] = Field(default_factory=dict)
