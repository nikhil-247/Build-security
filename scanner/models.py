from pydantic import BaseModel, Field
from typing import Literal, Optional

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

class AssessmentResult(BaseModel):
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    checks_run: list[str]
    notes: list[str]
