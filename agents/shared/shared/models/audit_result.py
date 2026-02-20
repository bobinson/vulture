"""Audit result model."""

from pydantic import BaseModel, Field

from shared.models.finding import Finding


class AuditResult(BaseModel):
    """Result of an audit run."""

    findings: list[Finding] = Field(default_factory=list, description="List of findings")
    summary: str = Field(default="", description="Human-readable summary")
    score: float = Field(default=0.0, description="Compliance score 0-100")
