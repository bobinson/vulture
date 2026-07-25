"""Audit request model."""

from typing import Any

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    """Request to run an audit."""

    run_id: str = Field(description="Unique run identifier")
    source_path: str = Field(description="Path to source code")
    config: dict = Field(default_factory=dict, description="Agent-specific configuration")
    prior_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Findings from other agents to consider for cross-agent correlation",
    )
