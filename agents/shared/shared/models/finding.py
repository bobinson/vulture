"""Finding model for audit results."""

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single audit finding."""

    id: str = Field(description="Unique finding identifier")
    audit_id: str = Field(description="Parent audit run identifier")
    agent_type: str = Field(description="Agent that produced this finding")
    severity: Severity = Field(description="Finding severity level")
    category: str = Field(description="Finding category")
    title: str = Field(description="Short finding title")
    description: str = Field(description="Detailed finding description")
    file_path: str = Field(default="", description="Source file path")
    line_start: int = Field(default=0, description="Start line number")
    line_end: int = Field(default=0, description="End line number")
    recommendation: str = Field(default="", description="Recommended fix")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    check_id: str = Field(default="", description="Hierarchical check ID (e.g. cwe.injection.sql)")
    code_snippet: str = Field(default="", description="Source code context around the finding")
    verification_hints: list[str] = Field(default_factory=list, description="Hints for verification")
    requires_context: bool = Field(default=False, description="Finding needs file context for verification")
