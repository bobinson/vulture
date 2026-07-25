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
    broker_token: str | None = Field(
        default=None,
        description=(
            "Feature 0064: per-run scoped LLM-broker token (ES256/EdDSA JWT). "
            "Additive and optional; None means no broker (env provider keys used). "
            "The agent uses it as the SDK model client's api_key. Secret-class."
        ),
    )
    task_type: str | None = Field(
        default=None,
        description=(
            "Feature 0064/§5: the run's task_type (the dispatching agent's type). "
            "Injected by the backend at dispatch alongside broker_token; the agent "
            "sends it as the X-Vulture-Task-Type header so the broker can "
            "scope-check the completion. None when the broker is off."
        ),
    )
    context_window: int | None = Field(
        default=None,
        description=(
            "Feature 0064 §31: broker-resolved model context window (tokens) for "
            "the run's primary model, injected at dispatch alongside broker_token. "
            "None => the agent resolves it itself (env > CONTEXT_WINDOWS > family > "
            "default). Additive/optional; never client-supplied."
        ),
    )
