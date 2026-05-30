"""Validate-stage types — feature 0045.

NORMATIVE (V1, V3): single entry point with JSON-serialisable contract.
Future extraction to a separate agent depends on these types
round-tripping cleanly through json.dumps / json.loads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "ValidationCheck",
    "FindingValidation",
    "ValidationResult",
    "ValidateConfig",
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class ValidationCheck:
    """One check's contribution to a finding's validation outcome.

    `id` identifies the producing layer:
        "path", "suppression", "sanitizer", "rollup",
        "cross_agent", "memory", "llm_judge", "compliance".
    `result` is the check's outcome label (free-form per layer).
    `weight` is the signed contribution to confidence in [-1, +1].
    `reason` is human-readable; surfaces in the UI tooltip.
    `extras` is layer-specific metadata; JSON-serialisable.
    """
    id: str
    result: str
    weight: float
    reason: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "result": self.result,
            "weight": self.weight,
            "reason": self.reason,
            "extras": self.extras,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ValidationCheck":
        return cls(
            id=data["id"],
            result=data["result"],
            weight=float(data["weight"]),
            reason=data.get("reason", ""),
            extras=data.get("extras", {}),
        )


@dataclass
class FindingValidation:
    """Per-finding validation result appended to the finding record."""
    status: str            # "high_confidence" | "suspicious" | "likely_fp"
    confidence: float      # 0.0 .. 1.0
    checks: list[ValidationCheck]
    validated_at: str = field(default_factory=_utc_now_iso)

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "checks": [c.to_json() for c in self.checks],
            "validated_at": self.validated_at,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FindingValidation":
        return cls(
            status=data["status"],
            confidence=float(data["confidence"]),
            checks=[ValidationCheck.from_json(c) for c in data.get("checks", [])],
            validated_at=data.get("validated_at", _utc_now_iso()),
        )


@dataclass
class ValidationResult:
    """Output of one validate() call. JSON-round-trippable (V3, V10).

    `findings` length equals input findings length (V6 — demote, never drop).
    `rollups` contains NEW parent records from L2.
    `event_texts` are free-form "[validate] ..." strings the caller
    forwards via emitter.text_message() (folded into the existing
    `thinking` agui event type — H5/M8).
    """
    findings: list[dict[str, Any]]
    rollups: list[dict[str, Any]] = field(default_factory=list)
    event_texts: list[str] = field(default_factory=list)
    layers_run: list[str] = field(default_factory=list)
    duration_ms: dict[str, int] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "rollups": self.rollups,
            "event_texts": list(self.event_texts),
            "layers_run": list(self.layers_run),
            "duration_ms": dict(self.duration_ms),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ValidationResult":
        return cls(
            findings=list(data.get("findings", [])),
            rollups=list(data.get("rollups", [])),
            event_texts=list(data.get("event_texts", [])),
            layers_run=list(data.get("layers_run", [])),
            duration_ms=dict(data.get("duration_ms", {})),
        )


@dataclass
class ValidateConfig:
    """Caller-supplied configuration. Passed as a value, never read
    from the environment by the validate package itself — keeps
    validate a pure function (V4)."""
    compliance_mode: bool = False
    use_llm: bool = False
    top_n_for_llm: int = 1000          # feature 0046 D4: locked at 1000
    enable_l1: bool = True
    enable_l2: bool = True
    enable_l5: bool = False             # master switch for L5 LLM judge (0046)
    preserve_validation_history: bool = False
    line_tolerance: int = 2             # L3 grouping width (currently Go-side; here for parity)
    # L5-specific knobs (feature 0046 §I, all overridable via env)
    l5_batch_size: int = 10
    l5_max_concurrency: int = 5         # 0046 D18
    l5_total_timeout_s: float = 300.0   # 0046 D13
    l5_per_batch_timeout_s: float = 30.0   # local 30B models routinely take 10-20 s/batch
    l5_model_override: str = ""         # empty → fall back to caller's LLM model
