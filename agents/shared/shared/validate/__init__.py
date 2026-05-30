"""Validation phase — feature 0045.

Single entry point: `validate(findings, source_path, ...)`.
See docs/features/0045_validation_phase/0045_implementation_plan.md
for the full design and the V1–V10 separation invariants.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable

from .compliance import apply_compliance_mode
from .context_heuristics import clear_l1_cache, run_l1
from .llm_judge import run_l5
from .rollup import run_l2
from .types import (
    FindingValidation,
    ValidateConfig,
    ValidationCheck,
    ValidationResult,
)
from .voter import vote

__all__ = [
    "validate",
    "is_enabled",
    "ValidateConfig",
    "ValidationResult",
    "ValidationCheck",
    "FindingValidation",
]


def is_enabled(config: dict[str, Any] | None) -> bool:
    """Resolve the on/off knob.

    Precedence: env var > config > default-on.
    """
    if os.environ.get("VULTURE_DISABLE_VALIDATE", "").lower() == "true":
        return False
    if config and config.get("disable_validate"):
        return False
    return True


def _resolve_l5_enabled(cfg: ValidateConfig) -> bool:
    env = os.environ.get("VULTURE_USE_VALIDATE_LLM", "").strip().lower()
    if env in ("true", "1", "yes"):
        return True
    if env in ("false", "0", "no"):
        return False
    return cfg.enable_l5


def validate(
    findings: list[dict[str, Any]],
    source_path: str = "",
    *,
    config: ValidateConfig | None = None,
    audit_id: str = "",
    emit_validation_update: Callable[[list[dict[str, Any]]], None] | None = None,
) -> ValidationResult:
    """Run the validate stage on a list of findings.

    V1: pure function — no side effects (besides clearing the
    per-call L1 file cache).
    V6: returns at least as many findings as it received.
    V8: compliance_mode prevents `likely_fp` classifications.
    """
    cfg = config or ValidateConfig()

    if not findings:
        return ValidationResult(
            findings=[],
            rollups=[],
            event_texts=["[validate] no findings to validate"],
            layers_run=[],
            duration_ms={},
        )

    event_texts: list[str] = []
    layers_run: list[str] = []
    duration_ms: dict[str, int] = {}

    # ── L1 context heuristics ──────────────────────────────────
    l1_results: list[list[ValidationCheck]]
    if cfg.enable_l1:
        t0 = time.monotonic()
        clear_l1_cache()
        try:
            l1_results = run_l1(findings)
            layers_run.append("L1")
        except Exception as exc:   # RC3 final safety net
            event_texts.append(
                f"[validate] L1 failed: {type(exc).__name__}; "
                f"contributing weight=0 for all findings")
            l1_results = [[ValidationCheck(
                id="path", result="error", weight=0.0,
                reason=f"L1 outer error: {type(exc).__name__}")] for _ in findings]
        finally:
            duration_ms["L1"] = int((time.monotonic() - t0) * 1000)
            clear_l1_cache()
        demoted = sum(
            1 for checks in l1_results
            for c in checks if c.weight < 0
        )
        event_texts.append(
            f"[validate] L1 done · {len(findings)} findings · "
            f"{demoted} demoting signal(s)")
    else:
        l1_results = [[] for _ in findings]

    # ── L2 rollup ──────────────────────────────────────────────
    l2_results: list[list[ValidationCheck]]
    rollups: list[dict[str, Any]]
    if cfg.enable_l2:
        t0 = time.monotonic()
        try:
            l2_results, rollups = run_l2(findings, audit_id=audit_id)
            layers_run.append("L2")
        except Exception as exc:
            event_texts.append(f"[validate] L2 failed: {type(exc).__name__}")
            l2_results = [[ValidationCheck(
                id="rollup", result="error", weight=0.0,
                reason=f"L2 outer error: {type(exc).__name__}")] for _ in findings]
            rollups = []
        finally:
            duration_ms["L2"] = int((time.monotonic() - t0) * 1000)
        event_texts.append(
            f"[validate] L2 done · {len(rollups)} rollup parent(s)")
    else:
        l2_results = [[] for _ in findings]
        rollups = []

    # ── Provisional vote (L1+L2 only) — build out_findings ────
    t0 = time.monotonic()
    out_findings: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings):
        checks: list[ValidationCheck] = []
        checks.extend(l1_results[idx])
        checks.extend(l2_results[idx])
        status, confidence = vote(checks)
        v = FindingValidation(
            status=status, confidence=confidence, checks=checks,
        )
        if cfg.compliance_mode:
            v = apply_compliance_mode(v)
        new_f = dict(finding)
        new_f["validation"] = v.to_json()
        new_f["validation_status"] = v.status
        new_f["validation_confidence"] = v.confidence
        out_findings.append(new_f)
    duration_ms["vote"] = int((time.monotonic() - t0) * 1000)
    layers_run.append("vote")

    # ── L5 LLM judge (opt-in, feature 0046) ────────────────────
    if _resolve_l5_enabled(cfg):
        t0 = time.monotonic()
        try:
            # Streaming callback (D6/D16): re-vote with L5 included and
            # apply V8 BEFORE emitting. Keeps compliance-mode flashes
            # from leaking to the SSE stream.
            def _stream_batch(updated_findings: list[dict[str, Any]]) -> None:
                if emit_validation_update is None:
                    return
                for f in updated_findings:
                    revote_checks = [
                        ValidationCheck.from_json(c)
                        for c in f.get("validation", {}).get("checks", [])
                    ]
                    s, c = vote(revote_checks)
                    fv = FindingValidation(status=s, confidence=c, checks=revote_checks)
                    if cfg.compliance_mode:
                        fv = apply_compliance_mode(fv)
                    f["validation"] = fv.to_json()
                    f["validation_status"] = fv.status
                    f["validation_confidence"] = fv.confidence
                emit_validation_update(updated_findings)

            l5_results = run_l5(
                out_findings, l1_results, cfg,
                audit_id=audit_id,
                emit_batch=_stream_batch,
            )
            # Backfill loop. Issue #14: if streaming was on, the
            # `_stream_batch` callback already updated validation +
            # status + confidence on each finding. Skip the redundant
            # re-vote in that case — just record the layer ran.
            #
            # Streaming = ON: `_stream_batch` mutated every selected
            # finding's validation in place; the L5 check is already
            # present. No backfill needed.
            #
            # Streaming = OFF: callback never fired; we must re-vote
            # here so the final result includes L5.
            streaming_on = emit_validation_update is not None
            if not streaming_on:
                for idx, l5_checks in enumerate(l5_results):
                    if not l5_checks:
                        continue
                    existing = out_findings[idx].get("validation", {}).get("checks", [])
                    merged = [ValidationCheck.from_json(c) for c in existing]
                    if not any(c.id == "llm_judge" for c in merged):
                        merged.extend(l5_checks)
                    s, c = vote(merged)
                    fv = FindingValidation(status=s, confidence=c, checks=merged)
                    if cfg.compliance_mode:
                        fv = apply_compliance_mode(fv)
                    out_findings[idx]["validation"] = fv.to_json()
                    out_findings[idx]["validation_status"] = fv.status
                    out_findings[idx]["validation_confidence"] = fv.confidence
            layers_run.append("L5")
        except Exception as exc:  # RC3 outer safety net
            event_texts.append(
                f"[validate] L5 failed: {type(exc).__name__}; layer disabled")
        finally:
            duration_ms["L5"] = int((time.monotonic() - t0) * 1000)
        judged = sum(
            1 for f in out_findings
            if any(c.get("id") == "llm_judge"
                   for c in f.get("validation", {}).get("checks", []))
        )
        event_texts.append(f"[validate] L5 done · {judged} finding(s) judged")

    total_ms = sum(duration_ms.values())
    demote_counts: dict[str, int] = {"likely_fp": 0, "suspicious": 0, "high_confidence": 0}
    for f in out_findings:
        demote_counts[f.get("validation_status", "suspicious")] = (
            demote_counts.get(f.get("validation_status", "suspicious"), 0) + 1
        )
    event_texts.append(
        f"[validate] done in {total_ms}ms · "
        f"high={demote_counts['high_confidence']} · "
        f"susp={demote_counts['suspicious']} · "
        f"fp={demote_counts['likely_fp']} · "
        f"rollups={len(rollups)}"
    )

    # Normalise rollup parents so the persisted records carry the
    # same top-level validation_status / validation_confidence as
    # members. Without this the rollup parent row ends up with
    # NULL validation_status and the UI's status filter skips it.
    for parent in rollups:
        v_blob = parent.get("validation") or {}
        parent["validation_status"] = v_blob.get("status", "suspicious")
        parent["validation_confidence"] = v_blob.get("confidence", 0.4)

    return ValidationResult(
        findings=out_findings,
        rollups=rollups,
        event_texts=event_texts,
        layers_run=layers_run,
        duration_ms=duration_ms,
    )
