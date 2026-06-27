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
from .llm_judge import _l5_check_is_demoting, run_l5
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


def _empty_result(event_texts: list[str]) -> ValidationResult:
    """Short-circuit return for the no-findings case."""
    return ValidationResult(
        findings=[], rollups=[],
        event_texts=event_texts, layers_run=[], duration_ms={},
    )


def _l1_error_checks(
    findings: list[dict[str, Any]], exc: BaseException,
) -> list[list[ValidationCheck]]:
    return [[ValidationCheck(
        id="path", result="error", weight=0.0,
        reason=f"L1 outer error: {type(exc).__name__}")] for _ in findings]


def _l2_error_checks(
    findings: list[dict[str, Any]], exc: BaseException,
) -> list[list[ValidationCheck]]:
    return [[ValidationCheck(
        id="rollup", result="error", weight=0.0,
        reason=f"L2 outer error: {type(exc).__name__}")] for _ in findings]


def _run_l1_phase(
    findings: list[dict[str, Any]], cfg: ValidateConfig,
    event_texts: list[str], layers_run: list[str], duration_ms: dict[str, int],
) -> list[list[ValidationCheck]]:
    """RC3-isolated L1 dispatcher. Returns one check-list per finding."""
    if not cfg.enable_l1:
        return [[] for _ in findings]
    t0 = time.monotonic()
    clear_l1_cache()
    try:
        l1_results = run_l1(findings)
        layers_run.append("L1")
    except Exception as exc:
        event_texts.append(
            f"[validate] L1 failed: {type(exc).__name__}; "
            f"contributing weight=0 for all findings")
        l1_results = _l1_error_checks(findings, exc)
    finally:
        duration_ms["L1"] = int((time.monotonic() - t0) * 1000)
        clear_l1_cache()
    demoted = sum(1 for checks in l1_results for c in checks if c.weight < 0)
    event_texts.append(
        f"[validate] L1 done · {len(findings)} findings · "
        f"{demoted} demoting signal(s)")
    return l1_results


def _run_l2_phase(
    findings: list[dict[str, Any]], cfg: ValidateConfig, audit_id: str,
    event_texts: list[str], layers_run: list[str], duration_ms: dict[str, int],
) -> tuple[list[list[ValidationCheck]], list[dict[str, Any]]]:
    """RC3-isolated L2 dispatcher. Returns (per-finding checks, parents)."""
    if not cfg.enable_l2:
        return [[] for _ in findings], []
    t0 = time.monotonic()
    try:
        l2_results, rollups = run_l2(findings, audit_id=audit_id)
        layers_run.append("L2")
    except Exception as exc:
        event_texts.append(f"[validate] L2 failed: {type(exc).__name__}")
        l2_results = _l2_error_checks(findings, exc)
        rollups = []
    finally:
        duration_ms["L2"] = int((time.monotonic() - t0) * 1000)
    event_texts.append(f"[validate] L2 done · {len(rollups)} rollup parent(s)")
    return l2_results, rollups


def _retag_l5_verified(
    new_f: dict[str, Any], checks: list[ValidationCheck],
) -> None:
    """Feature 0057 P6b: re-tag an LLM finding that SURVIVES L5.

    An ``llm``-provenance finding that carries a NON-demoting ``llm_judge``
    (L5) check is promoted to ``llm_l5_verified`` — it was model-generated and
    independently confirmed by the judge. A demoting or absent L5 verdict
    leaves the ``llm`` tag in place. Deterministic findings (any non-``llm``
    provenance) are NEVER re-tagged to an ``llm_*`` provenance. Mutates in
    place; the validation* fields stamped by the caller are untouched.
    """
    if new_f.get("provenance") != "llm":
        return
    l5_checks = [c for c in checks if c.id == "llm_judge"]
    if not l5_checks:
        return
    if any(_l5_check_is_demoting(c) for c in l5_checks):
        return
    new_f["provenance"] = "llm_l5_verified"


def _apply_validation_to_finding(
    finding: dict[str, Any], checks: list[ValidationCheck], cfg: ValidateConfig,
) -> dict[str, Any]:
    """Vote on checks and stamp validation fields onto a copy of the finding."""
    status, confidence = vote(checks)
    v = FindingValidation(status=status, confidence=confidence, checks=checks)
    if cfg.compliance_mode:
        v = apply_compliance_mode(v)
    new_f = dict(finding)
    new_f["validation"] = v.to_json()
    new_f["validation_status"] = v.status
    new_f["validation_confidence"] = v.confidence
    _retag_l5_verified(new_f, checks)
    return new_f


def _provisional_vote(
    findings: list[dict[str, Any]],
    l1_results: list[list[ValidationCheck]],
    l2_results: list[list[ValidationCheck]],
    cfg: ValidateConfig,
    layers_run: list[str], duration_ms: dict[str, int],
) -> list[dict[str, Any]]:
    """First-pass vote using L1+L2 only. Populates `validation*` fields."""
    t0 = time.monotonic()
    out_findings = [
        _apply_validation_to_finding(
            finding, list(l1_results[idx]) + list(l2_results[idx]), cfg,
        )
        for idx, finding in enumerate(findings)
    ]
    duration_ms["vote"] = int((time.monotonic() - t0) * 1000)
    layers_run.append("vote")
    return out_findings


def _revote_finding_in_place(
    finding: dict[str, Any], cfg: ValidateConfig,
) -> None:
    """Re-run vote() using the finding's own checks; mutate in place."""
    revote_checks = [
        ValidationCheck.from_json(c)
        for c in finding.get("validation", {}).get("checks", [])
    ]
    s, c = vote(revote_checks)
    fv = FindingValidation(status=s, confidence=c, checks=revote_checks)
    if cfg.compliance_mode:
        fv = apply_compliance_mode(fv)
    finding["validation"] = fv.to_json()
    finding["validation_status"] = fv.status
    finding["validation_confidence"] = fv.confidence


def _make_l5_stream_callback(
    cfg: ValidateConfig,
    emit_validation_update: Callable[[list[dict[str, Any]]], None] | None,
) -> Callable[[list[dict[str, Any]]], None]:
    """Build the per-batch callback L5 invokes during streaming.

    D6/D16: re-vote with L5 included and apply V8 before emitting so
    compliance-mode never leaks `likely_fp` to the SSE stream.
    """
    def _stream_batch(updated_findings: list[dict[str, Any]]) -> None:
        if emit_validation_update is None:
            return
        for f in updated_findings:
            _revote_finding_in_place(f, cfg)
        emit_validation_update(updated_findings)
    return _stream_batch


def _backfill_l5_offline(
    out_findings: list[dict[str, Any]],
    l5_results: list[list[ValidationCheck]],
    cfg: ValidateConfig,
) -> None:
    """When streaming is off, re-vote every L5-judged finding so the
    final result reflects the LLM verdict. (When streaming is on, the
    callback already mutated each finding in place — issue #14.)
    """
    for idx, l5_checks in enumerate(l5_results):
        if not l5_checks:
            continue
        existing = out_findings[idx].get("validation", {}).get("checks", [])
        merged = [ValidationCheck.from_json(c) for c in existing]
        if not any(c.id == "llm_judge" for c in merged):
            merged.extend(l5_checks)
        out_findings[idx] = _apply_validation_to_finding(
            out_findings[idx], merged, cfg,
        )
        # _apply_validation_to_finding returns a fresh dict; preserve
        # the existing keys by merging back so the caller's reference
        # observes the update.
        # (Iteration above replaces the slot, which is fine.)


def _revote_l5_judged(
    out_findings: list[dict[str, Any]], cfg: ValidateConfig,
) -> None:
    """Re-vote every finding carrying an ``llm_judge`` check from its current
    in-place checks. Used on the streaming path so the final status reflects
    the feature-0057 P1b safeguards that run after the L5 pool (issue: the
    streaming callback voted before the safeguards neutralised demotions)."""
    for f in out_findings:
        checks = f.get("validation", {}).get("checks", [])
        if any(isinstance(c, dict) and c.get("id") == "llm_judge" for c in checks):
            _revote_finding_in_place(f, cfg)


def _run_l5_phase(
    out_findings: list[dict[str, Any]],
    l1_results: list[list[ValidationCheck]], cfg: ValidateConfig,
    audit_id: str,
    emit_validation_update: Callable[[list[dict[str, Any]]], None] | None,
    event_texts: list[str], layers_run: list[str], duration_ms: dict[str, int],
) -> None:
    """RC3-isolated L5 dispatcher. Mutates out_findings in place."""
    if not _resolve_l5_enabled(cfg):
        return
    t0 = time.monotonic()
    try:
        _stream_batch = _make_l5_stream_callback(cfg, emit_validation_update)
        l5_results = run_l5(
            out_findings, l1_results, cfg,
            audit_id=audit_id, emit_batch=_stream_batch,
        )
        if emit_validation_update is None:
            _backfill_l5_offline(out_findings, l5_results, cfg)
        else:
            # Streaming path: run_l5's per-batch callback already re-voted +
            # emitted intermediate states for the live UI. But the feature
            # 0057 P1b safeguards (RC6 cap / trusted / crypto exemption) run
            # *after* the pool, neutralising demoting verdicts in place. Re-
            # vote every judged finding from its (now safe-guarded) checks so
            # the FINAL stored status reflects the safeguards, not the pre-
            # safeguard streamed status.
            _revote_l5_judged(out_findings, cfg)
        layers_run.append("L5")
    except Exception as exc:
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


def _emit_summary(
    out_findings: list[dict[str, Any]], rollups: list[dict[str, Any]],
    duration_ms: dict[str, int], event_texts: list[str],
) -> None:
    """Append the final summary event text + populate parent status fields."""
    total_ms = sum(duration_ms.values())
    counts = {"likely_fp": 0, "suspicious": 0, "high_confidence": 0}
    for f in out_findings:
        status = f.get("validation_status", "suspicious")
        counts[status] = counts.get(status, 0) + 1
    event_texts.append(
        f"[validate] done in {total_ms}ms · "
        f"high={counts['high_confidence']} · "
        f"susp={counts['suspicious']} · "
        f"fp={counts['likely_fp']} · "
        f"rollups={len(rollups)}"
    )
    # Mirror status/confidence onto rollup parents so the UI's
    # status filter doesn't skip parent rows persisted with NULL.
    for parent in rollups:
        v_blob = parent.get("validation") or {}
        parent["validation_status"] = v_blob.get("status", "suspicious")
        parent["validation_confidence"] = v_blob.get("confidence", 0.4)


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
        return _empty_result(["[validate] no findings to validate"])

    event_texts: list[str] = []
    layers_run: list[str] = []
    duration_ms: dict[str, int] = {}

    l1_results = _run_l1_phase(findings, cfg, event_texts, layers_run, duration_ms)
    l2_results, rollups = _run_l2_phase(
        findings, cfg, audit_id, event_texts, layers_run, duration_ms,
    )
    out_findings = _provisional_vote(
        findings, l1_results, l2_results, cfg, layers_run, duration_ms,
    )
    _run_l5_phase(
        out_findings, l1_results, cfg, audit_id, emit_validation_update,
        event_texts, layers_run, duration_ms,
    )
    _emit_summary(out_findings, rollups, duration_ms, event_texts)

    return ValidationResult(
        findings=out_findings, rollups=rollups,
        event_texts=event_texts, layers_run=layers_run,
        duration_ms=duration_ms,
    )
