"""Validation phase — feature 0045.

Single entry point: `validate(findings, source_path, ...)`.
See docs/features/0045_validation_phase/0045_implementation_plan.md
for the full design and the V1–V10 separation invariants.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

from .compliance import apply_compliance_mode
from .context_heuristics import clear_l1_cache, run_l1
from .llm_judge import (
    COVERAGE_ID,
    COVERAGE_JUDGE_ERROR,
    COVERAGE_SKIPPED_L5_DISABLED,
    COVERAGE_SKIPPED_NO_WINDOW,
    _l5_check_is_demoting,
    run_l5,
    stamp_coverage,
)
from .refutation import clear_route_model_cache, obligation_check
from .rollup import run_l2
from .types import (
    FindingValidation,
    ValidateConfig,
    ValidationCheck,
    ValidationResult,
)
from .voter import JUDGE_UNDECIDED, OBLIGATION_ID, vote
from shared.tools.window import record_window_reason, window_reason_of

# Verdict states that assert NOTHING about the finding. Neither is a survival
# signal, so neither may re-tag provenance as judge-verified (0072 T4.8).
_L5_NO_ASSERTION: frozenset[str] = frozenset({JUDGE_UNDECIDED, "error"})

__all__ = [
    "FindingValidation",
    "ValidateConfig",
    "ValidationCheck",
    "ValidationResult",
    "is_enabled",
    "validate",
]


def is_enabled(config: dict[str, Any] | None) -> bool:
    """Resolve the on/off knob.

    Precedence: env var > config > default-on.
    """
    if os.environ.get("VULTURE_DISABLE_VALIDATE", "").lower() == "true":
        return False
    return not (config and config.get("disable_validate"))


def _resolve_l5_enabled(cfg: ValidateConfig) -> bool:
    """Resolve the L5 master switch: per-request override → env → field.

    Feature 0083 W1. The env used to be read FIRST, which made an explicit
    `--validate-llm` a dead flag on the stock deployment: docker-compose pins
    `VULTURE_USE_VALIDATE_LLM=${VULTURE_USE_VALIDATE_LLM:-false}` on all ten
    agent blocks, and `false` defeated the request. Every finding came back
    stamped `skipped_l5_disabled` while the operator had asked for the judge.

    The env keeps deciding whenever the request is silent, so no existing
    deployment changes.
    """
    if cfg.enable_l5_override is not None:
        return bool(cfg.enable_l5_override)
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
    source_path: str = "",
) -> list[list[ValidationCheck]]:
    """RC3-isolated L1 dispatcher. Returns one check-list per finding.

    `source_path` is the scanned tree's root. It is what lets a WIRING-scoped
    obligation be resolved against the route model; without it every
    authorization finding can only ever be `unknown`.
    """
    if not cfg.enable_l1:
        return [[] for _ in findings]
    t0 = time.monotonic()
    clear_l1_cache()
    # The route model is cached per source root so it is built ONCE per audit
    # rather than once per finding. Clearing it here (like the L1 line cache)
    # bounds that reuse to a single audit: agent processes are long-lived, so a
    # process-lifetime cache would serve a stale route table for a second scan
    # of the same path after the tree moved — and refutations read from a stale
    # table are exactly the false negatives this feature must not create.
    clear_route_model_cache()
    try:
        l1_results = run_l1(findings, source_root=source_path)
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

    An ``llm``-provenance finding is promoted to ``llm_l5_verified`` when the
    judge left it standing. A demoting or absent L5 verdict leaves the ``llm``
    tag in place. Deterministic findings (any non-``llm`` provenance) are NEVER
    re-tagged to an ``llm_*`` provenance. Mutates in place; the validation*
    fields stamped by the caller are untouched.

    Feature 0072 T4.8: "survives" excludes verdicts that ASSERTED NOTHING. The
    predicate was the bare negation of a demotion, so two no-assertion states
    re-tagged a finding as "independently confirmed by the judge":

      * the no-verdict stub (``result="error"``, weight 0.0) emitted when the
        judge is unreachable — the same stub the L5 summary reports as
        "CONTRIBUTED NOTHING; treat this run as unjudged". Provenance said
        verified while the summary said unjudged.
      * a ``JUDGE_UNDECIDED`` verdict, the judge's own "cannot tell" — 10 of 10
        live verdicts on a real run sat exactly there.

    Deliberately NOT ``any(c.result == JUDGE_CITED)``. A verdict neutralised by
    the RC6 cap or the policy exemption is rebuilt as ``result="advisory"``,
    weight 0.0, and must still re-tag — ``test_provenance.py``'s streaming class
    exists precisely because that path was once unreachable. Subtracting the two
    no-assertion states kills both live traps and leaves that contract intact.
    """
    if new_f.get("provenance") != "llm":
        return
    l5_checks = [c for c in checks if c.id == "llm_judge"]
    if not l5_checks:
        return
    if any(_l5_check_is_demoting(c) for c in l5_checks):
        return
    if all(c.result in _L5_NO_ASSERTION for c in l5_checks):
        return
    new_f["provenance"] = "llm_l5_verified"


def _strip_private(new_f: dict[str, Any]) -> None:
    """Feature 0076 §5.4(2): drop the model-copied quote and the verifier's
    private stamps from the row this stage hands on.

    `run_l1` is their last consumer — it has already turned `_anchor_status`
    into the `anchor` check inside the persisted `validation` blob, which is
    the ONE egress route the feature commits to. Everything else about them is
    a liability: `evidence_quote` is model-copied source that can contain a
    live credential, and `emitter.finding_event(**finding)` would forward any
    surviving key verbatim to SSE while Go's fixed `model.Finding` dropped it,
    making the live stream and its replay disagree.

    The roster is imported rather than restated: one list of private names,
    one deletion pass (`audit_runner._strip_private_fields`). Imported at call
    time because `audit_runner` imports this package.
    """
    from shared.audit_runner import _strip_private_fields

    _strip_private_fields(new_f)


def _apply_validation_to_finding(
    finding: dict[str, Any], checks: list[ValidationCheck], cfg: ValidateConfig,
) -> dict[str, Any]:
    """Vote on checks and stamp validation fields onto a copy of the finding."""
    status, confidence = vote(checks)
    v = FindingValidation(status=status, confidence=confidence, checks=checks)
    if cfg.compliance_mode:
        v = apply_compliance_mode(v)
    new_f = dict(finding)
    # Feature 0082 C10: capture any window reason BEFORE the blob is replaced.
    # This is an overwrite, not a merge — a reason stamped upstream by
    # ensure_code_window (audit_runner.py:2487, which runs before _validate at
    # :2550) is otherwise destroyed here, and the "every empty window carries a
    # reason" guarantee would hold nowhere it is actually measured.
    prior_window = window_reason_of(finding)
    _strip_private(new_f)
    new_f["validation"] = v.to_json()
    new_f["validation_status"] = v.status
    new_f["validation_confidence"] = v.confidence
    # Re-attached AFTER the vote, never as an input to it: the check carries
    # weight 0.0 and recording why evidence is absent must not be able to move
    # a status or a confidence.
    if prior_window:
        record_window_reason(new_f, prior_window)
    _retag_l5_verified(new_f, checks)
    return new_f


def _ensure_obligation(
    finding: dict[str, Any], checks: list[ValidationCheck],
) -> list[ValidationCheck]:
    """Feature 0072: no finding may reach the voter without an obligation.

    A finding carrying NO obligation check is indistinguishable, to the gate,
    from one whose obligation was discharged — the same unknown-as-neutral
    defect the feature exists to remove, one level up.

    This is not hypothetical. L2 rollup PARENTS are synthesised after L1, so
    they never pass through run_l1 and arrive with an empty check list; without
    this guard they would confirm freely under enforcement. Found by scanning
    Vulture with Vulture, not by a unit test — every unit test reached the voter
    through run_l1.
    """
    if any(c.id == OBLIGATION_ID for c in checks):
        return checks
    return checks + [obligation_check(finding.get("category", "") or "", None)]


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
            finding,
            _ensure_obligation(
                finding, list(l1_results[idx]) + list(l2_results[idx])
            ),
            cfg,
        )
        for idx, finding in enumerate(findings)
    ]
    duration_ms["vote"] = int((time.monotonic() - t0) * 1000)
    layers_run.append("vote")
    return out_findings


def _revote_finding_in_place(
    finding: dict[str, Any], cfg: ValidateConfig,
) -> None:
    """Re-run vote() using the finding's own checks; mutate in place.

    Feature 0057 P6b: this is the finaliser on the L5 *streaming* path
    (``_run_l5_phase`` calls it via ``_revote_l5_judged`` when an
    ``emit_validation_update`` callback is wired). The offline backfill path
    finalises through ``_apply_validation_to_finding`` which already promotes
    a surviving LLM finding to ``llm_l5_verified``; the streaming revote must
    apply the SAME promotion or the re-tag is unreachable in the live audit
    (it only ever appeared in unit tests of the offline set-point). Mirror it
    here so a streamed LLM finding that carries a non-demoting ``llm_judge``
    verdict is re-tagged identically.
    """
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
    _retag_l5_verified(finding, revote_checks)


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
    source_path: str = "",
    rollups: list[dict[str, Any]] | None = None,
) -> None:
    """RC3-isolated L5 dispatcher. Mutates out_findings (and rollup parents)
    in place."""
    # AC7 covers rollup PARENTS too. They are synthesised after L1 and never
    # pass through run_l5 — the same gap class _ensure_obligation closed for
    # obligations, and found the same way: scanning Vulture with Vulture left
    # 306 of 2095 result rows (every L2 parent) without a coverage check.
    rollups = rollups or []
    if not _resolve_l5_enabled(cfg):
        # Feature 0072 P6 (AC7): the layer being off is the most common
        # "why was this never judged" of all, and it must be a stated fact
        # on the finding rather than an absence the reader infers.
        for f in out_findings + rollups:
            stamp_coverage(f, COVERAGE_SKIPPED_L5_DISABLED,
                           "L5 judge disabled for this run")
        _emit_l5_coverage_summary(out_findings + rollups, event_texts)
        return
    t0 = time.monotonic()
    try:
        _stream_batch = _make_l5_stream_callback(cfg, emit_validation_update)
        l5_results = run_l5(
            out_findings, l1_results, cfg,
            audit_id=audit_id, emit_batch=_stream_batch,
            source_path=source_path,
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
        # The whole layer crashed: any finding run_l5 never stamped was
        # attempted-and-lost, not skipped by a selection decision.
        for f in out_findings:
            stamp_coverage(f, COVERAGE_JUDGE_ERROR,
                           f"L5 layer failed outright: {type(exc).__name__}")
    finally:
        duration_ms["L5"] = int((time.monotonic() - t0) * 1000)
    # A finding carrying only an `error`/`no verdict` stub was NOT judged. The
    # count used to lump the two together, so a completely dead judge reported
    # "N finding(s) judged" and read as success. Live-observed: an LM Studio
    # model that failed to load 400'd every call, producing 680 error stubs
    # under a summary claiming 680 judged.
    #
    # This is the feature's own thesis one layer up: "we never checked" must not
    # be presentable as "we checked and it was clean".
    judged = errored = 0
    for f in out_findings:
        verdicts = [c for c in f.get("validation", {}).get("checks", [])
                    if c.get("id") == "llm_judge"]
        if not verdicts:
            continue
        if all(c.get("result") == "error" for c in verdicts):
            errored += 1
        else:
            judged += 1
    msg = f"[validate] L5 done · {judged} finding(s) judged"
    if errored:
        msg += f" · {errored} returned no verdict (judge unavailable)"
        if not judged:
            msg += " — L5 CONTRIBUTED NOTHING; treat this run as unjudged"
    event_texts.append(msg)
    # Rollup parents never enter run_l5 (they are not in out_findings'
    # selection universe): stamp them here so AC7 holds for every row.
    for parent in rollups:
        stamp_coverage(parent, COVERAGE_SKIPPED_NO_WINDOW,
                       "rollup parent: synthesised row, never judged")
    _emit_l5_coverage_summary(out_findings + rollups, event_texts)


def _emit_l5_coverage_summary(
    out_findings: list[dict[str, Any]], event_texts: list[str],
) -> None:
    """Feature 0072 P6 (T6.2): per-run L5 coverage, by result and provenance.

    The run-level counterpart of the per-finding coverage check: which share
    of the findings the judge actually saw, and — for the rest — why not,
    named per skip reason rather than left as a smaller "judged" count.
    """
    counts: dict[str, int] = {}
    by_provenance: dict[str, dict[str, int]] = {}
    for f in out_findings:
        cov = next(
            (c for c in f.get("validation", {}).get("checks", [])
             if isinstance(c, dict) and c.get("id") == COVERAGE_ID),
            None,
        )
        if cov is None:
            continue
        result = cov.get("result", "")
        counts[result] = counts.get(result, 0) + 1
        prov = f.get("provenance") or "skill"
        by_provenance.setdefault(prov, {})
        by_provenance[prov][result] = by_provenance[prov].get(result, 0) + 1
    if not counts:
        return
    parts = [f"{r}={n}" for r, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    prov_parts = [
        f"{prov}: " + ", ".join(
            f"{r}={n}" for r, n in sorted(results.items(), key=lambda kv: -kv[1])
        )
        for prov, results in sorted(by_provenance.items())
    ]
    event_texts.append(
        "[validate] L5 coverage · " + " · ".join(parts)
        + " · by provenance — " + "; ".join(prov_parts)
    )


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

    l1_results = _run_l1_phase(
        findings, cfg, event_texts, layers_run, duration_ms, source_path)
    l2_results, rollups = _run_l2_phase(
        findings, cfg, audit_id, event_texts, layers_run, duration_ms,
    )
    out_findings = _provisional_vote(
        findings, l1_results, l2_results, cfg, layers_run, duration_ms,
    )
    _run_l5_phase(
        out_findings, l1_results, cfg, audit_id, emit_validation_update,
        event_texts, layers_run, duration_ms, source_path, rollups,
    )
    _emit_summary(out_findings, rollups, duration_ms, event_texts)

    return ValidationResult(
        findings=out_findings, rollups=rollups,
        event_texts=event_texts, layers_run=layers_run,
        duration_ms=duration_ms,
    )
