"""Feature 0072 P7 — the calibration gate (T7.1–T7.4).

The control loop that keeps §9's guarantee true over time:

  * ``evaluate_rules`` — per-rule confirmed-tier PRECISION on a labelled
    corpus (T7.1) and the RECALL guard on the labelled positives (T7.3):
    a labelled-real finding dismissed to ``likely_fp`` is the false-negative
    failure this feature must never trade for its precision win.
  * ``rules_below_precision`` + a demotion file — a rule below threshold is
    demoted to candidate-only (T7.2). Demotion is enforced by forcing the
    rule's obligation to UNKNOWN at emission (refutation._decide_state),
    which reuses the existing status gate in BOTH voter languages — no new
    rule crosses the process boundary, so nothing can drift.
  * ``scope_divergence`` — alert when the scope actually searched diverges
    from the declared one for a material share of a rule's findings (T7.4).

**When demotion takes effect.** Like the rest of the gate, demotion acts only
under ``VULTURE_OBLIGATION_MODE=enforce`` — in the shipping ``observe`` default
it is recorded but changes no status (AC22). Within enforce mode, though, a
demoted rule gates REGARDLESS of whether its class's scope has been reviewed:
imprecision proven by measurement is orthogonal to scope-search adequacy, so a
demotion must not wait on the per-class ``scope_reviewed`` flip. It is keyed by
EITHER the finding's ``check_id`` or its ``category`` (matching how a rule is
identified when measured), so a finding lacking a ``check_id`` is still gated.

The demotion set is data, not code: ``VULTURE_CALIBRATION_FILE`` points at a
JSON file ``{"demoted_rules": ["check-id-or-category", ...]}`` produced by a
measurement run. No file (the default) demotes nothing.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

__all__ = [
    "RuleStats",
    "evaluate_rules",
    "finding_rule_demoted",
    "reset_demoted_rules_cache",
    "rule_is_demoted",
    "rules_below_precision",
    "scope_divergence",
]


# ── T7.2: the demotion set ──────────────────────────────────────────────────

_DEMOTED_LOCK = threading.Lock()
_DEMOTED_CACHE: Optional[frozenset[str]] = None


def _load_demoted_rules() -> Optional[frozenset[str]]:
    """The demoted-rule set, or None if a configured file could not be read.

    None (a genuine read/parse FAILURE) is distinct from an empty set (no file
    configured, or an empty list): None is NOT cached, so a transient failure
    — an NFS blip, a mid-write by the measurement job — self-heals on the next
    call instead of disabling demotion for the whole process lifetime.
    """
    path = os.getenv("VULTURE_CALIBRATION_FILE", "").strip()
    if not path:
        return frozenset()          # no file configured — a stable empty
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        rules = data.get("demoted_rules", [])
        if not isinstance(rules, list):
            raise ValueError("demoted_rules must be a list")
        return frozenset(str(r) for r in rules if r)
    except Exception as exc:
        # Fail OPEN by design: a broken calibration file must not demote
        # every rule (fail-closed here would empty the confirmed tier on a
        # typo). The error is loud; the gate simply doesn't fire — and we
        # return None so the failure is not cached.
        log.warning("[validate.calibration] cannot read %s (%s); "
                    "no rules demoted (will retry)", path, exc)
        return None


def _demoted_rules() -> frozenset[str]:
    """Cached demoted-rule set. Only a successful load is cached; a failed
    read returns empty for THIS call but leaves the cache unset so it retries."""
    global _DEMOTED_CACHE
    if _DEMOTED_CACHE is not None:
        return _DEMOTED_CACHE
    with _DEMOTED_LOCK:
        if _DEMOTED_CACHE is not None:
            return _DEMOTED_CACHE
        loaded = _load_demoted_rules()
        if loaded is None:
            return frozenset()      # transient failure — do not cache
        _DEMOTED_CACHE = loaded
        return _DEMOTED_CACHE


def rule_is_demoted(rule: str) -> bool:
    """Whether the calibration gate demoted this rule id to candidate-only."""
    return bool(rule) and rule in _demoted_rules()


def finding_rule_demoted(check_id: str, category: str) -> bool:
    """Whether a finding's rule is demoted, by EITHER identifier.

    The measurement side (`_rule_of`) keys a rule as ``check_id or category``,
    so a finding with no ``check_id`` is written to the calibration file under
    its category. Enforcement must consult the SAME pair or the two halves of
    the loop disagree and the demotion silently does nothing.
    """
    return rule_is_demoted(check_id) or rule_is_demoted(category)


def reset_demoted_rules_cache() -> None:
    """Re-read VULTURE_CALIBRATION_FILE on next use (tests / config reload)."""
    global _DEMOTED_CACHE
    with _DEMOTED_LOCK:
        _DEMOTED_CACHE = None


# ── T7.1 / T7.3: per-rule measurement ───────────────────────────────────────


@dataclass
class RuleStats:
    """Per-rule outcome counts against a labelled corpus."""

    rule: str
    findings: int = 0
    confirmed: int = 0                 # validation_status == high_confidence
    confirmed_true: int = 0            # ... and labelled real
    confirmed_false: int = 0           # ... and labelled false positive
    dismissed_true_positives: int = 0  # labelled real but likely_fp (T7.3)
    labelled_real: int = 0
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed_precision(self) -> Optional[float]:
        """Precision of the confirmed tier; None when nothing confirmed."""
        if self.confirmed == 0:
            return None
        return self.confirmed_true / self.confirmed

    @property
    def surviving_recall(self) -> Optional[float]:
        """Share of labelled-real findings NOT dismissed (T7.3's guard:
        a false refutation deletes findings; this is where it shows)."""
        if self.labelled_real == 0:
            return None
        return 1.0 - (self.dismissed_true_positives / self.labelled_real)


def _rule_of(finding: dict[str, Any]) -> str:
    return (finding.get("check_id")
            or finding.get("category")
            or "unknown-rule")


def evaluate_rules(
    labelled: list[tuple[dict[str, Any], bool]],
) -> dict[str, RuleStats]:
    """Score validated findings against ground-truth labels, per rule.

    ``labelled`` pairs each finding (carrying ``validation_status``) with its
    label: True = real vulnerability, False = false positive.
    """
    stats: dict[str, RuleStats] = {}
    for finding, is_real in labelled:
        rule = _rule_of(finding)
        s = stats.setdefault(rule, RuleStats(rule=rule))
        s.findings += 1
        if is_real:
            s.labelled_real += 1
        status = finding.get("validation_status", "suspicious")
        if status == "high_confidence":
            s.confirmed += 1
            if is_real:
                s.confirmed_true += 1
            else:
                s.confirmed_false += 1
        elif status == "likely_fp" and is_real:
            s.dismissed_true_positives += 1
    return stats


def rules_below_precision(
    stats: dict[str, RuleStats], threshold: float, min_findings: int = 3,
) -> set[str]:
    """T7.2: rules whose confirmed-tier precision measured below threshold.

    ``min_findings`` guards against demoting a rule on one bad sample; a rule
    that confirmed nothing has no precision and is never demoted for it.
    """
    out: set[str] = set()
    for rule, s in stats.items():
        p = s.confirmed_precision
        if p is None or s.confirmed < min_findings:
            continue
        if p < threshold:
            out.add(rule)
    return out


# ── T7.4: scope divergence ──────────────────────────────────────────────────


def scope_divergence(
    findings: list[dict[str, Any]], material_share: float = 0.25,
) -> dict[str, float]:
    """Per-rule share of findings whose obligation searched a DIFFERENT
    scope than the class declared. Returns only rules at or above
    ``material_share`` — the alert set, not the raw table.

    Reads the obligation check's extras (`scope_declared` / `scope_actual`)
    as recorded by refutation.obligation_check. Findings whose obligation
    never searched (both None) do not count as divergent.
    """
    seen: dict[str, int] = {}
    diverged: dict[str, int] = {}
    for f in findings:
        checks = (f.get("validation") or {}).get("checks", [])
        ob = next((c for c in checks
                   if isinstance(c, dict) and c.get("id") == "obligation"), None)
        if ob is None:
            continue
        extras = ob.get("extras") or {}
        declared = extras.get("scope_declared")
        actual = extras.get("scope_actual")
        if declared is None or actual is None:
            continue
        rule = _rule_of(f)
        seen[rule] = seen.get(rule, 0) + 1
        if actual != declared:
            diverged[rule] = diverged.get(rule, 0) + 1
    return {
        rule: diverged.get(rule, 0) / total
        for rule, total in seen.items()
        if total and diverged.get(rule, 0) / total >= material_share
    }
