"""L2 rollup — collapse near-duplicate findings into one parent
record. Children stay in the dataset (V6) with a back-reference.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from shared.env import env_flag
from shared.tools.window import WINDOW_ROLLUP_PARENT, window_check

from .refutation import obligation_check
from .types import ValidationCheck, _utc_now_iso

__all__ = ["derive_parent_verdicts", "rollup_id", "run_l2"]


_NORM_WS_RE = re.compile(r"\s+")

# The verdict a parent carries until its members supply one. Kept as the
# fallback rather than removed: a parent whose members cannot be resolved
# must not read as confirmed, and must not read as dismissed either.
PLACEHOLDER_CONFIDENCE = 0.40
PLACEHOLDER_STATUS = "suspicious"


def _normalize_title(title: str) -> str:
    """Lowercase + collapse whitespace + strip. M1 spec."""
    return _NORM_WS_RE.sub(" ", title or "").strip().lower()


def rollup_id(
    audit_id: str, category: str, title: str, file_path: str,
) -> str:
    """Deterministic rollup parent ID — SHA-256 hash of the key.

    Re-running validate on the same audit MUST produce the same ID
    so persistence is UPSERT and we don't get duplicate parents.
    """
    h = hashlib.sha256()
    for part in (audit_id, category, _normalize_title(title), file_path):
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\0")
    return "rollup-" + h.hexdigest()[:24]


def _rollup_status_for(category: str, instance_count: int) -> str:
    """Per the plan §D: dependency-file rollups → suspicious; large
    code-file rollups → suspicious; otherwise inherit max-of-members
    (handled by the caller using the member statuses; v1 always
    returns 'suspicious' as a reasonable default since rollups are
    inherently "review me but not individually")."""
    return "suspicious"


def _group_findings(
    findings: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[int]]:
    """Group findings by (category, normalised title, file_path)."""
    groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for idx, f in enumerate(findings):
        key = (
            f.get("category", "") or "",
            _normalize_title(f.get("title", "") or ""),
            f.get("file_path", "") or "",
        )
        groups[key].append(idx)
    return groups


_MAX_LISTED_LINES = 12
_MAX_EXTRA_CHARS = 200


def _sorted_member_lines(members: list[dict[str, Any]]) -> list[int]:
    """Distinct, ordered member line numbers (0/absent treated as unknown)."""
    return sorted({int(m.get("line_start") or 0) for m in members} - {0})


def _member_lines(members: list[dict[str, Any]]) -> str:
    """Comma-separated member lines, truncated so a large group stays readable."""
    lines = _sorted_member_lines(members)
    shown = ", ".join(str(n) for n in lines[:_MAX_LISTED_LINES])
    return f"{shown}, …" if len(lines) > _MAX_LISTED_LINES else shown


def _member_descriptions(members: list[dict[str, Any]]) -> list[str]:
    """Non-empty, stripped member descriptions."""
    raw = [str(m.get("description") or "").strip() for m in members]
    return [d for d in raw if d]


def _distinct_extra(members: list[dict[str, Any]], title: str) -> str:
    """Detail a member's description carries beyond the shared title.

    Members share a title by construction, so the only per-member information
    is what a specialised detector — or an ancestor collapse folding one in —
    added to the description. Surface the longest such fragment rather than
    dropping all of them; that is the most specific thing the group knows.
    """
    norm = _normalize_title(title)
    extras = [d for d in _member_descriptions(members) if _normalize_title(d) != norm]
    return max(extras, key=len, default="")[:_MAX_EXTRA_CHARS]


def _best_recommendation(members: list[dict[str, Any]]) -> str:
    """The most specific member recommendation, not merely the first.

    Members usually share a recommendation; when they differ it is because one
    absorbed a specialised detector's remediation, which is strictly the more
    actionable text. Length is the proxy for specificity — crude, but it cannot
    pick the *poorer* string when one is a superset of the other, which is the
    shape this actually takes.
    """
    return max(
        (str(m.get("recommendation") or "") for m in members), key=len, default=""
    )


def _rollup_description(
    members: list[dict[str, Any]], instance_count: int, title: str,
) -> str:
    """Summarise the group: how many, where, and any member-specific detail."""
    lines = _member_lines(members)
    where = f" at line{'s' if instance_count != 1 else ''} {lines}" if lines else ""
    head = f"{instance_count} instances rolled up{where}."
    extra = _distinct_extra(members, title)
    return f"{head} {extra}".rstrip() if extra else head


def _window_checks() -> list[dict[str, Any]]:
    """The window check for a rollup parent, or nothing when feature 0082's
    VULTURE_FINDING_WINDOW_PARITY is off. Read at call time so the switch is
    flippable without a restart, and so the rollback genuinely removes the
    stamp rather than leaving it in place under a disabled flag."""
    if not env_flag("VULTURE_FINDING_WINDOW_PARITY", True):
        return []
    return [window_check(WINDOW_ROLLUP_PARENT)]


def _build_rollup_parent(
    audit_id: str, category: str, file_path: str,
    members: list[dict[str, Any]], instance_count: int,
) -> dict[str, Any]:
    """Construct a single rollup-parent record from its members."""
    line_start = min((m.get("line_start") or 0) for m in members) or 1
    line_end = max((m.get("line_end") or 0) for m in members) or line_start
    severity = _max_severity([m.get("severity", "low") for m in members])
    title = members[0].get("title", "") or ""
    parent_id = rollup_id(audit_id, category, title, file_path)
    return {
        "id": parent_id,
        "audit_id": audit_id,
        "is_rollup": True,
        # Feature 0057 P6b: the L2 grouping parent ships to the frontend/DB
        # AFTER the central _set_provenance choke point has run, so stamp its
        # provenance here. A rollup parent carries no check_id / signature_status
        # (so _classify_deterministic_provenance would mislabel it "skill"); the
        # vocabulary reserves "catalog_rollup" for exactly this grouping record.
        "provenance": "catalog_rollup",
        "category": category,
        "title": title,
        "description": _rollup_description(members, instance_count, title),
        "file_path": file_path,
        "line_start": int(line_start),
        "line_end": int(line_end),
        "severity": severity,
        "instance_count": instance_count,
        "rolled_up_member_ids": [m.get("id", "") for m in members],
        "recommendation": _best_recommendation(members),
        # Feature 0072: a rollup parent must carry an obligation like any other
        # finding. It is appended to the result AFTER validate() returns
        # (audit_runner: `all_findings + v_result.rollups`), so it never reaches
        # the voter — and a finding with no obligation check is indistinguishable,
        # to the gate, from one whose obligation was discharged. Stamping it here
        # is the only place that sees the parent before it ships.
        "validation": {
            "status": _rollup_status_for(category, instance_count),
            "confidence": PLACEHOLDER_CONFIDENCE,
            # Feature 0082 C9: a parent's line_start is min(member lines), so
            # handing it one member's window would present 1 of `instance_count`
            # sites as evidence for all of them — the misrepresentation E4
            # forbids, moved from the verdict field into the evidence field. The
            # parent is LABELLED instead. Weight 0.0: bookkeeping, never evidence.
            "checks": [obligation_check(category, None).to_json(),
                       *_window_checks()],
            "validated_at": "",
        },
    }


def _member_confidence(member: dict[str, Any]) -> float | None:
    """A member's voted confidence, or None if it never got one.

    None and 0.0 must stay distinguishable: an unvoted member carries no
    information and is skipped, whereas a member voted to 0.0 is a real
    dismissal and belongs in the max.
    """
    raw = member.get("validation_confidence")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def derive_parent_verdicts(
    findings: list[dict[str, Any]], rollups: list[dict[str, Any]],
) -> None:
    """Give each rollup parent the verdict of its strongest member.

    A parent is synthesised in L2, after L1, and appended to the result only
    after ``validate()`` has returned, so it never reaches the voter and L5
    skips it by name. Until this ran, every parent shipped
    ``PLACEHOLDER_STATUS`` at ``PLACEHOLDER_CONFIDENCE`` — a literal, not a
    judgement. Measured on one 336-finding run: 83 rows (24.7%) carried
    ``suspicious`` / 0.40 regardless of what their members said, and
    ``likely_fp`` was unreachable for all of them, because ``_classify``
    needs two demoting checks and a parent's own checks are all weight 0.0.

    The members ARE fully voted by the time this runs, so the information
    already exists. MAX, not mean: a rollup groups instances of one weakness
    in one file, so a group holding a confirmed bug must be reviewed at that
    strength — averaging it against its siblings would bury it. Symmetrically
    a group whose every member was dismissed inherits the dismissal.

    Mutates the parents in place. Idempotent per call site; the derived
    ``rollup`` check replaces any earlier one so re-running cannot stack
    duplicates.
    """
    if not rollups:
        return
    by_id = {f["id"]: f for f in findings if f.get("id")}
    for parent in rollups:
        blob = parent.setdefault("validation", {})
        checks = [c for c in blob.get("checks", [])
                  if c.get("id") != "rollup"]
        scored = [
            (conf, mid) for mid in parent.get("rolled_up_member_ids", [])
            if (m := by_id.get(mid)) is not None
            and (conf := _member_confidence(m)) is not None
        ]
        if not scored:
            checks.append(ValidationCheck(
                id="rollup", result="orphan", weight=0.0,
                reason="no voted member resolved; verdict is the placeholder",
                extras={"members_total": len(
                    parent.get("rolled_up_member_ids", []))},
            ).to_json())
            blob["checks"] = checks
            continue
        best_conf, best_id = max(scored)
        best = by_id[best_id]
        blob["confidence"] = best_conf
        blob["status"] = best.get("validation_status") or PLACEHOLDER_STATUS
        blob["validated_at"] = _utc_now_iso()
        checks.append(ValidationCheck(
            id="rollup", result="derived", weight=0.0,
            reason=(f"inherited from the strongest of {len(scored)} voted "
                    f"member(s)"),
            extras={"inherited_from": best_id,
                    "members_voted": len(scored),
                    "members_total": len(
                        parent.get("rolled_up_member_ids", []))},
        ).to_json())
        blob["checks"] = checks


def _mark_rollup_members(
    per_finding: list[list[ValidationCheck]],
    indices: list[int], parent_id: str, count: int,
) -> None:
    """Replace each member's singleton check with a `rolled_up` ref."""
    check = ValidationCheck(
        id="rollup", result="rolled_up", weight=0.0,
        reason=f"member of rollup ({count} instances)",
        extras={"rolled_up_into": parent_id},
    )
    for i in indices:
        per_finding[i] = [check]


def _l2_error_result(
    findings: list[dict[str, Any]], exc: BaseException,
) -> tuple[list[list[ValidationCheck]], list[dict[str, Any]]]:
    """Layer-isolated fallback when run_l2 hits an unexpected exception."""
    return (
        [[ValidationCheck(
            id="rollup", result="error", weight=0.0,
            reason=f"L2 error: {type(exc).__name__}")] for _ in findings],
        [],
    )


def run_l2(
    findings: list[dict[str, Any]], audit_id: str = "",
) -> tuple[list[list[ValidationCheck]], list[dict[str, Any]]]:
    """Group findings; emit per-finding check lists + new rollup parents.

    Returns `(per_finding_checks, rollup_parents)`. `per_finding_checks`
    has the same length as `findings` (V6 — demote, never drop).
    Members of a rollup get a `rollup` check pointing at their parent
    via `extras.rolled_up_into = <parent_id>`.

    Layer-isolated: any exception falls through to a single
    `(neutral, [])` per finding without aborting.
    """
    try:
        groups = _group_findings(findings)
        per_finding: list[list[ValidationCheck]] = [
            [ValidationCheck(id="rollup", result="singleton", weight=0.0)]
            for _ in findings
        ]
        rollup_parents: list[dict[str, Any]] = []
        for (category, _norm_title, file_path), indices in groups.items():
            if len(indices) < 2:
                continue
            members = [findings[i] for i in indices]
            parent = _build_rollup_parent(
                audit_id, category, file_path, members, len(indices),
            )
            rollup_parents.append(parent)
            _mark_rollup_members(per_finding, indices, parent["id"], len(indices))
        return per_finding, rollup_parents
    except Exception as exc:    # RC3 layer-isolated
        return _l2_error_result(findings, exc)


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_severity(sevs: list[str]) -> str:
    return max(sevs, key=lambda s: _SEVERITY_RANK.get((s or "").lower(), 0))
