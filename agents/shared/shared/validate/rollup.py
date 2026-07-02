"""L2 rollup — collapse near-duplicate findings into one parent
record. Children stay in the dataset (V6) with a back-reference.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from .types import ValidationCheck

__all__ = ["run_l2", "rollup_id"]


_NORM_WS_RE = re.compile(r"\s+")


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
        "description": (
            f"{instance_count} instances rolled up; see member "
            f"findings for individual line locations."
        ),
        "file_path": file_path,
        "line_start": int(line_start),
        "line_end": int(line_end),
        "severity": severity,
        "instance_count": instance_count,
        "rolled_up_member_ids": [m.get("id", "") for m in members],
        "recommendation": members[0].get("recommendation", ""),
        "validation": {
            "status": _rollup_status_for(category, instance_count),
            "confidence": 0.40,
            "checks": [],
            "validated_at": "",
        },
    }


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
