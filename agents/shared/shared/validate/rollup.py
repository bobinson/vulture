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
        groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
        for idx, f in enumerate(findings):
            key = (
                f.get("category", "") or "",
                _normalize_title(f.get("title", "") or ""),
                f.get("file_path", "") or "",
            )
            groups[key].append(idx)

        # Per-finding checks; default to a singleton marker.
        per_finding: list[list[ValidationCheck]] = [
            [ValidationCheck(id="rollup", result="singleton", weight=0.0)]
            for _ in findings
        ]
        rollup_parents: list[dict[str, Any]] = []

        for (category, norm_title, file_path), indices in groups.items():
            if len(indices) < 2:
                continue
            # Real rollup: build the parent record.
            members = [findings[i] for i in indices]
            line_start = min((m.get("line_start") or 0) for m in members) or 1
            line_end = max((m.get("line_end") or 0) for m in members) or line_start
            severity = _max_severity([m.get("severity", "low") for m in members])
            title = members[0].get("title", "") or ""
            parent_id = rollup_id(audit_id, category, title, file_path)
            parent = {
                "id": parent_id,
                "audit_id": audit_id,
                "is_rollup": True,
                "category": category,
                "title": title,
                "description": (
                    f"{len(indices)} instances rolled up; see member "
                    f"findings for individual line locations."
                ),
                "file_path": file_path,
                "line_start": int(line_start),
                "line_end": int(line_end),
                "severity": severity,
                "instance_count": len(indices),
                "rolled_up_member_ids": [
                    members[k].get("id", "") for k in range(len(members))
                ],
                "recommendation": members[0].get("recommendation", ""),
                "validation": {
                    "status": _rollup_status_for(category, len(indices)),
                    "confidence": 0.40,
                    "checks": [],
                    "validated_at": "",
                },
            }
            rollup_parents.append(parent)
            for i in indices:
                per_finding[i] = [ValidationCheck(
                    id="rollup", result="rolled_up", weight=0.0,
                    reason=f"member of rollup ({len(indices)} instances)",
                    extras={"rolled_up_into": parent_id},
                )]
        return per_finding, rollup_parents
    except Exception as exc:    # RC3 layer-isolated
        return (
            [[ValidationCheck(id="rollup", result="error", weight=0.0,
                              reason=f"L2 error: {type(exc).__name__}")] for _ in findings],
            [],
        )


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_severity(sevs: list[str]) -> str:
    return max(sevs, key=lambda s: _SEVERITY_RANK.get((s or "").lower(), 0))
