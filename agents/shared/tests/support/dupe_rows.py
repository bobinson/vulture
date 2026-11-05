"""0076 dedup fixtures shared by the 0076 enforcement tests and 0074's quote
defaults (one fixture, reused, never copied).
"""

from __future__ import annotations

from typing import Any


def llm_finding(**over: Any) -> dict[str, Any]:
    """One LLM-provenance finding on a neutral path.

    `src/app/session.ts` is chosen so neither `_DEMOTING_PATH_RE` nor
    `_PROMOTING_PATH_RE` (context_heuristics.py:24, :62) matches: the L1 `path`
    check lands at weight 0.0 and every arithmetic assertion on it is about the
    anchor check alone. No `check_id`, so `_dedup_key` falls through to the
    normalised title and the dedup fixtures collapse on title+path.
    """
    base: dict[str, Any] = {
        "title": "Hardcoded credential in the session bootstrap",
        "category": "CWE-798",
        "severity": "high",
        "file_path": "src/app/session.ts",
        "line_start": 30,
        "line_end": 30,
        "provenance": "llm",
        "code_snippet": '30: const token = "hunter2";',
        "description": "A literal credential is assigned at module scope.",
    }
    base.update(over)
    return base


def dupe_rows(stamped: bool = True) -> list[dict[str, Any]]:
    """The `dupe_status.json` shape: four LLM rows, of which index 0 and index 3
    collapse onto ONE dedup key (same normalised title, same path).

    Index 0 is the `absent` claim at line 18; index 3 is the `exact` claim at
    line 15. Under first-seen-wins the survivor is index 0's dict, so every
    assertion about "the survivor" reads position 0 of the output.
    """
    rows = [
        llm_finding(title="Hardcoded credential in the session bootstrap",
                    line_start=18, line_end=18,
                    _anchor_status="absent", _anchor_delta=None,
                    _anchor_candidates=0, _anchor_other_path=None),
        llm_finding(title="Missing rate limit on the login route",
                    line_start=40, line_end=41,
                    _anchor_status="unquoted", _anchor_delta=None,
                    _anchor_candidates=0, _anchor_other_path=None),
        llm_finding(title="Unpinned dependency in the lockfile",
                    line_start=7, line_end=7,
                    _anchor_status="near_miss", _anchor_delta=None,
                    _anchor_candidates=0, _anchor_other_path=None),
        llm_finding(title="Hardcoded credential in the session bootstrap",
                    line_start=15, line_end=16,
                    _anchor_status="exact", _anchor_delta=-3,
                    _anchor_candidates=1, _anchor_other_path=None),
    ]
    return rows if stamped else [_unstamped(row) for row in rows]


def _unstamped(row: dict[str, Any]) -> dict[str, Any]:
    """The row without the verifier's private ``_anchor*`` stamps."""
    return {k: v for k, v in row.items() if not k.startswith("_anchor")}
