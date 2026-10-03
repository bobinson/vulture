"""Feature 0074 P3 — shared fixtures for citations past end of file.

One synthetic five-line module and the three stages a past-end-of-file citation
travels through in a real run, in production order:

    audit_runner._verify_and_strip   (0076's anchor choke point)
    tools.window.ensure_code_window  (the window stage, record_reasons on)
    validate.context_heuristics.run_l1  (where the `anchor` check is born)

The `anchor` check's ``extras`` is where 0076 persists the verifier's
provenance (``claimed_line``, ``delta``, ``candidates``); under owner decision
O3 = C the claim's range (``claimed_line_range`` in ``in_file`` / ``past_eof`` /
``no_line``) lands beside them, and the status vocabulary is unchanged.

Every helper is a straight line: no branch the tests would have to trust.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# The five-line module. Line 3 is the accused construct.
FIVE_LINES: tuple[str, ...] = (
    'import { run } from "./runner";',
    "const config = loadConfig();",
    "const parsed = eval(userInput);",
    "export default parsed;",
    "// end of module",
)

# Verbatim copy of line 3: clears 0076's signal floor (>= 24 chars, >= 2 tokens).
QUOTE_AT_3 = "const parsed = eval(userInput);"

# Shares no token with any line of FIVE_LINES, so it can be neither `exact`,
# `reanchored` nor `near_miss`: the fabrication signal, status `absent`.
ABSENT_QUOTE = "window.location.href = attackerControlledUrl;"

RANGE_KEY = "claimed_line_range"
RANGES = frozenset({"in_file", "past_eof", "no_line"})

# The nine 0076 statuses. O3 = C keeps this vocabulary exactly.
NINE_STATUSES = frozenset({
    "exact", "reanchored", "ambiguous", "near_miss", "found_elsewhere",
    "absent", "unquoted", "unreadable", "oversize",
})


def write_lines(root: Path, name: str, lines: tuple[str, ...] | list[str]) -> Path:
    """Write ``lines`` (newline-terminated) under ``root`` and return the path."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def five_line_file(root: Path, name: str = "module.ts") -> Path:
    """The synthetic five-line module."""
    return write_lines(root, name, FIVE_LINES)


def numbered_file(root: Path, count: int, name: str = "long.ts") -> Path:
    """A ``count``-line file whose every line is distinct, non-blank code."""
    return write_lines(root, name, [f"const v{i} = compute({i});" for i in range(1, count + 1)])


def llm_row(path: Path, line: int | None, quote: str | None = None,
            **over: Any) -> dict[str, Any]:
    """One parsed LLM finding as ``_parse_llm_result`` leaves it.

    ``line=None`` omits ``line_start`` entirely (the model gave no line).
    """
    row: dict[str, Any] = {
        "title": f"Dynamic evaluation of untrusted input ({line})",
        "severity": "high",
        "category": "CWE-95",
        "file_path": str(path),
        "provenance": "llm",
        "description": "User input reaches eval.",
    }
    row.update({"line_start": line, "line_end": line} if line is not None else {})
    row.update({"evidence_quote": quote} if quote is not None else {})
    row.update(over)
    return row


def set_quote_mode(monkeypatch: Any, mode: str, reanchor: str = "true") -> None:
    """Pin 0076's switches explicitly, independent of whatever default ships."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", mode)
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", reanchor)
    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", "false")


def clear_all_caches() -> None:
    """Drop every file cache the three stages read through."""
    from shared.tools.file_scanner import clear_caches
    from shared.validate.context_heuristics import clear_l1_cache

    clear_caches()
    clear_l1_cache()


def choke_point(rows: list[dict[str, Any]], root: Path) -> list[dict[str, Any]]:
    """0076's real anchor choke point, on fresh caches."""
    from shared import audit_runner

    clear_all_caches()
    return audit_runner._verify_and_strip(rows, str(root))


def window_stage(rows: list[dict[str, Any]], root: Path) -> list[dict[str, Any]]:
    """The real window stage with reason recording on; returns ``rows``."""
    from shared.tools.window import ensure_code_window

    ensure_code_window(rows, str(root), record_reasons=True)
    return rows


def window_reason(row: dict[str, Any]) -> str:
    """The recorded window reason of one row ("" when none)."""
    from shared.tools.window import window_reason_of

    return window_reason_of(row)


def l1_checks(rows: list[dict[str, Any]], root: Path) -> list[list[Any]]:
    """``run_l1`` over ``rows`` — the stage that turns the stamps into checks."""
    from shared.validate.context_heuristics import run_l1

    return run_l1(rows, source_root=str(root))


def anchor_of(checks: list[Any]) -> Any:
    """The `anchor` check in one row's check list, or None."""
    return next((check for check in checks if check.id == "anchor"), None)


def anchor_extras(checks: list[Any]) -> dict[str, Any]:
    """The anchor check's extras; {} when the row carries no anchor check."""
    check = anchor_of(checks)
    return dict(getattr(check, "extras", None) or {})


def status_of(checks: list[Any]) -> str:
    """The anchor status (the check's ``result``), "" when there is none."""
    return str(getattr(anchor_of(checks), "result", "") or "")
