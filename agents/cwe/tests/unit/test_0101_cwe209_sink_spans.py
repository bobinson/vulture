"""Feature 0101 (RED R209-I2) -- bounding per-line sink work keeps every verdict.

The fix for the many-sinks-per-line cost gives each sink only its OWN argument
span (cut at the next sink) and, past a small per-line count, judges the rest of
the line's sinks together. These cases pin that the bound costs no recall: a
leak in a later sink, in a sink past the count, or after a literal that merely
spells a sink is still reported, and a line of clean writes stays clean.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure


def _rows(tmp_path: Path, body: str) -> list[int]:
    src = tmp_path / "src" / "handler.ts"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("export function h(req, res) {\n  try { run() } catch (err) {\n" + body + "\n  }\n}\n")
    found = check_information_exposure(str(tmp_path))["findings"]
    return [f["line_start"] for f in found if f["category"] == "CWE-209"]


def _writes(n: int, last: str) -> str:
    return "    " + " ".join(f"res.write(part{k});" for k in range(n - 1)) + f" res.end({last});"


@pytest.mark.parametrize("body", [
    "    res.write(header); res.end(err.message);",
    "    res.write(header); res.end(JSON.stringify({ detail: err.stack }));",
    _writes(6, "err.message"),
    _writes(12, "String(err)"),
    '    res.send("a.json(b)" + err.message);',
    '    res.send(`see .end( ${err.message}`);',
    "    res.write(a); res.write(b); res.write(c); res.write(d); res.json({ e: err.message,",
], ids=["second", "second_wrapped", "sixth", "twelfth", "literal_spells_sink",
        "template_spells_sink", "past_cap_continues"])
def test_leak_in_any_sink_is_reported(tmp_path: Path, body: str) -> None:
    if body.endswith(","):
        body += "\n      ok: false })"
    assert _rows(tmp_path, body) == [3]


@pytest.mark.parametrize("body", [
    "    res.status(500).json({\n      code: 7,\n      detail: err.message, sent: res.headersSent })",
    "    res.status(500).json({\n      detail: err.message, also: res.send(1) })",
], ids=["continuation_far_key", "continuation_line_holds_a_sink"])
def test_continuation_still_reads_the_open_call(tmp_path: Path, body: str) -> None:
    assert _rows(tmp_path, body) == [3]


def test_continuation_stops_at_the_next_lines_sink(tmp_path: Path) -> None:
    """The open call on line 3 does not borrow line 4's argument: line 4 owns it."""
    assert _rows(tmp_path, "    res.write(chunk,\n    res.end(err.message))") == [4]


@pytest.mark.parametrize("body", [
    "    res.write(header); res.end(err.code);",
    _writes(6, "part9"),
    _writes(12, "err.status"),
], ids=["second_code", "sixth_clean", "twelfth_projection"])
def test_clean_writes_stay_clean(tmp_path: Path, body: str) -> None:
    assert _rows(tmp_path, body) == []
