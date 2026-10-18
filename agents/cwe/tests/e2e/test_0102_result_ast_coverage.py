"""Feature 0102 (D13, LLD 10.2/10.3): the ``result`` event reports AST coverage.

Business contract: an audit tells its consumer which files the AST tier owned
and which fell back to the regex tier, and why. A two-file tree drives the real
runner with the real cwe ``input_validation`` skill, skills-only:

* ``ok.js``  -- a clean parse (the corpus fixture ``cwe_22_1.js``);
* ``bad.js`` -- a trailing syntax error (``cwe_22_17.js``), so the regex tier
  owns it and the file is counted, by name, as a ``parse_error`` fallback.

Every fallback bucket is present even at zero (``worker_error`` and
``spawn_failed`` included), so "no fallback of this kind" is a stated number,
not a missing key. With ``ok.js`` swapped for its clean twin
(``cwe_22_1_clean.js``, the path passes through a basename sanitiser) the
engine declines the flow, and the decline is visible as one ``ast_decline``
line on the ``thinking`` stream.

The fixtures are read from the cwe corpus group ``ast_v1``: one copy of each
shape, shared by the corpus gate and this test.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills import SKILL_MAP
from shared.audit_runner import run_combined_audit
from shared.testing.isolation import isolate
from tests import _ast_v1

# Plan task 0.5, verbatim, plus the D24 guard's `fallback_keys` that LLD 10.2
# puts beside them in `files`. Compared key by key over THESE keys.
# `breaker_tripped` is pinned by its own identity check below: `==` here would
# also accept a 0.
_EXPECTED_FILES: dict[str, Any] = {
    "parsed": 1,
    "fallback": {
        "unsupported": 0, "parse_error": 1, "too_large": 0, "too_deep": 0,
        "worker_crashed": 0, "worker_error": 0, "timeout": 0, "ir_too_large": 0,
        "bad_model": 0, "spawn_failed": 0, "circuit_open": 0,
    },
    "fallback_paths": ["bad.js"],
    "fallback_paths_truncated": False,
    "fallback_keys": ["bad.js"],
}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Documented defaults: a developer's VULTURE_* env cannot move the counts."""
    isolate(monkeypatch, tmp_path)


def _audit(tmp_path: Path, ok_fixture: str) -> list[str]:
    """Build the two-file tree and run the cwe ``input_validation`` skill over it."""
    import shared.ast  # noqa: F401 - the layer whose coverage this reports

    root = tmp_path / "src"
    root.mkdir()
    shutil.copyfile(_ast_v1.AST_V1 / ok_fixture, root / "ok.js")
    shutil.copyfile(_ast_v1.AST_V1 / "cwe_22_17.js", root / "bad.js")
    return list(run_combined_audit(
        run_id="0102-coverage", source_path=str(root), categories=["input_validation"],
        skill_map={"input_validation": SKILL_MAP["input_validation"]}, use_llm=False,
    ))


def _payloads(events: list[str], name: str) -> list[dict[str, Any]]:
    """The JSON of every ``name`` event, in stream order (``event: <name>\ndata: <json>``)."""
    head = f"event: {name}\ndata: "
    return [json.loads(e.removeprefix(head)) for e in events if e.startswith(head)]


def test_result_reports_parsed_and_fallback_files(tmp_path: Path) -> None:
    """One parsed file, one ``parse_error`` fallback named by its root-relative path."""
    results = _payloads(_audit(tmp_path, "cwe_22_1.js"), "result")
    assert len(results) == 1, f"expected exactly one result event, got {len(results)}"
    coverage = results[0].get("ast_coverage")

    assert coverage is not None, "the result event carries no ast_coverage"
    files = coverage["files"]
    assert {key: files.get(key) for key in _EXPECTED_FILES} == _EXPECTED_FILES
    assert files["breaker_tripped"] is False, files


def test_decline_is_streamed_as_one_thinking_line(tmp_path: Path) -> None:
    """The clean twin's sanitised flow is declined, and the decline is visible."""
    declines = [
        p["content"] for p in _payloads(_audit(tmp_path, "cwe_22_1_clean.js"), "thinking")
        if p["content"].startswith("ast_decline ")
    ]

    assert len(declines) == 1, declines
