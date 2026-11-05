"""Blast radius reads the code it reports on, not prose about it.

Business contract
-----------------
A self-scan reported ``chaos.blast_radius.missing_isolation`` on a ``#`` comment
holding the English words "global that": the shared-state trigger matched the
word ``global`` anywhere, in any case, in comments, docstrings and string
literals alike.

* The ``global`` trigger is the STATEMENT (Python ``global x``, PHP
  ``global $x``): the keyword written first on its line, case-sensitive, outside
  comments, docstrings and string literals. Prose that uses the word is not a
  declaration of shared state, and a statement after such prose is reported at
  the statement's own line.
* The isolation evidence that EXCUSES a finding (``namespace``, ``partition``,
  ``semaphore``...) counts only in code. A comment or docstring mentioning
  "namespace" no longer hides a real ``global`` statement; a semaphore built in
  code still does.
* Every other trigger is unchanged: a singleton whose only signal is its doc
  comment is still reported.

Fixture layout (``fixtures/rule_precision``): one unit per directory under
``pos/`` (reported) or ``neg/`` (clean), each scanned on its own from a copy
outside any test path, since the rule skips test files.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from chaos_agent.skills.blast_radius import assess_blast_radius
from shared.tools.file_scanner import clear_caches, is_test_file, scan_code_files

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rule_precision"
CHECK = "chaos.blast_radius.missing_isolation"

# pos unit -> (file, text on the line the finding must anchor at)
REPORTED = {
    "blast_global_statement": ("cache.py", "global _CACHE"),
    "blast_global_statement_after_prose": ("counter.py", "global _COUNT"),
    "blast_global_statement_php": ("db.php", "global $db;"),
    "blast_isolation_word_in_comment": ("registry.py", "global _HANDLERS"),
    "blast_singleton_doc_comment": ("pool.ts", "/** Singleton"),
}
CLEAN = (
    "blast_global_comment_prose",
    "blast_global_docstring_prose",
    "blast_global_string_literal",
    "blast_isolation_in_code",
)


def _neutral_copy(src: Path, tmp_path: Path) -> Path:
    """Copy ``src`` where no file is classified as a test, so a scan is not vacuous."""
    root = tmp_path / "fixcorpus" / "app"
    shutil.copytree(src, root)
    files = [p for p in root.rglob("*") if p.is_file()]
    assert files and not any(map(is_test_file, files)), f"copy at {root} is not neutral"
    return root


def _scan(kind: str, unit: str, tmp_path: Path) -> tuple[Path, list[dict]]:
    root = _neutral_copy(FIXTURES / kind / unit, tmp_path)
    clear_caches()
    # Population floor: a file the scanner never enumerates would pass "clean".
    files = {p for p in root.rglob("*") if p.is_file()}
    assert files <= set(map(Path, scan_code_files(str(root)))), "fixture file not scanned"
    findings = assess_blast_radius(str(root))["findings"]
    return root, [f for f in findings if f["check_id"] == CHECK]


def _line_of(path: Path, text: str) -> int:
    lines = path.read_text().splitlines()
    hits = [n for n, line in enumerate(lines, start=1) if text in line]
    assert len(hits) == 1, f"anchor text {text!r} must occur once in {path.name}"
    return hits[0]


def test_every_unit_is_listed() -> None:
    """A fixture unit without an expectation would never be asserted."""
    on_disk = {p.name for kind in ("pos", "neg") for p in (FIXTURES / kind).iterdir()}
    assert on_disk == set(REPORTED) | set(CLEAN)


@pytest.mark.parametrize("unit", sorted(REPORTED))
def test_shared_state_is_reported_at_its_line(unit: str, tmp_path: Path) -> None:
    root, findings = _scan("pos", unit, tmp_path)
    name, anchor = REPORTED[unit]
    assert len(findings) == 1, findings
    finding = findings[0]
    assert Path(finding["file_path"]).name == name
    assert finding["line_start"] == _line_of(root / name, anchor)
    assert finding["severity"] == "medium"


@pytest.mark.parametrize("unit", CLEAN)
def test_prose_or_code_isolation_is_not_reported(unit: str, tmp_path: Path) -> None:
    _, findings = _scan("neg", unit, tmp_path)
    assert findings == []
