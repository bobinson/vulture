"""Feature 0101 (RED R209-R2-2) -- the CWE-209 resolver keeps no file alive after it moves on.

The per-sink resolution memo was module-global, capped at 4096 ENTRIES, and
each entry held a reference to the whole file's line list. RED scanned 1500
synthetic ~200 KB files with one sink each: max RSS grew 394 MB (HEAD: 0), and
afterwards the memo still held all 1500 files. In the long-lived agent process
that retention survives across audits; at 4096 files of 512 KB it is ~2 GB.

The contract: whatever the resolver caches per file, it holds at most a small,
fixed number of files (the per-file binding index already holds 8), measured
here by weak references to the line lists themselves -- a count of entries in
any one cache would miss a cache this test does not know about.
"""
from __future__ import annotations

import gc
import weakref
from pathlib import Path

from cwe_agent.skills import info_exposure_check as iec

FILES = 64
MAX_FILES_HELD = 8


class _Lines(list):
    """A list that can be weakly referenced (a plain list cannot)."""


def _file(k: int) -> _Lines:
    body = [f"// filler line {k} {i} " + "x" * 60 for i in range(200)]
    return _Lines([*body, f"  const value{k} = load{k}(req.query.id);", f"  res.json({{ a: value{k} }})"])


def _scan_one(k: int) -> weakref.ref:
    lines = _file(k)
    findings: list[dict] = []
    for n in range(len(lines) - 2, len(lines) + 1):
        iec._check_error_disclosure(Path(f"app/f{k}.ts"), lines[n - 1], n, lines, findings)
    return weakref.ref(lines)


def test_files_scanned_earlier_are_released() -> None:
    refs = [_scan_one(k) for k in range(FILES)]
    gc.collect()
    alive = sum(r() is not None for r in refs)
    assert alive <= MAX_FILES_HELD, f"{alive} of {FILES} scanned files are still held by the resolver"


def test_the_first_files_scanned_are_released() -> None:
    """Not only bounded: the OLDEST files go first, so a long run cannot pin early ones."""
    refs = [_scan_one(1000 + k) for k in range(FILES)]
    gc.collect()
    assert all(r() is None for r in refs[: FILES - MAX_FILES_HELD])


def test_a_sink_still_resolves_after_many_files() -> None:
    """Releasing files must not cost correctness: a later file's caught error still reports."""
    for k in range(FILES):
        _scan_one(2000 + k)
    lines = _Lines(["try {", "  run();", "} catch (fault) {", "  res.json({ m: fault.message });", "}"])
    findings: list[dict] = []
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(Path("app/late.ts"), line, n, lines, findings)
    assert [f["line_start"] for f in findings if f["category"] == "CWE-209"] == [4]
