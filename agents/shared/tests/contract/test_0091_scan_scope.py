"""Feature 0091 §6.5 / D2 — the Python half of the cross-language SCOPE pin.

WHY THIS FILE EXISTS ALONGSIDE ``tests/unit/test_0091_editor_config_scope.py``.
That test pins the same interaction against a TRANSCRIPTION of the Go predicate
(a ``_contains`` helper written in Python). A transcription is a second opinion:
it can be right about a rule Go no longer implements, or drift when Go's changes
and nobody edits the copy. It is exactly the shape of the defect that shipped in
P1, where a Pydantic model silently dropped a field the Go side was sending and
both suites stayed green.

So this test asserts the shipped walker against the SAME checked-in file the Go
suite asserts ``scanScope`` against:

    agents/shared/tests/contract/0091_scan_scope.json
    backend/internal/service/scan_scope_contract_test.go

Python owns "what the walker read and what it reported as pruned". Go owns "what
that report means for a lineage row". Renaming, widening or coarsening either
half fails the other side's assertion against this file, and editing the file to
silence one side moves the failure to the other — which is the point.

The case carries its own control. The walker ENTERS ``.vscode``/``.idea`` for
the allowlisted autorun files and must report the prune at CHILD granularity,
because a bare ``.vscode`` in ``pruned_dirs`` would put the file it just read
out of scope — and an out-of-scope row returns before the tier rules, so it
could never close. ``node_modules`` sits in the same tree with nothing
allowlisted inside it, is never entered, and is reported as the CONTAINER. Those
two shapes side by side are what prove child-granularity reporting happens
because the walker entered, not because containers stopped being reported.

That control used to be a second case toggled by ``VULTURE_SCAN_EDITOR_CONFIG``.
The 0091 flag retirement removed the switch — the allowlist is unconditional now
— so the off-case described behaviour the walker no longer has. It was deleted
rather than "fixed" to match, which would only have duplicated the on-case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shared.tools.file_scanner import clear_caches, pruned_dirs, scan_code_files

CONTRACT = Path(__file__).with_name("0091_scan_scope.json")


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _contract() -> dict[str, Any]:
    """The shared file. A hard failure when it is missing: a pin that quietly
    stops running is worse than no pin, because the report still says green."""
    assert CONTRACT.is_file(), (
        f"the shared 0091 scope contract is missing at {CONTRACT}. It is the "
        "cross-language pin between this walker and the Go backend's scanScope; "
        "if it moved, update BOTH suites that read it."
    )
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def _build_tree(root: Path, files: list[str]) -> None:
    """Materialise exactly the tree the contract describes — no more, so the
    walker cannot be measured against a fixture the Go side never saw."""
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")


def _rels(root: Path, paths: list[Path]) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in paths)


@pytest.mark.parametrize("case", _contract()["cases"], ids=lambda c: c["name"])
def test_walker_reproduces_the_scope_contract(
    case: dict[str, Any], tmp_path: Path
) -> None:
    root = tmp_path / "tree"
    _build_tree(root, _contract()["tree"]["files"])

    scanned = _rels(root, scan_code_files(str(root)))
    reported = sorted(pruned_dirs(str(root)))

    assert scanned == sorted(case["scanned"]), (
        f"[{case['name']}] the set of files this walker READS has changed. The Go "
        "scope pin derives 'must be in scope' from this list, so a file added here "
        "without a matching pruned_dirs change silently becomes a lineage row that "
        "can never close, and one removed becomes a row that closes unread."
    )
    assert reported == sorted(case["pruned_dirs"]), (
        f"[{case['name']}] pruned_dirs has changed. This value is consumed ONLY by "
        "the Go backend's scanScope, which prefix-matches lineage file paths "
        "against it: a coarser entry (a bare '.vscode') freezes every row beneath "
        "it forever, a missing entry lets a scan close a finding it never read. "
        f"Got {reported}, contract says {sorted(case['pruned_dirs'])}."
    )


def test_no_scanned_file_is_covered_by_a_reported_prune() -> None:
    """The invariant behind both cases, checked on the contract itself.

    Stated here as well as in Go because it is the property, not an artefact of
    either implementation: a path the walker read must not be reachable from any
    prefix it reported. The prefix rule is Go's (`rel == p or rel.startswith(p +
    "/")`), and it is restated in ONE place — here — rather than in the test
    that also asserts the walker's output, so the two are not the same claim.
    """
    for case in _contract()["cases"]:
        pruned = case["pruned_dirs"]
        for rel in case["scanned"]:
            covered = [p for p in pruned if rel == p or rel.startswith(p + "/")]
            assert not covered, (
                f"[{case['name']}] {rel!r} was scanned but is covered by pruned "
                f"prefix(es) {covered}; the backend would record every lineage row "
                "there out_of_scope and never close one."
            )
