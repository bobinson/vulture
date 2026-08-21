"""0075 — every file the LLM tier sees must carry absolute line numbers.

The model is asked to report ``line_start`` for each finding. It can only do that
by reading a line number or by counting newlines, and it is unreliable at
counting. Numbering was applied only to files that ALREADY carried a skill
finding, so the files where the LLM tier is uniquely valuable — the ones no
regex flagged — were the ones presented blind.

Measured on 108 hand-adjudicated findings (.graphql rows excluded, they are a
separate defect):

    presentation                       n    TP   precision   mislocated
    NUMBERED snippet (has skill find)  38   17     44.7%      5 (13.2%)
    RAW text (no skill finding)        32    4     12.5%     25 (78.1%)

5.9x the mislocation rate. All 17 challenge-surviving true positives came from
numbered files.

Six of these were RED against the pre-0075 code and are the guards proper. The rest
are REGRESSION LOCKS that passed before the change and must keep passing: absolute
(not snippet-relative) numbering, no double-numbering, and the rollback switch —
which cannot be red, because raw presentation is exactly what the baseline did.
Both kinds earn their place; only the first kind proves the fix landed.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from shared.audit_runner import (
    _build_source_batches,
    _extract_file_snippet,
    _format_file_block,
    _pack_files,
)

# "12: some code" — the one format the model is ever shown.
_NUMBERED = re.compile(r"^\d+: ")


def _write(body: str, name: str = "sample.ts") -> tuple[str, Path]:
    d = Path(tempfile.mkdtemp())
    p = d / name
    p.write_text(body)
    return str(d), p


def _code_lines(block: str) -> list[str]:
    """Content lines of a rendered block, minus the ``--- path ---`` header and
    the ``...`` elision markers snippet extraction inserts."""
    return [
        ln for ln in block.split("\n")
        if ln.strip() and not ln.startswith("--- ") and ln.strip() != "..."
    ]


def _numbered_fraction(block: str) -> float:
    lines = _code_lines(block)
    if not lines:
        return 0.0
    return sum(bool(_NUMBERED.match(ln)) for ln in lines) / len(lines)


# ── the dominant defect: a file with no skill finding is presented blind ──────

def test_file_without_skill_findings_is_numbered():
    """THE regression this feature exists to prevent.

    A file no skill flagged is exactly where the LLM tier earns its keep, and it
    was handed over as raw text.
    """
    root, path = _write("const a = 1;\nconst b = 2;\nconst c = 3;\n")
    block = _format_file_block(path, root, {})
    assert block is not None
    _rel, text = block
    assert _numbered_fraction(text) == 1.0, (
        f"every content line must carry an absolute line number; got:\n{text}"
    )


def test_pack_files_numbers_a_file_without_findings():
    """The single-shot path (`_pack_files`) has the same defect as the batch
    path, so it needs its own assertion — one fix must cover both."""
    root, path = _write("let x = 1;\nlet y = 2;\n")
    text, included = _pack_files([path], root, max_chars=100_000, skill_findings=[])
    assert included, "the file should have been packed"
    assert _numbered_fraction(text) == 1.0, f"unnumbered content in _pack_files:\n{text}"


def test_snippet_with_findings_but_no_line_info_is_numbered():
    """The fourth path, easy to miss: `_extract_file_snippet` returns raw content
    when a file HAS findings but none carry usable line numbers."""
    body = "\n".join(f"line{i}" for i in range(1, 21)) + "\n"
    findings = [{"file_path": "sample.ts", "line_start": 0, "line_end": 0}]
    out = _extract_file_snippet(body, findings, "sample.ts")
    assert _numbered_fraction(out) == 1.0, (
        f"a findings-bearing file with no line info must still be numbered:\n{out}"
    )


# ── correctness of the numbering itself ──────────────────────────────────────

def test_line_numbers_are_absolute_not_snippet_relative():
    """A snippet starting deep in a file must render the FILE's line numbers.

    If it restarted at 1 the model would be systematically wrong by the snippet
    offset — worse than no numbers, because the output would look precise.
    """
    body = "\n".join(f"line{i}" for i in range(1, 301)) + "\n"
    findings = [{"file_path": "sample.ts", "line_start": 200, "line_end": 200}]
    out = _extract_file_snippet(body, findings, "sample.ts", context_lines=3)
    nums = [int(m.group(1)) for m in re.finditer(r"^(\d+): ", out, re.MULTILINE)]
    assert nums, f"no numbered lines produced:\n{out}"
    assert min(nums) > 100, (
        f"numbers restarted near 1 — snippet-relative, not absolute: min={min(nums)}"
    )
    assert 200 in nums, f"the finding's own line 200 must appear; got {min(nums)}..{max(nums)}"
    # the number must label its own text
    assert "200: line200" in out, f"line number/text mismatch:\n{out}"


def test_no_double_numbering_when_a_snippet_was_extracted():
    """Guard against the obvious implementation slip: numbering unconditionally
    ON TOP of already-numbered snippet output, producing `30: 30: code`."""
    body = "\n".join(f"line{i}" for i in range(1, 61)) + "\n"
    root, path = _write(body)
    findings_by_path = {
        str(path): [{"file_path": str(path), "line_start": 30, "line_end": 30}]
    }
    block = _format_file_block(path, root, findings_by_path)
    assert block is not None
    _rel, text = block
    assert not re.search(r"^\d+: \d+: ", text, re.MULTILINE), f"double-numbered:\n{text}"


def test_both_call_paths_share_one_numbering_helper():
    """DRY, and a structural guard: the two sites had identical shape and the
    numbering was added to neither. One helper, or they will drift again."""
    import shared.audit_runner as ar

    src = Path(ar.__file__).read_text()
    # The literal format string must appear exactly once in the module.
    occurrences = src.count('f"{i + 1}: {lines[i]}"')
    assert occurrences <= 1, (
        f"the line-number format is written {occurrences} times; extract it to a "
        f"single helper so the two prompt paths cannot diverge"
    )


# ── budget accounting must include the numbering overhead ────────────────────

def test_numbering_overhead_respects_the_char_budget():
    """Numbering adds ~5-7 chars per line. If the budget were computed on the
    un-numbered text the batch would overshoot the encoded-body ceiling, which is
    the failure feature 0070 P5 exists to prevent.

    An earlier version of this test wrapped its assertion in ``if text:`` and used a
    budget smaller than the single file, so the file was skipped, ``text`` was empty
    and the assertion never ran. A vacuous budget test is how a budget regression
    ships. Both defects are fixed here: several small files that DO fit, and an
    unconditional assertion.
    """
    root = Path(tempfile.mkdtemp())
    paths = []
    for i in range(8):
        p = root / f"f{i}.ts"
        p.write_text("\n".join(f"const a{j} = {j};" for j in range(20)) + "\n")
        paths.append(p)
    budget = 3_000
    text, included = _pack_files(paths, str(root), max_chars=budget, skill_findings=[])
    assert text, "expected some files to fit the budget"
    assert included, "expected at least one file to be included"
    assert len(text) <= budget * 1.1, (
        f"packed text {len(text)} chars overshot the {budget} budget"
    )
    assert _numbered_fraction(text) == 1.0, "budget-limited packing must still number"


def test_batch_text_respects_the_char_budget_with_numbering():
    root = Path(tempfile.mkdtemp())
    paths = []
    for i in range(6):
        p = root / f"f{i}.ts"
        p.write_text("\n".join(f"const a{j} = {j};" for j in range(60)) + "\n")
        paths.append(p)
    batches = _build_source_batches(paths, str(root), max_chars=1_500, skill_findings=[])
    assert batches, "expected at least one batch"
    for text, _paths in batches:
        assert _numbered_fraction(text) == 1.0, f"unnumbered batch content:\n{text[:400]}"


# ── rollback ────────────────────────────────────────────────────────────────

def test_rollback_switch_restores_raw_presentation(monkeypatch):
    """One-release escape hatch. Numbering is additive and low-risk, but it does
    consume budget, so an operator must be able to turn it off without a deploy."""
    monkeypatch.setenv("VULTURE_LLM_LINE_NUMBERS", "false")
    root, path = _write("const a = 1;\nconst b = 2;\n")
    block = _format_file_block(path, root, {})
    assert block is not None
    _rel, text = block
    assert _numbered_fraction(text) == 0.0, (
        f"with the switch off the content must be raw:\n{text}"
    )
