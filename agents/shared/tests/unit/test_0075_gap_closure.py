"""0075 gap closure — the tasks the first implementation pass left open.

Two of these are defects the plan's adversarial review predicted and that were
then verified failing against the shipped code:

  * T1.10 — a file ending in a newline rendered a PHANTOM final numbered line
    (``'a=1;\\nb=2;\\n'`` became ``'1: a=1;\\n2: b=2;\\n3: '``). Introduced by
    ``_present_source``: ``str.split("\\n")`` yields a trailing empty element.
    It appeared in EVERY numbered file, inviting the model to cite a line that
    does not exist. ``_numbered_fraction`` cannot see it — ``"3: ".strip()`` is
    truthy and matches ``^\\d+: `` — so it needs a direct assertion.

  * T3.2b — widening the snippet window REMOVED lines. At ``context_lines=10`` a
    finding on line 26 rendered 16-36; at 25 it rendered 1-30, losing 31-36.
    Cause: a wider window drives the range start to 0, which trips the
    ``all_near_top`` branch and truncates to the first 30 lines. Pre-existing,
    and it makes the width knob actively unsafe.

The rest close T1.7b (the only test that guards AC6), T1.9, T1.10b, T1.12c and
the P3 switches.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from shared.audit_runner import (
    _extract_file_snippet,
    _format_file_block,
    _pack_files,
)

_NUMBERED = re.compile(r"^\d+: ")


def _tree(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp())
    for name, body in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def _rendered_lines(block: str) -> list[str]:
    return [ln for ln in block.split("\n") if not ln.startswith("--- ")]


def _labels(text: str) -> list[int]:
    return [int(m.group(1)) for m in re.finditer(r"^(\d+): ", text, re.MULTILINE)]


# ── T1.10 / T1.10b — the newline boundary ───────────────────────────────────

def test_trailing_newline_produces_no_phantom_line():
    """A file ending in ``\\n`` must not render a final empty numbered line.

    Asserted directly, because `_numbered_fraction` reports 1.0 for the phantom.
    """
    root = _tree({"t.ts": "a=1;\nb=2;\n"})
    _rel, text = _format_file_block(root / "t.ts", str(root), {})
    phantom = [ln for ln in text.split("\n") if re.fullmatch(r"\d+: ?", ln)]
    assert not phantom, f"phantom numbered line(s) {phantom} in:\n{text!r}"
    assert _labels(text) == [1, 2], f"expected labels [1, 2], got {_labels(text)}"


def test_no_trailing_newline_keeps_the_last_line():
    """Negative control for the mirrored hazard: a naive ``lines[:-1]`` would
    delete real source — and any defect sitting on the final line with it."""
    root = _tree({"u.ts": "x=1;\ny=2;"})
    _rel, text = _format_file_block(root / "u.ts", str(root), {})
    assert "2: y=2;" in text, f"final line dropped:\n{text!r}"
    assert _labels(text) == [1, 2]


def test_empty_and_whitespace_files_do_not_crash():
    """Boundary cases around the same split."""
    root = _tree({"blank.ts": "\n", "spaces.ts": "   \n"})
    for name in ("blank.ts", "spaces.ts"):
        block = _format_file_block(root / name, str(root), {})
        if block is not None:
            _rel, text = block
            assert not [ln for ln in text.split("\n") if re.fullmatch(r"\d+: ?", ln)], (
                f"{name} rendered a phantom line: {text!r}"
            )


# ── T3.2b / T3.6 — widening the window must never remove a line ─────────────

def test_widening_the_window_is_monotonic():
    """The blocking defect: a wider context must be a SUPERSET, never a
    different slice. Generalised over finding positions and widths."""
    body = "\n".join(f"line{i}" for i in range(1, 101)) + "\n"
    for pos in (1, 5, 11, 26, 50, 99):
        findings = [{"file_path": "m.ts", "line_start": pos, "line_end": pos}]
        prev: set[int] | None = None
        for width in (3, 10, 25, 40):
            out = _extract_file_snippet(body, findings, "m.ts", context_lines=width)
            cur = set(_labels(out))
            assert pos in cur, f"finding line {pos} missing at context={width}"
            if prev is not None:
                lost = prev - cur
                assert not lost, (
                    f"widening to {width} at finding line {pos} LOST lines "
                    f"{sorted(lost)} — the window is not monotonic"
                )
            prev = cur


def test_default_context_is_byte_identical_to_pre_0075():
    """The width knob must ship inert: the default must not change today's
    output for a line-bearing finding."""
    body = "\n".join(f"line{i}" for i in range(1, 61)) + "\n"
    findings = [{"file_path": "m.ts", "line_start": 30, "line_end": 30}]
    explicit = _extract_file_snippet(body, findings, "m.ts", context_lines=10)
    default = _extract_file_snippet(body, findings, "m.ts")
    assert explicit == default, "the resolved default must equal an explicit 10"


# ── T1.7b — the only test that guards AC6 ──────────────────────────────────

def test_numbering_shortfall_is_bounded_and_reported(caplog):
    """Numbering consumes budget, so FEWER files fit. That is a real coverage
    cost; it must stay inside the budget and must not be silent."""
    files = {f"f{i}.ts": "\n".join(f"const a{j} = {j};" for j in range(12)) + "\n"
             for i in range(12)}
    root = _tree(files)
    paths = sorted(root.glob("*.ts"))
    budget = 1_400
    with caplog.at_level("WARNING"):
        text, included = _pack_files(paths, str(root), max_chars=budget, skill_findings=[])
    assert text, "expected some files to fit"
    assert len(text) <= budget * 1.1, f"{len(text)} chars overshot budget {budget}"
    assert len(included) < len(paths), (
        "the budget should have excluded some files, or this test proves nothing"
    )
    assert any("llm_pack_dropped" in r.message or "llm_pack_dropped" in r.getMessage()
               for r in caplog.records), (
        "a coverage shortfall must be logged (llm_pack_dropped), never silent"
    )


# ── T1.9 — the rollback switch must not disable pre-0075 behaviour ──────────

def test_switch_off_still_numbers_a_line_bearing_snippet(monkeypatch):
    """`VULTURE_LLM_LINE_NUMBERS=false` restores the pre-0075 prompt exactly:
    raw whole files, but snippets STILL numbered — snippet numbering predates
    the switch, so turning it off must not take that with it."""
    monkeypatch.setenv("VULTURE_LLM_LINE_NUMBERS", "false")
    body = "\n".join(f"line{i}" for i in range(1, 61)) + "\n"
    root = _tree({"s.ts": body})
    fb = {str(root / "s.ts"): [{"file_path": str(root / "s.ts"),
                               "line_start": 30, "line_end": 30}]}
    _rel, text = _format_file_block(root / "s.ts", str(root), fb)
    assert _labels(text), f"snippet numbering must survive the switch:\n{text[:200]!r}"


# ── T1.12c — the duplication the format guard cannot see ───────────────────

def test_pack_files_delegates_and_does_not_duplicate_the_reader():
    """`test_both_call_paths_share_one_numbering_helper` only pins the format
    string; the two functions can still duplicate four branch structures around
    it. This asserts the delegation itself."""
    import inspect

    from shared import audit_runner as ar

    src = inspect.getsource(ar._pack_files)
    assert "_format_file_block(" in src, "_pack_files must delegate, not re-implement"
    assert "read_file_safe(" not in src, "one reader: _pack_files must not read files itself"
    assert "setdefault(" not in src, "one grouper: use the shared findings-by-path helper"
