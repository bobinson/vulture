"""0076 §5.0 / T0.1 / T0.7 — the line-number format is ONE leaf module.

The prompt's ``"30: code"`` prefix is the contract between what the model is shown
and what the model is asked to report. 0075 made the WRITE direction single-sourced
(``audit_runner._number_lines``); 0076 needs the READ direction too, because
``tools/file_reader.py`` must number what it hands the model and the verifier must
strip those numbers back off before comparing quoted evidence to the file.

**Why a new module and not a second function in ``audit_runner``.** The plan's own
first draft put ``strip_line_number`` beside ``_number_lines`` in ``audit_runner.py``
and had ``tools/file_reader.py`` import it. That breaks every agent, and it was
reproduced rather than theorised (§5.0, D16)::

    python -c "import shared.tools.file_reader"   ->  OK
    python -c "import shared.audit_runner"        ->  ImportError: cannot import name
      '_number_lines' from partially initialized module 'shared.audit_runner'

``audit_runner`` never names ``file_reader``; ``shared/tools/__init__.py:6`` does, and
that re-export closes the cycle ``audit_runner -> shared.tools.* -> __init__ ->
file_reader -> audit_runner``. **The direction of the failure is the trap**: importing
the tool ALONE succeeds, so a unit test that imports one order passes while every
agent fails at startup. Every import guard here therefore runs BOTH orders, in
separate subprocesses (T0.7).

The fix is a leaf: ``shared/tools/line_format.py`` importing nothing from ``shared.*``,
so both sides can depend on it. AC32 asserts that by parsing the module's own AST —
a convention nobody can grep for is a convention that comes back.

What each group of tests is worth:

  * the byte-identity goldens are **frozen from the shipping implementation**
    (``audit_runner._number_lines:740``, ``f"{i + 1}: {lines[i]}"``) before the move.
    They are not derived from the new module, so "moved verbatim" is checkable rather
    than tautological — and they also pin ``audit_runner._number_lines``, which stays
    as an alias so no 0075 caller or structural guard changes.
  * the inverse tests pin the property that makes ``strip_line_number`` safe to apply
    unconditionally: it is IDENTITY on a line carrying no prefix.
  * AC19 is asserted **scoped to the detector feed path**, with the two excluded sites
    named in ``_AC19_EXCLUSIONS``. An unscoped "the literal appears once in the tree"
    is unachievable — ``validate/judge_tools.py:213`` renders the L5 judge's own tool
    output and belongs to 0072 (§12), and ``tools/snippet.py`` has two sites refactored
    under a recorded fallback. A test that asserts an unachievable global is a test
    that gets edited, and these tests may not be edited.

RED status: every test that names ``shared.tools.line_format`` is RED today (no such
module). The two both-order import probes are RED for the same reason and stay useful
afterwards as the regression lock for the cycle — they are the only tests here that
would still fail if someone later moves the pair back into ``audit_runner``.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

# ── locations ────────────────────────────────────────────────────────────────

# .../agents/shared — the directory that CONTAINS the `shared` package, i.e. the
# entry that has to be on sys.path for `import shared.*` to resolve.
_SHARED_ROOT = Path(__file__).resolve().parents[2]
_PKG = _SHARED_ROOT / "shared"
_LINE_FORMAT = _PKG / "tools" / "line_format.py"

# The DETECTOR FEED PATH: the modules that render source into the LLM prompt or read
# a rendered line back. AC19 is scoped to exactly these; see _AC19_EXCLUSIONS.
_FEED_PATH_FILES = (
    "shared/tools/line_format.py",   # the new leaf: owns both directions
    "shared/audit_runner.py",        # _number_lines alias + _redact_snippet:1418
    "shared/tools/file_reader.py",   # numbers what the model reads (T2.5)
    "shared/diag/feed_probe.py",     # the probe that measures the numbered fraction
)

# Named, not silently absorbed. Each of these renders a numbered line and is
# deliberately NOT rewritten by 0076.
_AC19_EXCLUSIONS = {
    "shared/validate/judge_tools.py": (
        "judge_tools.py:213 renders L5's OWN read_lines tool output; it belongs to "
        "0072's judge, not the detector feed. Rewriting it here would change judge "
        "behaviour as a side effect of a detector fix (§12 amendment)"
    ),
    "shared/tools/snippet.py": (
        "snippet.py's two render sites are refactored in T0.1 under a RECORDED "
        "FALLBACK: if their byte-identity test fails they stay, and AC19 names them "
        "as known duplicates. This test therefore asserts nothing about its contents"
    ),
}


# ── frozen goldens: recorded from the SHIPPING implementation, pre-move ───────
# Produced by audit_runner._number_lines (line 740) before T0.1 touched anything.
# `number_lines` must reproduce these byte for byte.

_GOLDEN: tuple[tuple[str, list[str], str], ...] = (
    ("empty", [], ""),
    ("one_line", ["x"], "1: x"),
    # A blank source line still gets its number and the separator, trailing space
    # included. Trimming it would change the byte output of most real files.
    ("blank_line", [""], "1: "),
    # The phantom line _split_content_lines exists to prevent. number_lines itself
    # does NOT filter it — the split is the caller's job, and moving that
    # responsibility here would silently change every existing call site.
    ("trailing_empty_element", ["a", "b", ""], "1: a\n2: b\n3: "),
    # Numbering is unconditional: a line that already looks numbered is numbered
    # again. This is why strip_line_number cannot be identity on such a line.
    ("line_that_looks_numbered", ["12: already numbered"], "1: 12: already numbered"),
    ("leading_whitespace", ["    code"], "1:     code"),
    # Why NUMBER_RE carries re.DOTALL — see test_strip_line_number_is_the_inverse.
    ("embedded_newline", ["a\nb"], "1: a\nb"),
)

# Lines that must survive number_lines -> strip_line_number unchanged.
_ROUND_TRIP_LINES = (
    "",
    "x",
    "    indented",
    "\tif (x) {",
    "12: already numbered",
    "code # with: a colon",
    "a\nb",
)

# (line, must NUMBER_RE recognise it as a rendered prefix?)
_NUMBER_RE_CASES = (
    ("30: code", True),
    ("1: ", True),          # a presented blank line
    ("code", False),
    ("NOTE: text", False),  # a colon alone is not a line number
)

# Lines carrying no "<digits>:" prefix. strip_line_number must return these
# untouched, which is the property that lets callers apply it unconditionally.
_UNPREFIXED_LINES = (
    "",
    "code",
    "    indented code",
    "def f():  # note: colon",
    "NOTE: not a number",
    "-1: negative is not a line number",
    "3.14: pi is not a line number",
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse(rel_path: str) -> ast.Module:
    """AST of a repo-relative module. Structural guards read the AST, never the
    raw text: a docstring that MENTIONS ``^\\d+: `` is not a second regex."""
    return ast.parse((_SHARED_ROOT / rel_path).read_text(encoding="utf-8"))


def _starts_with_colon_space(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(": ")
    )


def _is_number_prefix_fstring(node: ast.JoinedStr) -> bool:
    """True for an f-string shaped ``f"{<expr>}: ..."`` — the write direction.

    That shape is what every current render site uses (``f"{i + 1}: {lines[i]}"``,
    ``f"{i}: {lines[i - 1][...]}"``). It does NOT match an f-string with leading
    prose, so ``f"marker on line {i + 1}: {m}"`` in context_heuristics is correctly
    ignored.
    """
    values = node.values
    if len(values) < 2:
        return False
    return isinstance(values[0], ast.FormattedValue) and _starts_with_colon_space(values[1])


def _is_re_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "re"
    )


def _first_str_const(node: ast.Call) -> str | None:
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    return value if isinstance(value, str) else None


def _is_line_number_pattern(pattern: str | None) -> bool:
    """A regex literal that matches a line-number prefix: it needs a digit class
    and the separator."""
    return bool(pattern) and "\\d" in pattern and ":" in pattern


def _write_sites(rel_path: str) -> list[int]:
    """Line numbers of every number-prefix RENDER in a module."""
    return [
        node.lineno
        for node in ast.walk(_parse(rel_path))
        if isinstance(node, ast.JoinedStr) and _is_number_prefix_fstring(node)
    ]


def _is_number_prefix_regex(node: ast.AST) -> bool:
    """True for an ``re.<fn>("...\\d...:...")`` call — the read direction."""
    if not isinstance(node, ast.Call) or not _is_re_call(node):
        return False
    return _is_line_number_pattern(_first_str_const(node))


def _read_sites(rel_path: str) -> list[int]:
    """Line numbers of every hand-rolled number-prefix REGEX in a module."""
    return [
        node.lineno
        for node in ast.walk(_parse(rel_path))
        if _is_number_prefix_regex(node)
    ]


def _sites_by_file(collect) -> dict[str, list[int]]:
    """{feed-path file: line numbers} for one direction. One walk per file."""
    return {rel: collect(rel) for rel in _FEED_PATH_FILES}


def _plain_imports(tree: ast.Module) -> list[str]:
    return [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]


def _from_imports(tree: ast.Module) -> list[str]:
    """``from X import y`` targets. Relative imports keep their leading dots,
    because ``from . import x`` inside ``shared.tools`` is a ``shared.*`` import
    wearing a disguise — and it is exactly the one that re-enters the package
    ``__init__`` and closes the cycle."""
    return [
        "." * n.level + (n.module or "")
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom)
    ]


def _shared_imports(tree: ast.Module) -> list[str]:
    """Every import this module takes from inside the ``shared`` package."""
    targets = _plain_imports(tree) + _from_imports(tree)
    return [name for name in targets if name.startswith(("shared", "."))]


def _assert_named_exclusion(rel: str, reason: str) -> None:
    """One AC19 exclusion is well formed: a real file, a stated reason, and NOT
    also claimed as part of the feed path the AC counts."""
    assert (_SHARED_ROOT / rel).exists(), f"named exclusion {rel} does not exist"
    assert reason.strip(), f"an exclusion without a stated reason is a loophole: {rel}"
    assert rel not in _FEED_PATH_FILES, (
        f"{rel} is excluded from AC19 and must not also be counted as part of the "
        f"detector feed path"
    )


_PROBE = (
    "import {first}\n"
    "import {second}\n"
    "import shared.tools.line_format as lf\n"
    "import shared.audit_runner as ar\n"
    "assert callable(lf.number_lines), 'number_lines missing'\n"
    "assert callable(lf.strip_line_number), 'strip_line_number missing'\n"
    "assert callable(ar._number_lines), '_number_lines alias missing'\n"
)


def _import_in_order(first: str, second: str) -> subprocess.CompletedProcess:
    """Import two modules in a FRESH interpreter, in the given order.

    A fresh process per order is the whole point: once either module is in
    ``sys.modules`` the cycle cannot reproduce, so two orders inside one pytest
    process would test one order twice.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_SHARED_ROOT), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    return subprocess.run(
        [sys.executable, "-c", _PROBE.format(first=first, second=second)],
        cwd=str(_SHARED_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


# ── T0.1: the move is byte-identical ─────────────────────────────────────────

@pytest.mark.parametrize(("name", "lines", "expected"), _GOLDEN, ids=[g[0] for g in _GOLDEN])
def test_number_lines_reproduces_the_recorded_bytes(name, lines, expected):
    """T0.1: the leaf's output is byte-identical to the pre-move implementation.

    The goldens were recorded from ``audit_runner._number_lines`` BEFORE the move,
    so this is a comparison against the shipped format rather than against whatever
    the new module happens to do. Any drift here changes what every model in the
    fleet is shown, and therefore what its ``line_start`` means.
    """
    from shared.tools.line_format import number_lines

    assert number_lines(lines) == expected, (
        f"number_lines({name}) must reproduce the pre-0076 bytes exactly; "
        f"the prompt format is a contract with the model, not an implementation detail"
    )


@pytest.mark.parametrize(("name", "lines", "expected"), _GOLDEN, ids=[g[0] for g in _GOLDEN])
def test_audit_runner_alias_reproduces_the_same_bytes(name, lines, expected):
    """``audit_runner._number_lines`` is kept as an alias (§5.0), so every 0075
    caller and every ``inspect.getsource`` structural guard keeps working. It must
    still emit the recorded bytes — an alias that drifts is a fork."""
    from shared.audit_runner import _number_lines

    assert _number_lines(lines) == expected, (
        f"audit_runner._number_lines({name}) changed output during the move to the "
        f"leaf; the alias must be the same function, not a reimplementation"
    )


def test_audit_runner_number_lines_is_the_leaf_function_itself():
    """Not a wrapper, not a copy: the same object. Two callables that merely agree
    today are the state 0075 already had to fix once."""
    import shared.audit_runner as ar
    from shared.tools import line_format

    assert ar._number_lines is line_format.number_lines, (
        "audit_runner._number_lines must be `= line_format.number_lines`; a wrapper "
        "or a second definition re-creates the drift 0075 removed"
    )


def test_number_lines_scales_without_padding_or_realignment():
    """300 lines: numbers are plain decimal, never zero-padded or right-aligned.

    Padding would look tidier and would silently change the byte output of every
    file over 9 lines — and the model's quoted evidence is compared against these
    bytes.
    """
    from shared.tools.line_format import number_lines

    rendered = number_lines([f"L{i}" for i in range(1, 301)])
    lines = rendered.split("\n")

    assert (len(lines), lines[0], lines[299]) == (300, "1: L1", "300: L300"), (
        "one output line per input line, first numbered 1 and last numbered 300 — "
        "the number is the file position, unpadded"
    )
    # (zero-padded?, right-aligned?) — both would change the bytes of every file
    # over 9 lines while still looking correct to a human reader.
    padded = ("012:" in rendered, " 12:" in rendered)
    assert padded == (False, False), (
        "line numbers must be neither zero-padded nor space-aligned: the format is "
        "exactly f'{n}: '"
    )


def test_number_lines_numbers_are_absolute_and_the_range_is_clamped():
    """A windowed render carries ABSOLUTE file positions, and an over-wide window
    is clamped rather than raising.

    Snippet-relative numbering is worse than none: the model's output would look
    precise and be wrong by exactly the window offset, which is undetectable
    downstream.
    """
    from shared.tools.line_format import number_lines

    body = [f"L{i}" for i in range(1, 301)]

    assert number_lines(body, 5, 8) == "6: L6\n7: L7\n8: L8", (
        "lines[5:8] must render as 6,7,8 — the file positions, not 1,2,3"
    )
    # end past the last line, start past the last line, empty range.
    out_of_range = (
        number_lines(["a", "b"], 0, 99),
        number_lines(["a", "b"], 5),
        number_lines(["a", "b"], 1, 1),
    )
    assert out_of_range == ("1: a\n2: b", "", ""), (
        "an out-of-range window is clamped to what exists and renders nothing when "
        "empty — never an IndexError, because the caller's window comes from a "
        "model-reported line number"
    )


# ── T0.1 / C1: the inverse ───────────────────────────────────────────────────

@pytest.mark.parametrize("line", _ROUND_TRIP_LINES, ids=[repr(x) for x in _ROUND_TRIP_LINES])
def test_strip_line_number_is_the_inverse_of_number_lines(line):
    """The pair must round-trip exactly, or quoted evidence cannot be compared to
    the file it was quoted from.

    ``"a\\nb"`` is in the set on purpose: it is why ``NUMBER_RE`` carries
    ``re.DOTALL``. Without it ``(.*)$`` cannot span the newline, the match fails
    outright, and the prefix survives into the comparison as a phantom difference.
    """
    from shared.tools.line_format import number_lines, strip_line_number

    assert strip_line_number(number_lines([line])) == line, (
        "strip_line_number must recover the original line byte for byte; a lossy "
        "inverse makes every quote comparison fail on presentation, not on content"
    )


@pytest.mark.parametrize("line", _UNPREFIXED_LINES, ids=[repr(x) for x in _UNPREFIXED_LINES])
def test_strip_line_number_is_identity_without_a_prefix(line):
    """Identity on unprefixed input is what makes the function safe to apply
    UNCONDITIONALLY — callers must not have to know whether a given line came from
    a numbered render or from the raw file. A caller forced to decide is a caller
    that will decide wrongly on the path nobody tested.
    """
    from shared.tools.line_format import strip_line_number

    assert strip_line_number(line) == line, (
        "a line with no '<digits>:' prefix must come back untouched, so the "
        "inverse can be applied without first classifying the input"
    )


def test_strip_line_number_also_strips_a_line_that_itself_looks_numbered():
    """The one ambiguity, pinned deliberately rather than left to discovery.

    ``number_lines`` numbers unconditionally, so a source line that already reads
    ``"12: x"`` is presented as ``"1: 12: x"``. The inverse must remove ONE prefix —
    the outermost. It follows that applying it to a RAW line of that shape removes a
    real character sequence. That is the correct trade: the read direction exists to
    undo the write direction, and the write direction always ran.
    """
    from shared.tools.line_format import number_lines, strip_line_number

    assert strip_line_number(number_lines(["12: x"])) == "12: x", (
        "exactly one prefix comes off — the one number_lines put on"
    )
    assert strip_line_number("12: x") == "x", (
        "a raw line of numbered shape is indistinguishable from a presented line; "
        "the documented behaviour is to strip"
    )


@pytest.mark.parametrize(
    ("line", "recognised"),
    _NUMBER_RE_CASES,
    ids=[repr(c[0]) for c in _NUMBER_RE_CASES],
)
def test_number_re_recognises_a_presented_line_only(line, recognised):
    """``NUMBER_RE`` is exported so ``feed_probe`` and any future reader use the ONE
    pattern instead of hand-rolling a fourth. Pin what it recognises: a rendered
    prefix yes, a bare colon in prose or code no."""
    from shared.tools.line_format import NUMBER_RE

    assert (NUMBER_RE.match(line) is not None) is recognised, (
        f"NUMBER_RE must recognise {line!r} as a line-number prefix: {recognised}"
    )


# ── AC32: the leaf invariant and the both-order import ───────────────────────

def test_line_format_imports_nothing_from_shared():
    """AC32: asserted on the module's own AST, not by convention.

    ``line_format`` is imported by ``tools/file_reader.py`` (which the package
    ``__init__`` re-exports) AND by ``audit_runner``. The instant it imports
    anything from ``shared.*`` — including a relative ``from . import x``, which
    re-enters ``shared/tools/__init__.py`` — the cycle of §5.0 is back and every
    agent fails at startup.
    """
    assert _LINE_FORMAT.exists(), (
        f"{_LINE_FORMAT} must exist: the pair cannot live in audit_runner.py "
        f"(reproduced circular import, §5.0 D16)"
    )
    offenders = _shared_imports(ast.parse(_LINE_FORMAT.read_text(encoding="utf-8")))
    assert offenders == [], (
        f"line_format.py must be a LEAF; it imports {offenders} from the shared "
        f"package, which re-opens the audit_runner <-> tools.__init__ cycle"
    )


def test_import_file_reader_first_then_audit_runner():
    """AC32 / T0.7, order 1 — the order that SUCCEEDS even when the cycle is
    present. It is here so the pair of tests is honest about the trap: on its own
    this order proves nothing, which is precisely how the cycle shipped in the
    first draft."""
    proc = _import_in_order("shared.tools.file_reader", "shared.audit_runner")

    assert proc.returncode == 0, (
        "importing shared.tools.file_reader first must leave shared.audit_runner "
        f"importable:\n{proc.stderr}"
    )


def test_import_audit_runner_first_then_file_reader():
    """AC32 / T0.7, order 2 — the order that FAILS when the pair lives in
    ``audit_runner``: ``shared/tools/__init__.py:6`` re-exports ``file_reader``,
    which imports back into the partially initialised ``audit_runner``. This is the
    order every agent actually runs, and the reason both orders are tested in
    separate subprocesses."""
    proc = _import_in_order("shared.audit_runner", "shared.tools.file_reader")

    assert proc.returncode == 0, (
        "importing shared.audit_runner first must succeed — this is the agent "
        "startup order, and the reproduced ImportError of §5.0 lands exactly "
        f"here:\n{proc.stderr}"
    )


# ── AC19, scoped to the detector feed path ───────────────────────────────────

def test_write_direction_has_one_site_on_the_detector_feed_path():
    """AC19 (write): across the feed path the ``f"{n}: "`` render appears once, in
    the leaf.

    ``audit_runner`` keeps only the alias, ``file_reader`` calls
    ``line_format.number_lines`` (T2.5) and ``feed_probe`` never renders. Two
    renderers on one path is how 0075's two prompt paths came to disagree about
    whether a file gets numbered at all.
    """
    sites = _sites_by_file(_write_sites)
    total = sum(len(v) for v in sites.values())

    assert total == 1, (
        f"exactly one number-prefix render may exist on the detector feed path; "
        f"found {total}: {sites}. The detector looks for an f-string beginning "
        f"f'{{...}}: ' — the shape every current site uses"
    )
    assert len(sites["shared/tools/line_format.py"]) == 1, (
        f"the one render site must be line_format.number_lines, not {sites}"
    )


def test_read_direction_has_one_site_on_the_detector_feed_path():
    """AC19 (read): the prefix regex appears once, in the leaf.

    Today there are two hand-rolled readers — ``_redact_snippet:1419``
    (``^(\\s*\\d+:\\s?)(.*)$``) and ``feed_probe:44`` (``^\\d+: ``) — which already
    disagree about leading whitespace and about the trailing space. Both must move
    onto ``strip_line_number`` / ``NUMBER_RE``, or a rendered line will parse
    differently depending on which module reads it.
    """
    sites = _sites_by_file(_read_sites)
    total = sum(len(v) for v in sites.values())

    assert total == 1, (
        f"exactly one number-prefix REGEX may exist on the detector feed path; "
        f"found {total}: {sites}. _redact_snippet and feed_probe must call the "
        f"leaf instead of matching their own pattern"
    )
    assert len(sites["shared/tools/line_format.py"]) == 1, (
        f"the one regex must be line_format.NUMBER_RE, not {sites}"
    )


def test_the_ac19_exclusions_are_named_and_out_of_scope():
    """AC19 is SCOPED, and the scope is stated here rather than implied.

    An unscoped "the format literal appears once in the tree" is unachievable —
    there are four write-direction sites — and an unachievable assertion is one
    that gets edited later to make code pass. So the two excluded files are named
    with their reasons, and the only thing asserted about them is that they are
    real files outside the feed path.
    """
    assert set(_AC19_EXCLUSIONS) == {
        "shared/validate/judge_tools.py",
        "shared/tools/snippet.py",
    }, "the exclusion list is part of the contract; extending it needs a plan amendment"

    for rel, reason in _AC19_EXCLUSIONS.items():
        _assert_named_exclusion(rel, reason)


def test_the_judge_tool_render_is_left_alone():
    """The concrete reason AC19 cannot be global: ``judge_tools.py:213`` still
    renders its own numbered lines after 0076.

    That site feeds L5's ``read_lines`` tool, not the detector prompt. Absorbing it
    here would change judge behaviour as a side effect of a detector fix; §12
    records it as a 0072 amendment instead. If a later change DOES unify it, this
    test is the one that must be revisited deliberately — with the amendment — and
    that is the point of pinning it.
    """
    sites = _write_sites("shared/validate/judge_tools.py")

    assert len(sites) >= 1, (
        "judge_tools.py's numbered render was removed or rewritten by a detector "
        "feed change; that belongs to 0072 (§12), not to 0076"
    )
