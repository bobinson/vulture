"""Feature 0102 (D18, LLD §8.7): every cap of the complexity contract is a named
constant in ``shared.ast.limits``.

The AST layer promises O(1) amortised work per node, per line and per query
(invariant 7). Each promise rests on one cap, and every cap lives in one module
so the bound is visible, reviewed and changed in one place. None of them is an
environment variable (CLAUDE.md rule 6, D12): a cap an operator could raise is
a cap an adversarial repository can be planned around.

This file is the CONSTANTS half of the contract: each §8.7 cap exists with the
value the LLD states; ``limits.py`` is a table of constants that reads no
environment and gives every cap a comment naming its §8.7 row; and no other
module of the package binds a cap of its own. The BEHAVIOURAL half — each cap
exercised at cap + 1, asserting the tally or degradation the §8.7 table names —
is appended to this file by the change that implements that cap.
"""

from __future__ import annotations

import ast
import tokenize
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from shared.ast import FileModel, limits
from shared.tools import suppression
from tests.unit.ast._analysis import (
    ALLOWLIST,
    NO_GUARD,
    READ,
    SINK,
    SINK_P,
    analysis_of,
    call_at,
    candidates_of,
    flow_at_call,
    guard_verdict,
    if_test,
    in_audit,
    js_handler,
    judge,
    model_of,
    nested,
    origins_of,
    program,
    spy_pool,
    subject,
    unknown,
)
from tests.unit.ast._audit import (
    FORCED,
    SANITIZED,
    clean_files,
    decline_line,
    ledger_view,
    names,
    path_lists,
    records,
    snapshot_after,
)

if TYPE_CHECKING:
    from shared.ast.flow import Origin

_MIB = 1024 * 1024

# LLD §8.7, one entry per cap; the comment names the table row whose bound it
# makes constant. MAX_DEPTH serves two rows (the worker's cursor depth and the
# IF ancestors guards_for examines) and is still one constant.
CAPS: dict[str, int] = {
    "MAX_FILE_SIZE": 512 * 1024,  # worker parse + captures
    "MAX_NODES": 500_000,  # worker parse + captures
    "MAX_DEPTH": 256,  # worker parse + captures; guards_for ancestors
    "FRAME_CAP": 8 * _MIB,  # frame decode + validate
    "MAX_CHAIN": 8,  # chain_words
    "MAX_WORDS": 16,  # chain_words
    "MAX_BRANCH_DEPTH": 32,  # scope pass per function
    "MAX_ORIGINS": 16,  # origins(node)
    "MAX_SUMMARY_SIGNATURES": 4,  # callee summary
    "MAX_SUMMARY_DEPTH": 2,  # callee summary
    "MAX_ARG_NAMES": 16,  # guards_for
    "MAX_TEST_NODES": 64,  # guards_for
    "GUARD_WINDOW": 8,  # guards_for
    "MAX_ARGS": 16,  # candidates(family)
    "MAX_SUPPRESSIONS_PER_RULE": 50,  # decline ledger
    "MAX_FALLBACK_PATHS": 200,  # coverage lists (the display list only)
    "CIRCUIT_BREAK_AFTER": 20,  # breaker
    "MAX_HOPS": 8,  # hops
    "MAX_RENDERED_PATH": 200,  # safe_path: the first characters of a rendered path (A30 (5))
}

_LIMITS_PATH = Path(limits.__file__)
_PACKAGE = _LIMITS_PATH.parent
# Every spelling through which Python code reaches the process environment.
_ENV_NAMES = frozenset({"os", "environ", "environb", "getenv", "getenvb", "putenv"})
_BINDINGS = (ast.Assign, ast.AnnAssign)


def _no_names(_node: ast.AST) -> tuple[str, ...]:
    """The names a node that mentions none mentions."""
    return ()


# Each node type that mentions a name, and the names it mentions.
_NAMES_IN: dict[type[ast.AST], Callable[[Any], tuple[str, ...]]] = {
    ast.Name: lambda node: (node.id,),
    ast.Attribute: lambda node: (node.attr,),
    ast.Import: lambda node: tuple(alias.name for alias in node.names),
    ast.ImportFrom: lambda node: (node.module or "", *(alias.name for alias in node.names)),
}


def _limits_tree() -> ast.Module:
    """The parsed source of ``limits.py``."""
    return ast.parse(_LIMITS_PATH.read_text(encoding="utf-8"))


def _targets(node: ast.Assign | ast.AnnAssign) -> list[ast.expr]:
    """The binding targets of one assignment statement."""
    return list(node.targets) if isinstance(node, ast.Assign) else [node.target]


def _assignments(tree: ast.AST) -> Iterator[ast.Assign | ast.AnnAssign]:
    """Every assignment statement anywhere in ``tree``."""
    return (node for node in ast.walk(tree) if isinstance(node, _BINDINGS))


def _assigned_names(tree: ast.AST) -> set[str]:
    """Every plain name any assignment in ``tree`` binds."""
    return {t.id for node in _assignments(tree) for t in _targets(node) if isinstance(t, ast.Name)}


def _imported_names(node: ast.ImportFrom) -> set[str]:
    """The local names one ``from ... import`` statement binds."""
    return {alias.asname or alias.name for alias in node.names}


def _bound_by(node: ast.stmt) -> set[str]:
    """The names one top-level statement of ``limits.py`` binds."""
    if isinstance(node, ast.ImportFrom):
        return _imported_names(node)
    return _assigned_names(node)


def _is_docstring(node: ast.stmt) -> bool:
    """True for a bare string expression (the module docstring)."""
    value = getattr(node, "value", None)
    return isinstance(node, ast.Expr) and isinstance(getattr(value, "value", None), str)


def _is_reexport(node: ast.stmt) -> bool:
    """``from __future__`` or a re-export of an existing ``shared`` constant."""
    root = (getattr(node, "module", None) or "").split(".")[0]
    return isinstance(node, ast.ImportFrom) and root in {"__future__", "shared"}


def _binds_constants(node: ast.stmt) -> bool:
    """An assignment whose every target is one UPPER_CASE name."""
    if not isinstance(node, _BINDINGS):
        return False
    return all(isinstance(t, ast.Name) and t.id.isupper() for t in _targets(node))


def _is_table_row(node: ast.stmt) -> bool:
    """A statement a constants-only module may contain."""
    return _is_docstring(node) or _is_reexport(node) or _binds_constants(node)


def _identifiers(tree: ast.AST) -> set[str]:
    """Every name, attribute and imported name ``tree`` mentions."""
    found: set[str] = set()
    for node in ast.walk(tree):
        found.update(_NAMES_IN.get(type(node), _no_names)(node))
    return found


def _comments(path: Path) -> dict[int, bool]:
    """Line number -> whether its ``#`` comment is the whole line (no code before)."""
    with tokenize.open(path) as handle:
        tokens = tokenize.generate_tokens(handle.readline)
        return {
            tok.start[0]: not tok.line[: tok.start[1]].strip()
            for tok in tokens
            if tok.type == tokenize.COMMENT
        }


def _binding_statement(tree: ast.Module, name: str) -> ast.stmt | None:
    """The top-level statement of ``limits.py`` that binds ``name``."""
    return next((node for node in tree.body if name in _bound_by(node)), None)


def _statement_lines(node: ast.stmt) -> range:
    """The source lines one statement spans."""
    return range(node.lineno, (node.end_lineno or node.lineno) + 1)


def _is_commented(node: ast.stmt | None, comments: dict[int, bool]) -> bool:
    """A comment sits on the statement's own lines, or a whole-line comment sits
    just above it (another statement's trailing comment does not count)."""
    if node is None:
        return False
    return not comments.keys().isdisjoint(_statement_lines(node)) or comments.get(node.lineno - 1, False)


def _imports_a_cap_from_elsewhere(node: ast.AST) -> bool:
    """A ``from X import CAP`` whose module is not a ``limits`` module."""
    if not isinstance(node, ast.ImportFrom):
        return False
    return (node.module or "").split(".")[-1] != "limits"


def _names_imported_from_elsewhere(tree: ast.AST) -> set[str]:
    """Every name ``tree`` imports from a module other than ``limits``."""
    return {
        name
        for node in ast.walk(tree)
        if _imports_a_cap_from_elsewhere(node)
        for name in _imported_names(node)
    }


def _foreign_cap_names(tree: ast.AST) -> set[str]:
    """The cap names a module binds other than by importing them from limits."""
    return (_names_imported_from_elsewhere(tree) | _assigned_names(tree)) & CAPS.keys()


def _rebound_caps(path: Path) -> list[str]:
    """The cap names one package module redefines, sorted."""
    return sorted(_foreign_cap_names(ast.parse(path.read_text(encoding="utf-8"))))


def _rebound_caps_by_module() -> dict[str, list[str]]:
    """Package-relative module path -> the caps it binds outside limits.py."""
    return {
        str(path.relative_to(_PACKAGE)): names
        for path in sorted(_PACKAGE.rglob("*.py"))
        if path != _LIMITS_PATH and (names := _rebound_caps(path))
    }


def _is_stated(name: str) -> bool:
    """``limits.<name>`` is an ``int`` equal to its §8.7 value (never a float,
    bool or string that merely compares equal)."""
    value = getattr(limits, name, None)
    return type(value) is int and value == CAPS[name]


def _misstated_caps() -> dict[str, object]:
    """Cap name -> what ``limits`` holds, for every cap not as stated."""
    return {name: getattr(limits, name, None) for name in CAPS if not _is_stated(name)}


def test_every_cap_has_its_stated_value() -> None:
    """Each §8.7 cap is an ``int`` in ``limits`` with exactly the stated value:
    a cap is a count or a byte size, compared against counters."""
    assert _misstated_caps() == {}, f"limits caps differ from LLD §8.7 {CAPS}"


def test_decline_cap_is_the_existing_suppression_cap() -> None:
    """D9 states the per-rule decline cap AS the existing per-rule suppression
    cap (``shared/tools/suppression.py``); two values for one fact cannot drift."""
    assert limits.MAX_SUPPRESSIONS_PER_RULE == suppression.MAX_SUPPRESSIONS_PER_RULE


def test_a_max_size_file_fits_one_frame() -> None:
    """D3: a file's bytes travel to the worker in one ``u32``-length frame that
    the reader refuses above ``FRAME_CAP``. The largest file the layer admits
    must therefore fit under the cap, and the cap under the ``u32`` prefix."""
    assert limits.MAX_FILE_SIZE < limits.FRAME_CAP < 2**32


def test_limits_holds_constants_only() -> None:
    """``limits.py`` is a table of constants (D18): a docstring, imports
    of existing ``shared`` constants and UPPER_CASE bindings — no function, no
    class, no statement that computes state at import."""
    stray = [
        f"line {node.lineno}: {type(node).__name__}"
        for node in _limits_tree().body
        if not _is_table_row(node)
    ]
    assert stray == [], f"limits.py holds more than constants: {stray}"


def test_limits_reads_no_environment() -> None:
    """No cap is configurable (CLAUDE.md rule 6, D12): ``limits.py`` never names
    ``os`` or any environment accessor, so no value it holds can come from one."""
    mentioned = _identifiers(_limits_tree()) & _ENV_NAMES
    assert mentioned == set(), f"limits.py reaches the environment through {sorted(mentioned)}"


def test_every_cap_carries_a_comment() -> None:
    """Each cap's binding carries a comment (a one-line comment naming its
    §8.7 row), so the reader of the table sees which bound each value makes
    constant without opening the design."""
    tree = _limits_tree()
    comments = _comments(_LIMITS_PATH)
    missing = [name for name in CAPS if not _is_commented(_binding_statement(tree, name), comments)]
    assert missing == [], f"caps bound without a comment in limits.py: {missing}"


def test_no_other_ast_module_binds_a_cap() -> None:
    """One source per cap (D19; §14 "every cap comes from limits.py"): no other
    module of ``shared.ast`` assigns a cap name or imports one from anywhere but
    ``limits``. A private copy would let one bound move while its twin stays."""
    assert _rebound_caps_by_module() == {}, "caps bound outside limits.py"


def test_words_memo_is_bounded_by_its_limit() -> None:
    """D18: the ``words()`` memo is a cap like any other — its LRU bound is
    ``limits.WORDS_MEMO``, not a literal of the module that memoises."""
    from shared.ast.model import words

    assert words.cache_info().maxsize == limits.WORDS_MEMO


# ══ the behavioural half: each Phase-2 cap at cap and at cap + 1 (§8.7) ══════
#
# Each row runs one program at the cap and its twin one step past it, and asserts the
# degradation §8.7's "at cap + 1" column names. Phase-2 modules are reached only through
# ``_analysis``'s lazy accessors (and ``model.analysis()``), so this module still collects
# while they are missing, and each row fails on its own until its task lands.
#
# Each row whose cap the analysis tallies (MAX_BRANCH_DEPTH, the two summary caps,
# MAX_ORIGINS) also reads ``analysis_of(model).tallies`` (A28 (3), A32): the per-file fact
# counts a FlowAnalysis carries, read after the query that meets the cap.
#
# Rows that live with the module of the code they exercise, each already at the cap and
# at cap + 1, and are not restated here:
#   MAX_ARGS             test_0102_model_queries.py::test_max_args_keeps_the_first_positions_and_tallies
#                        (the model's half; the candidates(family) half is below, A32)
#   MAX_ORIGINS          test_0102_flow_rules.py::test_seventeen_origins_collapse_to_any_and_overflow,
#                        ::test_an_origin_overflow_is_a_per_file_analysis_tally
#   GUARD_WINDOW         test_0102_guards.py::test_guard_window_counts_preceding_if_and_try_siblings
#   CIRCUIT_BREAK_AFTER  test_0102_worker_pool.py::test_circuit_breaker, ::test_circuit_breaker_counts_crashes;
#                        test_0102_coverage.py::test_a_tripped_breaker_is_reported_in_files_and_mirrored_in_workers
# The plan's own cases for MAX_SUPPRESSIONS_PER_RULE (60 declines, test_0102_declines.py) and
# MAX_FALLBACK_PATHS (250 fallbacks, test_0102_coverage.py) sit well past their caps. The
# rows here add the boundary those cases cannot see: AT the cap nothing is capped, and one
# more is. MAX_DEPTH's guards_for row (the IF ancestors examined) has no reachable cap + 1:
# the worker refuses a file deeper than MAX_DEPTH (too_deep), and every IF ancestor is at
# least one tree level, so no model has more than MAX_DEPTH of them.

# A row that builds models: the module's one W = 1 pool and audit (``conftest.py``).
_ON_A_POOL = pytest.mark.usefixtures("real_pool")


# ── MAX_BRANCH_DEPTH: scope pass per function (§7.2; plan 2.1) ───────────────

# Language code -> the handler around ``{body}`` (``p`` is bound from the request parameter
# before any branch), and one branch's head and tail: each IF opens one delta (§7.2).
_BRANCHING: dict[str, tuple[str, str, str]] = {
    "js": ("function h(req) {{\n  const p = req;\n{body}}}\n", "if (c) {\n", "}\n"),
    "go": ("package main\n\nfunc h(req string) {{\n\tp := req\n{body}}}\n", "if c {\n", "}\n"),
}


def _tally(m: FileModel, name: str) -> int:
    """One per-file fact count of the model's analysis (A28 (3)); 0 when absent."""
    return analysis_of(m).tallies.get(name, 0)


def _read_in_branches(lang: str, depth: int) -> tuple[frozenset[Origin], int]:
    """``origins`` of the read of ``p`` in ``sink(p)`` inside ``depth`` nested IFs, and the
    analysis's ``branch_depth`` tally once it is read."""
    handler, head, tail = _BRANCHING[lang]
    m = model_of(handler.format(body=nested(head, tail, depth, "sink(p)\n")), lang)
    return origins_of(m, m.args(call_at(m, "sink"))[0]), _tally(m, "branch_depth")


@_ON_A_POOL
@pytest.mark.parametrize("lang", list(_BRANCHING))
def test_a_read_deeper_than_max_branch_depth_is_unknown_depth(lang: str) -> None:
    """§7.2, §8.7 "deeper branches -> unknown(depth)": a read inside ``MAX_BRANCH_DEPTH``
    nested IFs resolves exactly as the same read outside any branch; one IF deeper (33) its
    origins hold ``unknown(depth)``, and the analysis tallies ``branch_depth`` (A32). ``p`` is
    a plain name, so no dotted-path truncation (§7.1) can be what puts ``unknown(depth)``
    there."""
    depths = (0, limits.MAX_BRANCH_DEPTH, limits.MAX_BRANCH_DEPTH + 1)
    (flat, _), (at_cap, at_cap_tally), (over, over_tally) = (
        _read_in_branches(lang, depth) for depth in depths
    )
    deep = unknown("depth")

    assert (at_cap == flat, deep in flat, deep in over) == (True, False, True), (flat, at_cap, over)
    assert (at_cap_tally, over_tally >= 1) == (0, True)


# ── MAX_SUMMARY_SIGNATURES, MAX_SUMMARY_DEPTH: callee summary (§8.4; plan 2.3) ─

# Argument texts with pairwise distinct origin sets (§8.2): ``req`` a request PARAM,
# ``argv`` a source word (W9 (b)), ``mystery`` unresolved, and their unions (BINOP).
_SIGNATURES = ("req", "argv", "mystery", "req + argv", "req + mystery", "argv + mystery")


def _summary_answer(m: FileModel, call: int) -> str:
    """What a call of a local identity function answers: ``summary_cap`` when its origins
    hold ``unknown(summary_cap)``, ``summary`` when they are its argument's (the identity's
    summary ran), else ``other``."""
    answer = origins_of(m, call)
    if unknown("summary_cap") in answer:
        return "summary_cap"
    return "summary" if answer == origins_of(m, m.args(call)[0]) else "other"


def _relay_answers(arguments: Sequence[str]) -> tuple[list[str], int]:
    """The sorted answers of one ``relay(<argument>)`` call per argument, in one handler;
    ``relay`` is a local identity function, so each call is summarised (§8.4). With them, the
    analysis's ``summary_cap`` tally once every call is read (A32)."""
    calls = "".join(f"  sink(relay({argument}));\n" for argument in arguments)
    m = model_of(f"function relay(p) {{\n  return p;\n}}\nfunction h(req) {{\n{calls}}}\n", "js")
    answers = sorted(_summary_answer(m, call_at(m, "relay", nth=k)) for k in range(len(arguments)))
    return answers, _tally(m, "summary_cap")


_CAP_SIGNATURES = _SIGNATURES[: limits.MAX_SUMMARY_SIGNATURES]
_SUMMARIES = ["summary"] * limits.MAX_SUMMARY_SIGNATURES


@_ON_A_POOL
@pytest.mark.parametrize(("arguments", "answers"), [
    pytest.param(_CAP_SIGNATURES, _SUMMARIES, id="four-signatures"),
    pytest.param(_CAP_SIGNATURES * 2, _SUMMARIES * 2, id="four-signatures-each-twice"),
    pytest.param(
        _SIGNATURES[: limits.MAX_SUMMARY_SIGNATURES + 1], [*_SUMMARIES, "summary_cap"],
        id="a-fifth-signature",
    ),
])
def test_a_callee_past_max_summary_signatures_answers_summary_cap(
    arguments: Sequence[str], answers: list[str]
) -> None:
    """§8.4, §8.7: ``summary`` is memoised on ``(callee, canonical(arg_origins))``, at most
    ``MAX_SUMMARY_SIGNATURES`` signatures per callee. Four distinct signatures are all
    summarised, and so is a repeat of any of them (a memo hit is no new signature); a fifth
    distinct signature answers ``unknown(summary_cap)``, and the analysis tallies
    ``summary_cap`` (A32). Which call is the fifth depends on the order the analysis meets
    them, so the answers are compared as a sorted list."""
    found, tallied = _relay_answers(arguments)
    assert (found, tallied >= 1) == (answers, "summary_cap" in answers)


def _relays(depth: int) -> FileModel:
    """JS whose handler passes ``req`` through ``depth`` nested local summaries:
    ``f{depth}(req)`` calls ``f{depth - 1}`` ... down to ``f1``, the identity."""
    relays = "".join(f"function f{i}(p) {{\n  return f{i - 1}(p);\n}}\n" for i in range(2, depth + 1))
    handler = f"function h(req) {{\n  sink(f{depth}(req));\n}}\n"
    return model_of(f"function f1(p) {{\n  return p;\n}}\n{relays}{handler}", "js")


@_ON_A_POOL
@pytest.mark.parametrize(("depth", "answer"), [
    pytest.param(limits.MAX_SUMMARY_DEPTH, "summary", id="two-nested-summaries"),
    pytest.param(limits.MAX_SUMMARY_DEPTH + 1, "summary_cap", id="three-nested-summaries"),
])
def test_a_summary_nested_past_max_summary_depth_answers_summary_cap(depth: int, answer: str) -> None:
    """§8.4, §8.7: summaries nest to ``MAX_SUMMARY_DEPTH``. The handler's own pass is no
    summary (as ``test_0102_flow_rules.py``'s depth-two case reads it), so ``f2(req)``
    resolves through two summaries to its argument's origins, and ``f3(req)``, whose third
    nested summary is past the cap, answers ``unknown(summary_cap)`` and is tallied (A32)."""
    m = _relays(depth)

    assert _summary_answer(m, call_at(m, f"f{depth}")) == answer
    assert (_tally(m, "summary_cap") >= 1) is (answer == "summary_cap")


# ── MAX_ARG_NAMES, MAX_TEST_NODES: guards_for (§8.5; plan 2.3) ───────────────
# §8.7 "unexamined guards are no guard (reportable)". Both rows put what the guard needs
# LAST in the bounded walk (in pre-order and breadth-first order alike), so a walk that
# stops at the cap and one that gives up past it both leave the guard unexamined, and the
# path sink reports with no guard found (``NO_GUARD``). A32 rules the MAX_ARG_NAMES walk
# keeps the FIRST names in document order, so that row also reads ``p`` first of 17: kept.


def _reads_ending_in_p(pads: int) -> tuple[str, str]:
    """The guards module's JS handler: ``pads`` Defs ``a0`` ... (each unresolved), then ``p``
    from the request behind an allowlist early exit; the path sink's one argument, a
    template literal, reads every ``a{i}`` and then ``p``, its last read."""
    defs = [f"const a{i} = x{i};" for i in range(pads)]
    reads = "".join(f"${{a{i}}}/" for i in range(pads))
    sink = f"{SINK}(`{reads}${{p}}`);"
    return js_handler(*defs, READ, "if (!ALLOWED.includes(p)) return;", sink)


def _reads_starting_with_p(pads: int) -> tuple[str, str]:
    """``_reads_ending_in_p`` with ``p`` read FIRST, before the ``pads`` other names."""
    defs = [f"const a{i} = x{i};" for i in range(pads)]
    reads = "".join(f"/${{a{i}}}" for i in range(pads))
    sink = f"{SINK}(`${{p}}{reads}`);"
    return js_handler(*defs, READ, "if (!ALLOWED.includes(p)) return;", sink)


@_ON_A_POOL
@pytest.mark.parametrize(("program", "verdict"), [
    pytest.param(_reads_ending_in_p(limits.MAX_ARG_NAMES - 1), ALLOWLIST, id="p-is-the-16th-name"),
    pytest.param(_reads_ending_in_p(limits.MAX_ARG_NAMES), NO_GUARD, id="p-is-the-17th-name"),
    pytest.param(_reads_starting_with_p(limits.MAX_ARG_NAMES), ALLOWLIST,
                 id="p-is-the-first-of-17-names"),
])
def test_a_guard_on_a_name_past_max_arg_names_is_unexamined(
    program: tuple[str, str], verdict: str
) -> None:
    """§8.5, A32: ``roots(arg)`` keeps the FIRST ``MAX_ARG_NAMES`` names in document order,
    each with its own Def. When ``p`` is the 16th, the allowlist IF that tests it guards the
    sink (``guarded:allowlist``); as the 17th it is never resolved, the IF meets no root, and
    the sink reports with no guard; read first of 17, it is kept, and the IF guards."""
    assert guard_verdict(subject(program), "path", SINK) == verdict


def _guarded_by(pads: int, negated: int) -> FileModel:
    """The guards module's JS handler with one early-exit IF before the sink. Its TEST is
    ``pads`` names (the first ``negated`` under ``!``), each right-nested before the
    allowlist test of ``p``: ``c0 || (c1 || (!ALLOWED.includes(p)))``, so ``p`` is the TEST's
    last node."""
    names = [f"!c{i}" if i < negated else f"c{i}" for i in range(pads)]
    test = "".join(f"{name} || (" for name in names) + "!ALLOWED.includes(p)" + ")" * pads
    return subject(js_handler(READ, f"if ({test}) {{ return; }}", SINK_P))


def _test_nodes(m: FileModel) -> int:
    """The nodes of the model's one IF TEST, its root included."""
    pending, count = [if_test(m)], 0
    while pending:
        count += 1
        pending.extend(m.children(pending.pop()))
    return count


def _guard_test_of(nodes: int) -> FileModel:
    """The ``_guarded_by`` program whose TEST holds exactly ``nodes`` nodes, sized on the
    model and checked, never assumed: every name adds the same ``step``, and each negated
    one a UNARY more."""
    one, two = (_test_nodes(_guarded_by(pads, 0)) for pads in (1, 2))
    step = two - one
    pads = (nodes - one) // step + 1
    m = _guarded_by(pads, nodes - one - (pads - 1) * step)
    assert _test_nodes(m) == nodes, f"the TEST holds {_test_nodes(m)} nodes, not {nodes}"
    return m


@_ON_A_POOL
@pytest.mark.parametrize(("nodes", "verdict"), [
    pytest.param(limits.MAX_TEST_NODES, ALLOWLIST, id="a-64-node-test"),
    pytest.param(limits.MAX_TEST_NODES + 1, NO_GUARD, id="a-65-node-test"),
])
def test_a_guard_test_past_max_test_nodes_is_no_guard(nodes: int, verdict: str) -> None:
    """§8.5: a TEST's reads and role parts are read over at most ``MAX_TEST_NODES`` nodes
    (counted with the TEST itself). A 64-node TEST is examined whole, so its allowlist test
    of ``p`` guards the sink; at 65 nodes its last node, the read of ``p``, is past the cap,
    and the sink reports with no guard."""
    assert guard_verdict(_guard_test_of(nodes), "path", SINK) == verdict


# ── MAX_HOPS: a flow's hops (§8.6; plan 2.3) ─────────────────────────────────


def _copied_flow(copies: int) -> Any:
    """The path flow whose request value is copied ``copies`` times (``const a1 = a0;`` ...)
    before the sink reads the last copy."""
    lines = [f"const a{i + 1} = a{i};" for i in range(copies)]
    program = js_handler("const a0 = req.query.f;", *lines, f"{SINK}(a{copies});")
    return flow_at_call(subject(program), "path", SINK)


def _source_side(flow: Any) -> tuple[Any, bool, bool]:
    """A flow's first hop, whether its hops run in line order from the source side, and
    whether a ``sink`` hop is among them."""
    lines = [hop.line for hop in flow.hops]
    return flow.hops[0], lines == sorted(lines), "sink" in {hop.kind for hop in flow.hops}


def _hops(copies: int) -> tuple[int, bool]:
    """``(len(hops), truncated)`` of ``_copied_flow(copies)``."""
    flow = _copied_flow(copies)
    return len(flow.hops), flow.truncated


@_ON_A_POOL
def test_a_flow_longer_than_max_hops_is_cut_and_truncated() -> None:
    """§8.6, §8.7: a flow keeps at most ``MAX_HOPS`` hops; a longer chain is cut and marked
    ``truncated``. Each copy is one ``assign`` hop (§8.6, the §10.1 example), so the copy
    count that fills the cap is measured from the uncopied flow, never assumed: at it the
    flow has ``MAX_HOPS`` hops and is whole; one copy more, and far more, it has
    ``MAX_HOPS`` hops and is ``truncated``. A32: the hops kept are the FIRST ones from the
    source side, so a cut flow starts where the whole one does and has lost its sink hop."""
    base, cut = _hops(0)
    assert (0 < base < limits.MAX_HOPS, cut) == (True, False), f"the uncopied flow: {base} hops"
    copies = limits.MAX_HOPS - base

    observed = list(map(_hops, (copies, copies + 1, copies + 4 * limits.MAX_HOPS)))

    assert observed == [(limits.MAX_HOPS, False)] + [(limits.MAX_HOPS, True)] * 2
    far = _copied_flow(copies + 4 * limits.MAX_HOPS)
    assert _source_side(far) == (_copied_flow(0).hops[0], True, False)


# ── MAX_ARGS: candidates(family) (§8.7; A32) ─────────────────────────────────


def _paths_get(pads: int) -> FileModel:
    """Java ``Paths.get(ROOT, "d0", ..., request.getParameter("f"))`` (the pair key
    ``pathsget``, ``path_args="all"``), the request read as argument ``pads + 1``."""
    constants = "".join(f'"d{i}", ' for i in range(pads))
    return program("java", f"""
        class Docs {{
            Path pick(HttpServletRequest request) {{
                return Paths.get(ROOT, {constants}request.getParameter("f"));
            }}
        }}
        """)


@_ON_A_POOL
@pytest.mark.parametrize(("pads", "reported"), [
    pytest.param(limits.MAX_ARGS - 2, (3,), id="the-16th-argument-is-read"),
    pytest.param(limits.MAX_ARGS - 1, (), id="the-17th-argument-is-not-read"),
])
def test_an_argument_past_max_args_is_not_read_and_is_tallied(
    pads: int, reported: tuple[int, ...]
) -> None:
    """§8.7 "extra args ignored, tallied", A32: a ``path_args="all"`` sink reads its first
    ``MAX_ARGS`` arguments. The request read as the 16th reports; as the 17th it is not read
    — no flow names it as its argument — the sink does not report, and the file tallies
    ``args_capped``."""
    m = _paths_get(pads)
    request = call_at(m, "request.getParameter")
    args = {flow.arg for flow in candidates_of(m, "path")}

    assert (judge(m, "path").reported, request in args) == (reported, bool(reported))
    assert m.tallies.get("args_capped", 0) == (0 if reported else 1)


# ── MAX_SUPPRESSIONS_PER_RULE: the decline ledger (§10.3; plan 2.4) ──────────


def test_a_rule_is_capped_one_decline_past_max_suppressions_per_rule(tmp_path: Path) -> None:
    """§8.7 "capped_rules names the rule": ``MAX_SUPPRESSIONS_PER_RULE`` declines of one rule
    render every one and cap nothing; one more renders the same smallest fifty and names
    the rule. The extra, largest decline arrives FIRST, so the heap must evict it."""
    cap = limits.MAX_SUPPRESSIONS_PER_RULE
    files = names(cap + 1)
    shown = [decline_line(name) for name in files[:cap]]

    at_cap = ledger_view(tmp_path, records(tmp_path, files[:cap]))
    over = ledger_view(tmp_path, records(tmp_path, files[::-1]))

    assert (at_cap, over) == (
        (shown, {SANITIZED: cap}, []),
        (shown, {SANITIZED: cap + 1}, [SANITIZED]),
    )


# ── MAX_FALLBACK_PATHS: the coverage display list (§10.2, D24; plan 2.4) ─────


@_ON_A_POOL
def test_display_paths_are_truncated_one_fallback_past_max_fallback_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§8.7 "fallback_paths_truncated (display only)": an audit with ``MAX_FALLBACK_PATHS``
    fallbacks shows every one, untruncated; an audit with one more shows the same smallest
    200, truncated, while ``fallback_keys`` and the bucket keep every file (D24). The extra,
    largest path is asked first, so the display heap must evict it."""
    cap = limits.MAX_FALLBACK_PATHS
    spy_pool(monkeypatch, answer=FORCED)
    files = names(cap + 1)
    paths = clean_files(tmp_path, files)

    observed = [path_lists(in_audit(tmp_path, snapshot_after, tmp_path, audit)["files"])
                for audit in (paths[:cap], paths[::-1])]

    assert observed == [(files[:cap], False, files[:cap], cap), (files[:cap], True, files, cap + 1)]
