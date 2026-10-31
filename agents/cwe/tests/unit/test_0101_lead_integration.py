"""Feature 0101 -- integration checks from the cross review of the three rule tracks.

Each test pins one outcome of that review, so the outcome cannot quietly regress:

* the CWE-778 reversed-name read is anchored, so the protected 0087 ReDoS gate
  (which searches every module pattern unanchored over 512 KB) has a real
  margin instead of sitting on its budget;
* the lexical primitives the three rules share (stripped code, indent width,
  parameter name, parenthesised lists, bracket matching) are defined ONCE, in
  ``_lexical``; the rules had grown private copies that already disagreed;
* no dead lexicon is left, and helpers that only tests call say so;
* comments cite public things (the feature number, a test file), never the
  private review or design-document numbering;
* the CWE-209 shipped-genuine E2E gate loads the pre-0101 rule from a fixed
  commit, so it cannot compare the new rule with itself after a merge.
"""
from __future__ import annotations

import ast
import inspect
import re
import time
from pathlib import Path

import pytest

from cwe_agent.skills import _lexical as lx
from cwe_agent.skills import info_exposure_check as iec
from cwe_agent.skills import insufficient_logging_check as ilc
from cwe_agent.skills import resource_check as rc
from shared.testing.timing import budget

AGENT_ROOT = Path(__file__).resolve().parents[2]
RULES = (iec, ilc, rc)
MODULES = (lx, *RULES)


def _source(module) -> str:
    return Path(module.__file__).read_text(encoding="utf-8")


def _defined_functions(module) -> set[str]:
    return {n.name for n in ast.walk(ast.parse(_source(module))) if isinstance(n, ast.FunctionDef)}


def _assigned_names(node: ast.stmt) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else []
    return {t.id for t in targets if isinstance(t, ast.Name)}


def _module_assigns(module) -> set[str]:
    return set().union(*map(_assigned_names, ast.parse(_source(module)).body))


# --------------------------------------------------------------------------
# 0087 ReDoS gate margin (the gate itself is protected and not edited)
# --------------------------------------------------------------------------
_GATE_MS_PER_KB = 0.060          # tests/unit/test_0087_redos.py BUDGET_MS_PER_KB
_GATE_KB = 512


def _best_search_ms(pattern: re.Pattern[str], subject: str) -> float:
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        pattern.search(subject)
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def test_reversed_name_read_is_anchored() -> None:
    assert ilc._REVERSED_NAME.pattern.startswith(r"\A")


@pytest.mark.parametrize("fill", [" ", "\t", "("])
def test_reversed_name_is_far_inside_the_0087_budget(fill: str) -> None:
    gate = budget(_GATE_MS_PER_KB * _GATE_KB)
    ms = _best_search_ms(ilc._REVERSED_NAME, fill * (_GATE_KB * 1024))
    assert ms < 0.5 * gate, f"{ms:.2f} ms against a {gate:.1f} ms gate"


@pytest.mark.parametrize(("text", "at", "name"), [
    ("foo(", 3, "foo"),
    ("a.bar  (", 7, "bar"),
    ("x     (", 6, ""),          # more than four spaces: no name, as before
    ("1st(", 3, ""),             # a name never starts with a digit
    ("$cb(", 3, "$cb"),
    ("(", 0, ""),
])
def test_name_before_reads_the_same_names(text: str, at: int, name: str) -> None:
    assert ilc._name_before(text, at) == name


# --------------------------------------------------------------------------
# One copy of each shared primitive
# --------------------------------------------------------------------------
SHARED = ("stripped_code", "indent_width", "param_name", "paren_lists", "opening_bracket")


@pytest.mark.parametrize("name", SHARED)
def test_shared_primitive_is_exported_by_lexical(name: str) -> None:
    assert name in lx.__all__ and callable(getattr(lx, name))


@pytest.mark.parametrize("module", RULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_rules_keep_no_private_copy(module) -> None:
    copies = _defined_functions(module) & {"_code", "_indent", "_param_name", "_matching_open", "_words"}
    assert not copies, f"private copies of shared primitives: {sorted(copies)}"
    assert "_PARAMS" not in _module_assigns(module)


def test_callee_word_helpers_do_not_share_one_name_for_three_meanings() -> None:
    owners = [m.__name__ for m in RULES if "_callee_words" in _defined_functions(m)]
    assert len(owners) <= 1, owners


@pytest.mark.parametrize(("param", "name"), [
    ("e", "e"),
    ("e: Error", "e"),
    ("Exception e", "e"),
    ("$e = null", "e"),
    ("...args", "args"),
    ("(err)", "err"),
    ("readonly a: T", "a"),
    ("a = 1", "a"),
    ("  final IOException ex ", "ex"),
    ("", ""),
    ("   ", ""),
])
def test_param_name_has_one_canonical_reading(param: str, name: str) -> None:
    assert lx.param_name(param) == name


def test_both_rules_read_the_same_parameter_names() -> None:
    header = "function handle($e = null, ...args, readonly opts: T) {"
    assert set(iec._header_params(header)) == set(ilc._routine_params((header,), 0)) == {"e", "args", "opts"}


@pytest.mark.parametrize(("text", "parens_only", "at"), [
    ("f(a, g(b))", True, 1),
    ("x[f(a)]", False, 1),
    ("x[f(a)", True, 3),
    ("a)", True, -1),
    ("load().then(() => db.close())", False, 11),
])
def test_opening_bracket(text: str, parens_only: bool, at: int) -> None:
    assert lx.opening_bracket(text, parens_only=parens_only) == at


def test_stripped_code_is_capped_and_strips() -> None:
    long_tail = "x" * (3 * lx.MAX_SCAN_CHARS)
    assert len(lx.stripped_code("a = 1  # " + long_tail)) <= lx.MAX_SCAN_CHARS
    assert "secret" not in lx.stripped_code('f("secret")  // note')


def test_paren_lists_reads_innermost_lists() -> None:
    assert lx.paren_lists("def f(a, b) -> g(c):") == ["a, b", "c"]


def test_lexical_says_why_770_keeps_a_narrower_routine_header() -> None:
    doc = lx.__doc__ or ""
    assert "CWE-770" in doc and "routine_header" in doc and "call statement" in doc


# --------------------------------------------------------------------------
# Dead lexicon and test-only helpers
# --------------------------------------------------------------------------
def test_unreferenced_bracket_map_is_gone() -> None:
    assert not hasattr(ilc, "_OPEN_OF")


TEST_ORACLES = {
    rc: ("_declared_inside", "_reset_in_loop", "_trimmed", "_named"),
    ilc: ("_code_lines_above", "_enclosing_openers"),
}


@pytest.mark.parametrize(("module", "name"), [(m, n) for m, ns in TEST_ORACLES.items() for n in ns],
                         ids=lambda v: getattr(v, "__name__", str(v)).rsplit(".", 1)[-1])
def test_helpers_only_tests_call_say_so(module, name: str) -> None:
    fn = getattr(module, name, None)
    if fn is None:
        return   # deleted: nothing left to mark
    fn = inspect.unwrap(fn)
    lines, start = inspect.getsourcelines(fn)
    above = _source(module).splitlines()[max(0, start - 4):start - 1]
    text = "\n".join(above) + (fn.__doc__ or "")
    assert "test oracle" in text.lower(), f"{name} is called only by tests and does not say so"


# --------------------------------------------------------------------------
# Public comments
# --------------------------------------------------------------------------
# Pre-0101 comments that say "the LLD" (no section) predate this feature and stay.
_PRIVATE_TAGS = re.compile(
    r"\bRED\b|\bR-C\d|\bR(?:770|778|209)-|\bRED\d|\bPERF-\d|\bLLD\s?\d|\bRM-\d|\bN3-|\bNG\d"
    r"|\b(?:RC|CR)-\d|\(C\d{1,2}\)|\(D[1-8]\)"
)


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_rule_comments_cite_no_private_review_numbering(module) -> None:
    hits = [f"{i}: {line.strip()[:100]}" for i, line in enumerate(_source(module).splitlines(), 1)
            if _PRIVATE_TAGS.search(line)]
    assert not hits, "\n".join(hits[:20])


# --------------------------------------------------------------------------
# The CWE-209 shipped-genuine gate reads a FIXED pre-0101 commit
# --------------------------------------------------------------------------
def test_209_shipped_gate_reads_the_pre_0101_commit() -> None:
    src = (AGENT_ROOT / "tests" / "e2e" / "test_0101_cwe209_error_disclosure.py").read_text(encoding="utf-8")
    assert "071cde8096274841786947043a79d961852233b8" in src
    assert "merge-base" not in src and '"rev-parse", "HEAD"' not in src
