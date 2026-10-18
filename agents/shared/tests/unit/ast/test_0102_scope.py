"""Feature 0102 plan task 2.1 (RED): the scope pass and def-use with delta states (LLD §7).

``shared.ast.scope`` does not exist yet, so every test that reads it fails on its own with
the ``ModuleNotFoundError`` of ``scope_mod()`` (``_analysis``); nothing here imports it at
collection. The surface these tests read:

* ``ScopeTable.build(model, *, state_factory=dict)`` (A22; ``state_factory`` builds every
  State dict, base and deltas, and nothing else, §7.2), through ``_analysis.scope_of``;
* ``table.defs`` — every ``Def`` of the file, in document order — and ``table.resolve(node)``
  — the tuple of Defs that reach the read at ``node`` (A22; W8 calls this "the scope read") —
  each spelled once below;
* ``Def`` as §7.1 gives it (``node``, ``name``, ``kind``, ``value``, ``scope``), plus
  ``symbol``: the R-H symbol of an import binding, else None (A22). ``Def.value`` is the RHS
  node the Def binds (W11: pairwise, or the one CALL both targets of ``req, err := f()``
  bind). There is no ``global`` DefKind (A24): ``global x`` is no Def; it makes ``x``
  module-scoped for the rest of its function, so a later write there is an ``assign`` Def of
  the MODULE scope;
* ``scope.decorators(model, fn)`` -> ``tuple[int, ...]`` (W7, A22).

A Def's line is ``model.line(def.node)``. The ``CONSTRUCTS`` rows are in ``_constructs.py``.
The ``MAX_BRANCH_DEPTH`` row is ``test_0102_limits.py``'s, not this module's.
"""

from __future__ import annotations

import functools
from collections import Counter
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

import pytest

from shared.ast import FileModel
from shared.ast.kinds import Field, Kind
from tests.unit.ast._analysis import (
    LANG_SUFFIX,
    LANGS,
    Spec,
    external,
    fixture_model,
    model_of,
    node_at,
    numbered,
    origins_of,
    program,
    scope_mod,
    scope_of,
    source_of,
    subject,
)
from tests.unit.ast._constructs import (
    ARM_SANITIZED_LINE,
    BY_NAME,
    CONSTRUCTS,
    Construct,
    construct_model,
    construct_use,
)

if TYPE_CHECKING:
    from shared.ast.scope import Def, ScopeTable

pytestmark = pytest.mark.usefixtures("real_pool")

_CONSTRUCT_IDS = [construct.name for construct in CONSTRUCTS]


# ── the ScopeTable queries, spelled once ─────────────────────────────────────


def _defs(table: ScopeTable) -> list[Def]:
    """Every Def the table records (§7.1)."""
    return list(table.defs)


def _reaching(table: ScopeTable, node: int) -> list[Def]:
    """The Defs reaching the read at ``node`` (§7.2): ``ScopeTable.resolve``, a tuple (A22)."""
    found = table.resolve(node)
    assert isinstance(found, tuple), f"resolve answered a {type(found).__name__}, not a tuple"
    return list(found)


def _named(table: ScopeTable, name: str) -> list[Def]:
    """The Defs of ``name``."""
    return [d for d in _defs(table) if d.name == name]


def _decorators(model: FileModel, fn: int) -> set[int]:
    """``decorators(fn)`` (W7): its DECORATOR children and the DECORATORs right before it,
    as ``scope.decorators(model, fn)`` answers them: a tuple of node indexes (A22)."""
    found = scope_mod().decorators(model, fn)
    assert isinstance(found, tuple), f"decorators answered a {type(found).__name__}, not a tuple"
    return set(found)


def _lines(model: FileModel, defs: Iterable[Def]) -> set[int]:
    """The lines the Defs start on."""
    return {model.line(d.node) for d in defs}


def _resolution(model: FileModel, node: int) -> tuple[set[int], set[str], set[str]]:
    """What the read at ``node`` resolves to: the lines, names and kinds of its Defs."""
    defs = _reaching(scope_of(model), node)
    return _lines(model, defs), {d.name for d in defs}, {d.kind for d in defs}


def _name_on(model: FileModel, ident: str, line: int) -> int:
    """The first NAME ``ident`` on ``line``."""
    return node_at(model, Kind.NAME, text=ident, line=line)


def _function_named(model: FileModel, name: str) -> int:
    """The FUNCTION whose NAME child is ``name``."""
    (fn,) = (f for f in model.functions() if _ident_child(model, f) == name)
    return fn


def _ident_child(model: FileModel, fn: int) -> str | None:
    names = model.children(fn, Field.NAME)
    return model.ident(names[0]) if names else None


# ── the CONSTRUCTS table itself (green now: it pins the RED inputs) ──────────


@pytest.mark.parametrize("construct", CONSTRUCTS, ids=_CONSTRUCT_IDS)
@pytest.mark.parametrize("lang", LANGS)
def test_construct_programs_parse_and_align(construct: Construct, lang: str) -> None:
    """Every program parses with no ERROR node, holds its read inside ``sink(...)``, and
    names ``sink_ident`` on ``expected_def_line``: a scope failure is never a table error."""
    model = construct_model(construct.name, lang)
    source = construct.sources[lang]
    assert source is not None and model.error_nodes == 0
    construct_use(model, construct)
    assert construct.sink_ident in source.split("\n")[construct.expected_def_line - 1]


def _empty_cells(construct: Construct) -> set[tuple[str, str]]:
    return {(construct.name, lang) for lang in LANGS if construct.sources[lang] is None}


def _explained_cells(construct: Construct) -> set[tuple[str, str]]:
    return {(construct.name, lang) for lang in construct.lacks}


def test_every_absent_construct_names_its_reason() -> None:
    """A ``None`` cell is exactly a cell its row's ``lacks`` explains, with a reason."""
    explained = set().union(*map(_explained_cells, CONSTRUCTS))
    assert set().union(*map(_empty_cells, CONSTRUCTS)) == explained
    assert all(why for construct in CONSTRUCTS for why in construct.lacks.values())


@pytest.mark.parametrize("lang", LANGS)
def test_arm_rows_rewrite_on_the_sanitized_line(lang: str) -> None:
    """Every ``arm`` program rewrites ``name`` inside its first arm on ``ARM_SANITIZED_LINE``."""
    source = BY_NAME["arm"].sources[lang]
    assert source is not None
    assert "name = clean(" in source.split("\n")[ARM_SANITIZED_LINE - 1]


# ── def-use per construct and language (plan 2.1) ────────────────────────────


@pytest.mark.parametrize("construct", CONSTRUCTS, ids=_CONSTRUCT_IDS)
@pytest.mark.parametrize("lang", LANGS)
def test_use_at_the_sink_resolves_to_the_expected_def(construct: Construct, lang: str) -> None:
    """The read of ``sink_ident`` inside ``sink(...)`` resolves to the Def(s) of that name on
    ``expected_def_line`` and to nothing else (§7.2: overwrite, arms, R-O, W6, W7, W11, W13)."""
    model = construct_model(construct.name, lang)
    lines, names, _ = _resolution(model, construct_use(model, construct))
    assert (lines, names) == ({construct.expected_def_line}, {construct.sink_ident})


# ── revision 9, one test per decision ────────────────────────────────────────

# cwe_22_rs_2: the reads of `name` in the sink arm (line 12) and after the match (line 14);
# the pre-match Def (line 9) and the first arm's rewrite (line 11).
_RS_2 = ("cwe_22_rs_2", 12, 14, 9, 11)


def _arm_reads(case: str) -> tuple[FileModel, int, int, int, int]:
    """(model, the sibling arm's read, the read after the match, the pre-match Def's line,
    the first arm's rewrite line) of a language's ``arm`` row or of ``cwe_22_rs_2``."""
    if case in LANG_SUFFIX:
        model, arm = construct_model("arm", case), BY_NAME["arm"]
        inside, after = construct_use(model, arm), construct_use(model, arm, "after")
        return model, inside, after, arm.expected_def_line, ARM_SANITIZED_LINE
    stem, inside_line, after_line, pre, rewrite = _RS_2
    model = fixture_model(stem)
    return model, _name_on(model, "name", inside_line), _name_on(model, "name", after_line), pre, rewrite


@pytest.mark.parametrize("case", [*LANGS, _RS_2[0]])
def test_match_arms_join_against_pre_match_state(case: str) -> None:
    """L10: every arm runs from the pre-match state — a rewrite in one arm never reaches a
    read in a sibling arm — and the post-match state is ``join(pre, Δ1, …, Δk)``."""
    model, inside, after, pre, rewrite = _arm_reads(case)
    table = scope_of(model)
    assert _lines(model, _reaching(table, inside)) == {pre}
    assert _lines(model, _reaching(table, after)) == {pre, rewrite}


_ARGV_ARRAY = """\
// construct
int main(int argc, char *argv[]) {
    return sink(argv[1]);
}
"""
_REFERENCE = """\
// construct
void f(std::string x) {
    std::string &r = x;
    sink(r);
}
"""


def _assert_literal_index(model: FileModel, read: int) -> None:
    """``read`` is the OBJECT of a SUBSCRIPT whose INDEX is the unwrapped LITERAL ``1``."""
    subscript = model.parent(read)
    (index,) = model.children(subscript, Field.INDEX)
    assert (model.kind(subscript), model.kind(index), source_of(model, index)) == (
        Kind.SUBSCRIPT, Kind.LITERAL, "1",
    )


@pytest.mark.parametrize(
    ("spec", "ident", "line", "expected"),
    [
        pytest.param("cwe_22_c_1", "argv", 6, ({5}, {"argv"}, {"param"}), id="char_pp_argv"),
        pytest.param(("c", _ARGV_ARRAY), "argv", 3, ({2}, {"argv"}, {"param"}), id="argv_array"),
        pytest.param("cwe_22_cpp_1", "argv", 7, ({6}, {"argv"}, {"param"}), id="cpp_argv"),
        pytest.param(
            "cwe_22_c_2", "docPath", 7, ({6}, {"docPath"}, {"assign"}), id="init_declarator"
        ),
        pytest.param(("cpp", _REFERENCE), "r", 4, ({3}, {"r"}, {"assign"}), id="cpp_reference"),
    ],
)
def test_c_declarators_unwrap_and_main_argv(
    spec: Spec, ident: str, line: int, expected: tuple[set[int], set[str], set[str]]
) -> None:
    """C4: ``char **argv`` / ``char *argv[]`` bind the PARAM ``argv``; ``char *p = argv[1]``
    binds ``p`` (an ``init_declarator`` LHS unwrapped from its ``pointer_declarator``); C++
    ``T &r = x`` binds ``r``; ``argv[1]`` is a SUBSCRIPT whose INDEX is the unwrapped literal
    (C++ through the transparent ``subscript_argument_list``)."""
    model = subject(spec)
    read = _name_on(model, ident, line)
    if ident == "argv":
        _assert_literal_index(model, read)
    assert _resolution(model, read) == expected


_MAIN_ONLY = """\
// construct
int helper(int argc, char **argv) {
    return sink(argv[1]);
}
int main(int argc, char **argv) {
    return sink(argv[1]);
}
"""
_MAIN_BY_POSITION = """\
// construct
int main(int n, char *args[]) {
    return sink(args[1]);
}
"""


@pytest.mark.parametrize(
    ("source", "ident", "line", "is_argv"),
    [
        pytest.param(_MAIN_ONLY, "argv", 3, False, id="helper_argv"),
        pytest.param(_MAIN_ONLY, "argv", 6, True, id="main_argv"),
        pytest.param(_MAIN_BY_POSITION, "args", 3, True, id="main_second_param"),
    ],
)
def test_main_argv_is_external_argv_in_main_only(
    source: str, ident: str, line: int, is_argv: bool
) -> None:
    """C4's origin half (§8.2 PARAM; it reads ``FlowAnalysis``, task 2.3): ``main``'s
    SECOND parameter, whatever its name (P6), is ``external(argv)``; the same declarator in
    any other function is not."""
    model = program("c", source)
    origins = origins_of(model, _name_on(model, ident, line))
    assert (external("argv") in origins) is is_argv
    assert is_argv or all(origin.role != "argv" for origin in origins)


# ── A22: the table's shape ───────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["overwrite", "loop_target", "arm", "multi_target"])
@pytest.mark.parametrize("lang", ["js", "py", "go"])
def test_defs_are_every_def_once_in_document_order(name: str, lang: str) -> None:
    """A22: ``table.defs`` lists every Def of the file once, in document order (a node's index
    is its pre-order position, §6.2), whatever order the pass met them in (loops run twice)."""
    model = construct_model(name, lang)
    defs = _defs(scope_of(model))
    nodes = [d.node for d in defs]
    assert (nodes == sorted(nodes), len(set(defs)) == len(defs)) == (True, True)


# ── D6: joins cost the delta, never the state ────────────────────────────────


class _Touches(dict[Any, Any]):
    """A ``dict`` that logs, in one shared ``Counter``, every key an operation reads, writes
    or walks: a walk over the whole map logs every key it holds."""

    def __init__(self, log: Counter[Any], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.log = log
        self._walked()

    def _walked(self) -> None:
        self.log.update(dict.keys(self))

    def __getitem__(self, key: Any) -> Any:
        self.log[key] += 1
        return super().__getitem__(key)

    def __setitem__(self, key: Any, value: Any) -> None:
        self.log[key] += 1
        super().__setitem__(key, value)

    def __delitem__(self, key: Any) -> None:
        self.log[key] += 1
        super().__delitem__(key)

    def __contains__(self, key: object) -> bool:
        self.log[key] += 1
        return super().__contains__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        self.log[key] += 1
        return super().get(key, default)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        self.log[key] += 1
        return super().setdefault(key, default)

    def pop(self, key: Any, *default: Any) -> Any:
        self.log[key] += 1
        return super().pop(key, *default)

    def __iter__(self) -> Iterator[Any]:
        self._walked()
        return super().__iter__()

    def keys(self) -> Any:
        self._walked()
        return super().keys()

    def items(self) -> Any:
        self._walked()
        return super().items()

    def values(self) -> Any:
        self._walked()
        return super().values()

    def copy(self) -> _Touches:
        return type(self)(self.log, dict.items(self))

    def update(self, *args: Any, **kwargs: Any) -> None:
        merged = dict(*args, **kwargs)
        self.log.update(merged.keys())
        super().update(merged)

    def __or__(self, other: Any) -> _Touches:
        merged = self.copy()
        merged.update(other)
        return merged

    def __ior__(self, other: Any) -> _Touches:
        self.update(other)
        return self


def _join_program(count: int, branch: bool) -> str:
    """``count`` assignments to distinct names, then (``branch``) an IF whose TEST reads no
    name and whose body writes one of them."""
    body = numbered("  let v{i} = 0;\n", count)
    tail = "  if (true) {\n    v0 = 1;\n  }\n" if branch else ""
    return "// construct\nfunction f() {\n" + body + tail + "}\n"


def _touches(count: int, branch: bool) -> Counter[Any]:
    """Every key the scope pass touched in the State of ``_join_program(count, branch)``."""
    log: Counter[Any] = Counter()
    model = model_of(_join_program(count, branch), "js")
    scope_of(model, state_factory=functools.partial(_Touches, log))
    return log


def _join_cost(count: int) -> Counter[Any]:
    """The key touches the IF adds over ``count`` prior assignments (with it minus without)."""
    plain, branched = _touches(count, False), _touches(count, True)
    assert len(plain) >= count, "the State never held the function's names: the count is vacuous"
    return branched - plain


def test_join_cost_is_delta_sized() -> None:
    """D6, §7.2: with 2,000 assignments before an IF that writes one name, the IF — its
    delta, the join and the apply — touches that one key, exactly as often as it does after
    20 assignments: ``O(|Δa| + |Δb|)``, never ``O(|state|)``."""
    big, small = _join_cost(2_000), _join_cost(20)
    assert len(big) == 1, f"the join touched {len(big)} keys of a 2,000-name state"
    assert (len(big), big.total()) == (len(small), small.total())


# ── walk corrections (LLD §3 W6, W7, W11, W13) and A3 ───────────────────────


@pytest.mark.parametrize(
    ("fixture", "ident", "line", "def_lines", "kind"),
    [
        pytest.param("cwe_22_41", "rest", 5, {3}, "destruct", id="rest_leaf"),
        pytest.param("cwe_22_41", "name", 4, {3}, "destruct", id="shorthand_leaf"),
        pytest.param("cwe_22_27", "params", 3, {2}, "param", id="pattern_param"),
        pytest.param("cwe_22_22", "doc", 3, {2}, "param", id="typed_default_parameter"),
        pytest.param("cwe_22_23", "name", 4, {3}, "param", id="decorated_function"),
        pytest.param("cwe_22_32", "rf", 4, {2}, "import", id="import_pair"),
        pytest.param("cwe_22_33", "rd", 4, {2}, "destruct", id="require_pair"),
    ],
)
def test_walk_correction_fixtures_resolve(
    fixture: str, ident: str, line: int, def_lines: set[int], kind: str
) -> None:
    """W6/W7 on the fixtures they name: each read resolves to its binding's line and kind
    (``DefKind`` of §7.1)."""
    model = fixture_model(fixture)
    assert _resolution(model, _name_on(model, ident, line)) == (def_lines, {ident}, {kind})


@pytest.mark.parametrize(
    ("name", "lang", "line", "bound"),
    [
        pytest.param("pair_leaf", "js", 3, {"v"}, id="js_pair"),
        pytest.param("pair_leaf", "ts", 3, {"v"}, id="ts_pair"),
        pytest.param("rest_leaf", "js", 3, {"a", "rest"}, id="js_rest"),
        pytest.param("rest_leaf", "py", 3, {"a", "rest"}, id="py_rest"),
        pytest.param("import_pair", "js", 2, {"rf"}, id="js_import"),
        pytest.param("import_pair", "py", 2, {"rf"}, id="py_import"),
    ],
)
def test_patterns_bind_their_leaves_never_their_keys(
    name: str, lang: str, line: int, bound: set[str]
) -> None:
    """W6: a PAIR binds its VALUE leaf (``{k: v}`` binds ``v``, ``readFile as rf`` binds
    ``rf``), never its KEY; a shorthand and a rest leaf bind their own names."""
    model = construct_model(name, lang)
    defs = _defs(scope_of(model))
    assert {d.name for d in defs if model.line(d.node) == line} == bound


@pytest.mark.parametrize(
    ("lang", "params"),
    [
        pytest.param("js", {"_", "params"}, id="js_object_pattern"),
        pytest.param("rs", {"a", "params"}, id="rs_tuple_pattern"),
    ],
)
def test_a_pattern_param_binds_each_of_its_names(lang: str, params: set[str]) -> None:
    """W7, A26: a pattern PARAM binds each of its leaves — a Rust tuple pattern
    ``(a, params): (u8, u8)``, a PARAM with several NAME children under Field NAME, binds both."""
    defs = _defs(scope_of(construct_model("pattern_param", lang)))
    assert {d.name for d in defs if d.kind == "param"} == params


_IMPORTS = """\
# construct
from os import path as p
import os.path
sink(p, os)
"""


@pytest.mark.parametrize(
    ("spec", "alias", "symbol"),
    [
        pytest.param("cwe_22_32", "rf", "readFile", id="js_import_specifier"),
        pytest.param("cwe_22_33", "rd", "readFile", id="js_require_destruct"),
        pytest.param(("py", _IMPORTS), "p", "path", id="py_aliased_import"),
    ],
)
def test_import_pair_binds_the_alias_with_the_key_as_symbol(
    spec: Spec, alias: str, symbol: str
) -> None:
    """W6, R-H: an IMPORT PAIR — or a DESTRUCT PAIR whose RHS is a ``require`` CALL — binds
    its alias, which carries the PAIR KEY's last identifier as its symbol; the KEY itself is
    not bound."""
    table = scope_of(subject(spec))
    assert [d.symbol for d in _named(table, alias)] == [symbol]
    assert _named(table, symbol) == []


@pytest.mark.parametrize(
    ("fixture", "symbols"),
    [
        pytest.param("cwe_22_32", {"rf": "readFile"}, id="import_specifier"),
        pytest.param("cwe_22_33", {"rd": "readFile"}, id="require_destruct"),
    ],
)
def test_only_an_import_binding_carries_a_symbol(fixture: str, symbols: dict[str, str]) -> None:
    """A22: ``Def.symbol`` is the R-H symbol of an import binding (an IMPORT, or a DESTRUCT
    leaf of a ``require`` CALL — R-H) and None for every other Def: the function, its
    parameter."""
    defs = _defs(scope_of(fixture_model(fixture)))
    assert {d.name: d.symbol for d in defs if d.symbol is not None} == symbols
    assert {d.name for d in defs if d.symbol is None} >= {"handler", "req"}


def test_a_bare_dotted_import_binds_its_first_segment() -> None:
    """§7.2: ``import os.path`` binds ``os`` (an ``import`` Def), not ``path``."""
    model = program("py", _IMPORTS)
    table = scope_of(model)
    assert {(model.line(d.node), d.kind) for d in _named(table, "os")} == {(3, "import")}


_TYPED = """\
# construct
def f(p: Upload, q: Upload = make(), r=make()):
    sink(p, q, r)
"""


@pytest.mark.parametrize(
    ("spec", "params", "annotations"),
    [
        pytest.param(("py", _TYPED), {"p", "q", "r"}, {"Upload", "make"}, id="typed_parameters"),
        pytest.param("cwe_22_22", {"doc"}, {"UploadFile", "File"}, id="cwe_22_22"),
    ],
)
def test_typed_parameters_bind_their_name_never_the_annotation(
    spec: Spec, params: set[str], annotations: set[str]
) -> None:
    """W7: Python ``typed_parameter`` (its first NAME), ``typed_default_parameter`` and
    ``default_parameter`` (their Field NAME) bind the parameter's name; the annotation and
    the default value bind nothing."""
    defs = _defs(scope_of(subject(spec)))
    assert {d.name for d in defs if d.kind == "param"} == params
    assert not {d.name for d in defs} & annotations


_STACKED = """\
# construct
@a
def f():
    pass
x = 1
@b
@c
def g():
    pass
@d
class K:
    def m(self):
        pass
"""


@pytest.mark.parametrize(
    ("fn", "lines"),
    [
        pytest.param("f", {2}, id="one"),
        pytest.param("g", {6, 7}, id="stacked"),
        pytest.param("m", set(), id="class_decorator_is_not_the_methods"),
    ],
)
def test_decorators_are_the_run_right_before_the_function(fn: str, lines: set[int]) -> None:
    """W7: ``decorators(x)`` holds the DECORATORs that IMMEDIATELY precede ``x`` among its
    siblings — a stacked run, never one separated from it by a statement, never its
    enclosing class's."""
    model = program("py", _STACKED)
    assert {model.line(i) for i in _decorators(model, _function_named(model, fn))} == lines


@pytest.mark.parametrize("lang", ["js", "ts", "py", "java", "rs", "php"])
def test_decorators_precede_or_annotate_their_function(lang: str) -> None:
    """W7 (``cwe_22_23``): ``decorators(show)`` finds the line-2 decorator, whether it
    precedes the FUNCTION as a sibling (Python, Rust, TS) or hangs under it as a child
    (JS, Java's ``modifiers``, PHP's attribute group); a nested DECORATOR is not one."""
    model = construct_model("decorated_param", lang)
    outer = node_at(model, Kind.DECORATOR, line=2)
    assert _decorators(model, _function_named(model, "show")) == {outer}


def test_decorators_on_cwe_22_23() -> None:
    """W7: the route decorator of ``cwe_22_23`` precedes ``show`` (``decorated_definition``
    is transparent, so the two are siblings)."""
    model = fixture_model("cwe_22_23")
    outer = node_at(model, Kind.DECORATOR, line=2)
    assert _decorators(model, _function_named(model, "show")) == {outer}


_MULTI = """\
package main
func f(x string, y string) {
    a, b := x, y
    req, err := g()
    sink(a, b, req, err)
}
"""


def test_multi_target_binds_pairwise_or_the_whole_rhs() -> None:
    """W11: ``a, b := x, y`` binds pairwise (``a`` <- ``x``, ``b`` <- ``y``); ``req, err :=
    f()`` binds both targets to the one RHS value."""
    model = program("go", _MULTI)
    table = scope_of(model)
    call = node_at(model, Kind.CALL, line=4)
    values = {name: [d.value for d in _named(table, name)] for name in ("a", "b", "req", "err")}
    assert values == {
        "a": [_name_on(model, "x", 3)], "b": [_name_on(model, "y", 3)],
        "req": [call], "err": [call],
    }


def _assert_global_statement_is_no_def(model: FileModel, table: ScopeTable) -> None:
    """``cwe_22_15``'s ``global PATH`` statement (line 6) is no Def, and no Def is of a
    ``global`` kind."""
    assert [d.name for d in _defs(table) if model.line(d.node) == 6] == []
    assert "global" not in {d.kind for d in _defs(table)}


def test_global_write_is_a_module_def() -> None:
    """W13 (``cwe_22_15``), A24: ``set_doc``'s write under ``global PATH`` is an ``assign`` Def
    of the module scope, so ``read_doc``'s free ``PATH`` reads it joined with the module-level
    Def. The ``global PATH`` statement itself is no Def, and no Def is of a ``global`` kind."""
    model = fixture_model("cwe_22_15")
    table = scope_of(model)
    defs = _reaching(table, _name_on(model, "PATH", 11))
    assert _lines(model, defs) == {2, 7}
    assert (len({d.scope for d in defs}), {d.kind for d in defs}) == (1, {"assign"})
    _assert_global_statement_is_no_def(model, table)


_GO_RESULTS = """\
package main
func (s *Server) open(p string) (data string, err error) {
    sink(s, p, data, err)
}
"""


def test_params_bind_only_from_the_function_params() -> None:
    """A3: parameters bind ONLY from the ARGS under Field PARAMS of a FUNCTION — a Go
    method's receiver list included — and the result ``parameter_list`` (a second ARGS,
    Field NONE) binds nothing."""
    model = program("go", _GO_RESULTS)
    table = scope_of(model)
    assert {d.name for d in _defs(table) if d.kind == "param"} == {"s", "p"}
    reads = {name: _lines(model, _reaching(table, _name_on(model, name, 3)))
             for name in ("s", "p", "data", "err")}
    assert reads == {"s": {2}, "p": {2}, "data": set(), "err": set()}


_PROTOTYPES = """\
// construct
void g(char *docPath) {
    std::string helper(Config);
    std::ifstream other(docPath, Mode);
    std::ifstream in(docPath);
    sink(helper, other, in);
}
"""


def test_rx_prototype_naming_no_local_def_is_dropped() -> None:
    """C2 (R-X), confirmed: a vexing-parse declaration is kept as a stack-constructor CALL
    only when EVERY parameter NAME resolves to an in-scope local/param Def; otherwise it is
    a local prototype and contributes nothing — no Def of its name."""
    model = program("cpp", _PROTOTYPES)
    table = scope_of(model)
    assert (_named(table, "helper"), _named(table, "other")) == ([], [])
    assert _lines(model, _named(table, "in")) == {5}
    assert _lines(model, _reaching(table, _name_on(model, "docPath", 5))) == {2}


def test_rx_vexing_parse_reads_the_local_def() -> None:
    """C2 (R-X) on ``cwe_22_cpp_3``: ``std::ifstream in(docPath);`` declares ``in`` and its
    parameter NAME reads the local ``docPath`` of line 7 — an ARGS under an ASSIGN binds no
    parameter (A3)."""
    model = fixture_model("cwe_22_cpp_3")
    table = scope_of(model)
    assert _lines(model, _named(table, "in")) == {8}
    assert _resolution(model, _name_on(model, "docPath", 8)) == ({7}, {"docPath"}, {"assign"})
