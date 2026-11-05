"""Feature 0102, A42 (2): PHP's calls in disguise ship their operand as positional ARGS.

LLD §6.3's synthetic-call row: ``include``/``require``, their ``_once`` forms and the
backtick shell command are calls the grammar spells without a call node. The PHP profile
names each in ``synthetic_calls`` with its glued callee key; the worker ships the node as a
CALL whose CALLEE is a NAME carrying that key and whose ARGS container is the node itself, so
the operand (a backtick command's interpolations) is the call's positional argument and the
flow pass has a sink argument to follow. An empty key (Rust ``macro_invocation``) is no
disguise: the macro's own name is its CALLEE.

Every model is built by a real worker through the boundary validator (``parse_model``); the
two ``ast_v1`` fixtures the ruling names are read by path, read-only.
"""

from __future__ import annotations

import pytest

from shared.ast import FileModel
from shared.ast._records import external
from shared.ast.kinds import Kind
from shared.ast.profile import PROFILES
from tests.unit.ast._support import fixture_model, only_call, parse_model

pytestmark = pytest.mark.usefixtures("real_pool")

type _Shipped = list[tuple[Kind, str | None]]

# Each keyed PHP type -> one statement holding it, its glued key, and the arguments its CALL
# ships, as (kind, text): a NAME carries its identifier, the `.` BINOP no text.
_DISGUISED: dict[str, tuple[str, str, _Shipped]] = {
    "include_expression": ("include $page;", "include", [(Kind.NAME, "page")]),
    "include_once_expression": ("include_once($page);", "include", [(Kind.NAME, "page")]),
    "require_expression": ("require __DIR__ . $page;", "require", [(Kind.BINOP, None)]),
    "require_once_expression": ("require_once $page;", "require", [(Kind.NAME, "page")]),
    "shell_command_expression": (
        "$out = `cp $src {$dst}`;", "shellexec", [(Kind.NAME, "src"), (Kind.NAME, "dst")],
    ),
}

# The fixtures A42 (2) names -> the family, line and key of their one candidate.
_RULING_FIXTURES = {
    "cwe_22_php_2.php": ("path", 4, "include"),  # include $full;
    "cwe_78_php_2.php": ("command", 3, "shellexec"),  # echo `ls -l $dir`;
}


def _shipped_args(m: FileModel, call: int) -> _Shipped:
    """The CALL's positional arguments as (kind, text)."""
    return [(m.kind(arg), m.ident(arg)) for arg in m.args(call)]


def test_the_cases_are_every_keyed_php_type() -> None:
    """The PHP profile's ``synthetic_calls`` is the one table the worker reads (D19): the cases
    below cover each of its types, with its key."""
    keys = {node_type: case[1] for node_type, case in _DISGUISED.items()}
    assert dict(PROFILES["php"].synthetic_calls) == keys


@pytest.mark.parametrize("node_type", sorted(_DISGUISED))
def test_a_call_in_disguise_ships_its_key_and_its_operand(node_type: str) -> None:
    """§6.3: the node is a CALL whose CALLEE is a NAME carrying the glued key and whose ARGS
    are the operand the node holds — a parenthesised operand unwrapped, a concatenation one
    argument, every interpolation of a backtick command one argument each."""
    source, key, shipped = _DISGUISED[node_type]
    m = parse_model(f"<?php\n{source}\n", "php")
    call = only_call(m)
    callee = m.callee(call)
    assert (m.kind(callee), m.ident(callee)) == (Kind.NAME, key)
    assert _shipped_args(m, call) == shipped


@pytest.mark.parametrize("language", sorted(PROFILES))
def test_every_synthetic_call_type_has_its_own_node_map_row(language: str) -> None:
    """``LanguageProfile``: a ``synthetic_calls`` type also needs its plain ``node_map`` row —
    the worker reads a keyed type's key off that row, and a type with none ships unlisted, its
    key dropped without an error (A42 (2))."""
    profile = PROFILES[language]
    plain = {key for key in profile.node_map if isinstance(key, str)}
    assert set(profile.synthetic_calls) <= plain


def test_an_empty_key_is_no_disguise() -> None:
    """Rust's ``macro_invocation`` is keyed ``""``: the CALLEE is the macro's own name, from
    its ``macro`` field, and its ``token_tree`` stays the ARGS container."""
    assert dict(PROFILES["rust"].synthetic_calls) == {"macro_invocation": ""}
    m = parse_model('fn f(x: i32) { println!("{}", x); }\n', "rust")
    call = only_call(m)
    assert m.ident(m.callee(call)) == "println"
    assert _shipped_args(m, call) == [(Kind.LITERAL, None), (Kind.NAME, "x")]


@pytest.mark.parametrize("name", sorted(_RULING_FIXTURES))
def test_the_ruling_fixtures_have_a_request_candidate(name: str) -> None:
    """A42 (2): ``include $full;`` and the backtick command are sinks the flow pass reaches:
    each fixture's one candidate of its family is the synthetic CALL, keyed by the profile's
    key, and the request superglobal reaches its argument."""
    family, line, key = _RULING_FIXTURES[name]
    m, _ = fixture_model(name)
    (flow,) = m.analysis().candidates(family)
    assert (m.line(flow.sink), flow.sink_key) == (line, key)
    assert external("request") in flow.origins
