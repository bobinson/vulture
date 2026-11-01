"""Feature 0102, A39 (1) (LLD §7.2, §8.7): the scope table the flow pass reads.

``ScopeTable.on_demand(model)`` runs the MODULE scope up front, and with it every function
whose pass can leave a fact outside its own scope; any other function's scope runs when a read
in it, or a parameter of it, is first asked — after the scopes enclosing it, and only as far as
the top-level statement holding the read. ``build`` runs every scope. Pinned here:

* every answer is ``build``'s: the Defs reaching each node's read (``Def`` equality leaves out
  ``position``, which differs: an on-demand table numbers its Defs in the order its scopes
  ran), whether the read is capped, each node's parameter names, the tallies, constructors and
  prototypes — over every ``ast_v1`` fixture (every v1 profile, ``global`` included), asked
  last node first (a nested function before the scopes enclosing it) and in document order
  (each function run on statement by statement);
* a function no question reaches is never run: none of its Defs is in the table's ``defs``;
* a function's statements after the last one a question reaches never run;
* a ``global`` write is a MODULE Def a read in any function may reach, so its function runs
  before any question;
* a branch past ``MAX_BRANCH_DEPTH`` is tallied per file (A28 (3)) though no question reaches
  its function.

The flow pass builds its table with ``call_writes`` (R-J, R-W), so both tables here do too.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest

from shared.ast import FileModel, get_model, limits
from shared.ast.kinds import Kind
from shared.ast.profile import profile_for
from tests.unit.ast._analysis import (
    external,
    fixture_names,
    fixture_path,
    flow_at_call,
    nested,
    node_at,
    program,
    scope_mod,
    scope_of,
)

if TYPE_CHECKING:
    from shared.ast.scope import ScopeTable

pytestmark = pytest.mark.usefixtures("real_pool")


def _tables(model: FileModel) -> tuple[ScopeTable, ScopeTable]:
    """``build``'s table and a fresh on-demand one, both with the flow pass's hook."""
    from shared.ast._calls import call_writes

    on_demand = scope_mod().ScopeTable.on_demand(model, call_writes=call_writes)
    return scope_of(model, call_writes=call_writes), on_demand


def _answers(table: ScopeTable, nodes: range) -> list[tuple[Any, ...]]:
    """Each node's answers, asked in ``nodes``' order: capped first (no read asked yet), then
    the Defs reaching it, then its parameter names."""
    return [(table.depth_capped(n), table.resolve(n), table.param_names(n)) for n in nodes]


def _facts(table: ScopeTable) -> tuple[Any, ...]:
    """What a table holds per file: its tallies, constructors and prototypes."""
    return dict(table.tallies), dict(table.constructors), table.prototypes


# Every ``ast_v1`` fixture of a v1 language (the one Ruby file has no profile).
_FIXTURES = [name for name in fixture_names() if profile_for(fixture_path(name))]

# The orders a table is asked in, each a node range for a node count: last node first (a
# nested function before the scopes enclosing it), and document order (each function run on
# statement by statement).
_ORDERS: dict[str, Callable[[int], range]] = {
    "last-first": lambda count: range(count - 1, -1, -1),
    "document-order": range,
}
_IN_EACH_ORDER = pytest.mark.parametrize("order", list(_ORDERS.values()), ids=list(_ORDERS))


def _served(name: str) -> FileModel:
    """The model the layer serves for a fixture (``get_model``, the production lookup); a
    fixture it serves none for (a depth bomb: ``too_deep``) is regex-owned and skipped."""
    model = get_model(fixture_path(name))
    if model is None:
        pytest.skip(f"{name}: no model, regex-owned (D10)")
    return model


@_IN_EACH_ORDER
@pytest.mark.parametrize("name", _FIXTURES)
def test_on_demand_answers_as_build(name: str, order: Callable[[int], range]) -> None:
    """Every answer an on-demand table gives is ``build``'s, whatever order it is asked in."""
    model = _served(name)
    built, on_demand = _tables(model)
    nodes = order(model.node_count)

    assert _answers(on_demand, nodes) == _answers(built, nodes)
    assert _facts(on_demand) == _facts(built)


# Programs whose answers depend on what a paused scope keeps: a member path bound before a
# pause and unbound after it (W8), and a parameter default read just before the body (W7).
_PAUSE_PROGRAMS = {
    "member-path": """
function handle(req) {
  let o = {};
  o.f = req.query.f;
  o = {};
  return o.f;
}
""",
    "default-before-body": """
const base = "/srv";
function handle(req, root = base) {
  return root;
}
""",
}


@_IN_EACH_ORDER
@pytest.mark.parametrize("program_id", sorted(_PAUSE_PROGRAMS))
def test_a_paused_scope_answers_as_build(program_id: str, order: Callable[[int], range]) -> None:
    """What a scope holds when it pauses — its bound member paths, its parameters with
    their defaults read — is what it resumes with."""
    model = program("js", _PAUSE_PROGRAMS[program_id])
    built, on_demand = _tables(model)
    nodes = order(model.node_count)

    assert _answers(on_demand, nodes) == _answers(built, nodes)


_TWO_FUNCTIONS = """
function helper(a) {
  const b = a + 1;
  return b;
}
function handle(req) {
  const p = req.query.p;
  return p;
}
"""


def _scopes(table: ScopeTable) -> set[int]:
    """The scopes the table's Defs belong to (``0``: the MODULE)."""
    return {found.scope for found in table.defs}


def _names_in(table: ScopeTable, scope: int) -> set[str]:
    """The names the table's Defs of ``scope`` bind."""
    return {found.name for found in table.defs if found.scope == scope}


def test_a_function_no_question_reaches_never_runs() -> None:
    """Before any question an on-demand table holds the MODULE's Defs only; a read in
    ``handle`` runs ``handle``'s scope, never ``helper``'s."""
    model = program("js", _TWO_FUNCTIONS)
    _, on_demand = _tables(model)
    handle = node_at(model, Kind.FUNCTION, line=5)
    before = _scopes(on_demand)

    on_demand.resolve(node_at(model, Kind.NAME, text="p", line=7))

    assert (before, _scopes(on_demand)) == ({0}, {0, handle})


_FOUR_STATEMENTS = """
function handle(req) {
  const p = req.query.p;
  const q = p + "x";
  const r = q + "y";
  return r;
}
"""


def test_statements_after_the_last_question_never_run() -> None:
    """A read in ``handle``'s first statement runs its scope that far (its parameter and
    ``p`` bound, not ``q`` or ``r``); a read in the third statement runs it on to there."""
    model = program("js", _FOUR_STATEMENTS)
    _, on_demand = _tables(model)
    handle = node_at(model, Kind.FUNCTION, line=1)

    on_demand.resolve(node_at(model, Kind.NAME, text="req", line=2))
    first = _names_in(on_demand, handle)
    on_demand.resolve(node_at(model, Kind.NAME, text="q", line=4))

    assert (first, _names_in(on_demand, handle)) == ({"req", "p"}, {"req", "p", "q", "r"})


_GLOBAL_WRITE = """
target = "/srv/data"

def configure(request):
    global target
    target = request.args["path"]

def serve():
    return open(target)
"""


def test_a_global_write_reaches_a_reader_asked_first() -> None:
    """A24, W13: ``configure``'s write under ``global`` is a MODULE Def, so the free read in
    ``serve`` — asked before anything of ``configure`` — reaches it as ``build``'s does, and
    the path flow carries the request value."""
    model = program("py", _GLOBAL_WRITE)
    built, on_demand = _tables(model)
    read = node_at(model, Kind.NAME, text="target", line=8)

    assert on_demand.resolve(read) == built.resolve(read)
    assert external("request") in flow_at_call(model, "path", "open").origins


def _deep_branches(depth: int) -> str:
    """A sink-free function whose innermost statement sits ``depth`` IFs deep."""
    return "function deep(x) {\n" + nested("if (x) {", "}", depth, "x = 1;") + "\n}\n"


def test_a_branch_past_the_cap_is_tallied_with_no_question() -> None:
    """A28 (3), A32: no question reaches ``deep``, yet its branches past ``MAX_BRANCH_DEPTH``
    are in the on-demand table's tallies as in ``build``'s."""
    model = program("js", _deep_branches(limits.MAX_BRANCH_DEPTH + 2))
    built, on_demand = _tables(model)

    assert dict(on_demand.tallies) == dict(built.tallies) == {"branch_depth": 2}
