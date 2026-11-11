"""Feature 0104: what the 0104 unit modules share. Not a test module.

Each new production name (a ``roles`` table, a ``flow`` function, a ``Flow`` field) is read
here through ``getattr`` with a default, so a module that names one COLLECTS before it exists
and each test fails on its own (plan 0.7): ``layer_name`` / ``field_of`` answer ``MISSING``,
``required`` fails the test that needs the name. The rows are built the way a head builds them:
``consume.family_spans`` into a real ``AuditContext``, then ``consume.flow_to_finding``. A case
table is a list of ``(id, *values)`` tuples, parametrized by ``cases``.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable, Sequence
from typing import Any

import pytest

from tests.unit.ast._analysis import (
    DECIDED_PATH,
    Spec,
    _layer,
    consume_mod,
    finding_of,
    fresh_context,
    stub_rule,
    subject,
)

# R-T's role, as a row names it (``validation.flow.heuristic``) and an origin carries it.
HINT = "param_hint"
# The file a row is built for: a path under a root no test reads from disk.
ROOT = DECIDED_PATH.parent
MISSING: Any = object()


def cases(table: Iterable[Sequence[Any]]) -> list[Any]:
    """``pytest.param(*values, id=case_id)`` for each ``(case_id, *values)`` of ``table``."""
    return [pytest.param(*case[1:], id=case[0]) for case in table]


def layer_name(module: str, name: str) -> Any:
    """``shared.ast.<module>.<name>``, or ``MISSING`` while it does not exist."""
    return getattr(_layer(module), name, MISSING)


def required(module: str, name: str) -> Any:
    """``layer_name``, failing the test that needs it while it does not exist."""
    found = layer_name(module, name)
    assert found is not MISSING, f"shared.ast.{module}.{name} does not exist"
    return found


def sink_table(name: str) -> Any:
    """A table 0104 adds to ``roles/sinks.py`` (HT-20): one object, which ``roles.sinks`` and
    ``roles`` both hold and both export."""
    table = required("roles.sinks", name)
    exported = name in layer_name("roles.sinks", "__all__") and name in _layer("roles").__all__
    assert exported and layer_name("roles", name) is table, f"roles does not export {name}"
    return table


def field_of(flow: Any, name: str) -> Any:
    """A ``Flow`` field 0104 adds, or ``MISSING`` on a ``Flow`` that has none."""
    return getattr(flow, name, MISSING)


def family_rule(family: str) -> Any:
    """The stand-in rule of ``family``; the command rule carries D25's hook, as cwe ships it."""
    hook = consume_mod().command_param if family == "command" else None
    return stub_rule(family, heuristic=hook)


@functools.cache
def spans_of(spec: Spec, family: str) -> dict[int, Any]:
    """``consume.family_spans`` of ``spec``'s model: every line of each reported sink span ->
    its flow, as the head maps them. Once per (program, family): a model and its flows are
    immutable."""
    ctx = fresh_context(ROOT)
    return dict(consume_mod().family_spans(subject(spec), family_rule(family), ctx, ROOT / "f"))


def flow_blob(spec: Spec, family: str, line: int) -> dict[str, Any]:
    """``validation.flow`` of the row the head emits at ``line`` (its sink line); an
    AssertionError when it emits none there."""
    flow = spans_of(spec, family).get(line)
    assert flow is not None and flow.sink_line == line, f"no {family} row at line {line}"
    row = finding_of(flow, family_rule(family), ROOT / "f", subject(spec).nl_lines)
    return row["validation"]["flow"]
