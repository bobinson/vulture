"""Feature 0104: what the 0104 unit modules share. Not a test module.

Each new production name (a ``roles`` table, a ``flow`` function, a ``Flow`` field) is read
here through ``getattr`` with a default, so a module that names one COLLECTS before it exists
and each test fails on its own (plan 0.7): ``layer_name`` / ``field_of`` answer ``MISSING``,
``required`` fails the test that needs the name. The rows are built the way a head builds them:
``consume.family_spans`` into a real ``AuditContext``, then ``consume.flow_to_finding``. A case
table is a list of ``(id, *values)`` tuples, parametrized by ``cases``.

The hint-group modules (``test_0104_hint_group_fold``, ``test_0104_fold_deterministic``) share
the member rows of one stamped group and the fold and validate stage they go through. The
linear-cost modules (``test_0104_uses_linear``, ``test_0104_coverage_pins``) share a work
count: a ``sys.setprofile`` hook counts, never times, what a call costs (``_profiled``), and
``_growth`` compares two sizes.
"""

from __future__ import annotations

import copy
import functools
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, FrameType
from typing import Any

import pytest

from shared import audit_runner
from tests.unit.ast._analysis import (
    DECIDED_PATH,
    Spec,
    _layer,
    consume_mod,
    external,
    finding_of,
    flow_with,
    fresh_context,
    stub_rule,
    subject,
)
from tests.unit.ast._support import write

# R-T's role, as a row names it (``validation.flow.heuristic``) and an origin carries it.
HINT = "param_hint"
# The label of a bare probe the hint alone reaches, which the probe rule declines.
PROBE = f"probe:{HINT}"
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


# ── one stamped hint group's rows, the fold and the validate stage (A2, D-S (2)) ──

Rows = list[dict[str, Any]]
# Keys a row at an index of the rows carries beside its own (``_carrying``).
Extras = Mapping[int, Mapping[str, Any]]
_PATH = ROOT / "app" / "store.py"
_NL = ["x"] * 24
_SINKS = (3, 7, 10)


def _hint(line: int, family: str = "path", *origins: Any) -> Any:
    """A flow sinking at ``line`` whose origins are ``origins``, the hint alone by default."""
    return flow_with(family, *(origins or (external(HINT),)), sink_line=line)


def _row(
    line: int, family: str = "path", path: Path = _PATH, nl_lines: Sequence[str] = _NL
) -> dict[str, Any]:
    """The row the head appends for a hint-only flow sinking at ``line``."""
    return finding_of(_hint(line, family), family_rule(family), path, nl_lines)


def _stamped(rows: Rows, sinks: tuple[int, ...]) -> Rows:
    """``rows``, each stamped a member of the group of ``sinks``, as the head stamps it."""
    for row in rows:
        required("consume", "stamp_member")(row, sinks)
    return rows


def _members(family: str = "path", path: Path = _PATH, sinks: tuple[int, ...] = _SINKS) -> Rows:
    """One group's member rows, stamped."""
    return _stamped([_row(line, family, path) for line in sinks], sinks)


def _carrying(rows: Rows, extras: Extras) -> Rows:
    """``rows``, the row at each index of ``extras`` carrying a copy of its keys."""
    for index, keys in extras.items():
        rows[index].update(copy.deepcopy(dict(keys)))
    return rows


def _other(line: int, category: str, path: Path | str = _PATH) -> dict[str, Any]:
    """Another check's row at ``line``, of no provenance: a deterministic row (D-S (2))."""
    return {"file_path": str(path), "line_start": line, "line_end": line,
            "category": category, "check_id": f"other.{category}", "title": "Other",
            "severity": "high", "description": "Other"}


def _flow_sinks(row: dict[str, Any]) -> Any:
    return ((row.get("validation") or {}).get("flow") or {}).get("sinks")


def _private(rows: Rows, prefix: str = "_hint") -> list[str]:
    """Every key of ``rows`` starting ``prefix`` (a group stamp by default), sorted."""
    return sorted(key for row in rows for key in row if key.startswith(prefix))


def _fold(findings: Rows) -> Rows:
    return required("consume", "fold_hint_groups")(findings, str)


# The audited file of the validate stage: three path sinks, a marker line in the second.
_FILE = (
    "import os\n\n"
    "def load(file_path):\n    return open(file_path)\n\n"
    "def save(file_path):\n    {marker}\n    return open(file_path, 'w')\n\n"
    "def drop(file_path):\n    os.remove(file_path)\n"
)
_FILE_SINKS = (4, 8, 11)


def _written(root: Path, marker: str) -> Path:
    return write(root / "app" / "store.py", _FILE.format(marker=marker))


def _file_rows(path: Path) -> Rows:
    """The head's rows at the file's three sink lines, unstamped."""
    nl_lines = path.read_text(encoding="utf-8").split("\n")
    return [_row(n, path=path, nl_lines=nl_lines) for n in _FILE_SINKS]


def _file_members(path: Path) -> Rows:
    return _stamped(_file_rows(path), _FILE_SINKS)


def _finalized(rows: Rows, root: Path) -> Rows:
    return audit_runner.finalize_skill_findings(rows, str(root), "run-0104")


# ── work, counted (WS-C, WS-D rev 4: linear in the file) ──

# The most a linear cost may grow by when its input doubles; a quadratic one grows by 4.
LINEAR = 2.5
# The events of a ``sys.setprofile`` hook that are a unit of work: a Python frame entered, a C
# function called from Python bytecode.
_STEPS = frozenset({"call", "c_call"})


@dataclass
class _Work:
    """What a profiled call cost (``_profiled``)."""

    steps: int = 0  # frames entered and C functions called: all interpreted work
    frames: Counter[CodeType] = field(default_factory=Counter)  # frames entered, by code

    def hook(self, frame: FrameType, event: str, _arg: object) -> None:
        """The ``sys.setprofile`` hook: one step per ``_STEPS`` event; a frame entered is
        also counted under its code."""
        if event == "call":
            self.frames[frame.f_code] += 1
        self.steps += event in _STEPS


def _profiled(run: Callable[[], object]) -> _Work:
    """What ``run()`` costs, counted by ``_Work.hook``; the previous hook is restored after.
    Pass a bound method (``model_of(...).analysis``) so building its receiver is not counted."""
    work, previous = _Work(), sys.getprofile()
    sys.setprofile(work.hook)
    try:
        run()
    finally:
        sys.setprofile(previous)
    return work


def _growth(measure: Callable[[int], _Work], count: Callable[[_Work], int], size: int) -> float:
    """How many times ``count`` of ``measure`` grows when its input doubles from ``size``."""
    return count(measure(2 * size)) / max(count(measure(size)), 1)
