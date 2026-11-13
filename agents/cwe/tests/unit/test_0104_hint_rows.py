"""Feature 0104 WS-A1 on the ``ast_v1`` corpus (LLD §4.1, HT-7, HT-9; A48 O1).

The corpus rows the two migrated skills emit, read as a consumer reads them:

* the pins whose only external origin is the parameter-name hint (``cwe_22_37``,
  ``cwe_22_78``, ``cwe_22_79``) carry ``validation.flow.heuristic = "param_hint"``;
* no labelled row has, in the ``decide`` trace, a reported flow of its own family at its sink
  line with any other external origin -- the label is decided per family (O1: a CWE-78 request
  flow on the line of a CWE-22 hint row does not unlabel the CWE-22 row);
* D25 rows (no external origin; ``unknown(param)`` / ``unknown(argv)``) keep ``command_param``.

RED until A1 lands: the label rows (no row carries ``param_hint`` before it). Green today, and
kept: the D25 token.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests import _ast_v1

HINT = "param_hint"
PINS = ("cwe_22_37.js", "cwe_22_78.ts", "cwe_22_79.py")
FAMILY = {"CWE-22": "path", "CWE-78": "command", "CWE-918": "request"}
Trace = list[tuple[str, str, int, tuple[str, ...], str]]


def _heuristic(row: _ast_v1.Finding) -> str | None:
    return row.get("validation", {}).get("flow", {}).get("heuristic")


def _ast_rows_of(rows: list[_ast_v1.Finding], name: str) -> list[_ast_v1.Finding]:
    return [r for r in _ast_v1.ast_rows(rows) if Path(r["file_path"]).name == name]


@pytest.mark.parametrize("name", PINS)
def test_hint_pin_rows_carry_the_label(ast_v1_rows: list[_ast_v1.Finding], name: str) -> None:
    rows = _ast_rows_of(ast_v1_rows, name)
    assert rows, f"no AST row on {name}"
    assert [_heuristic(r) for r in rows] == [HINT] * len(rows)


def _external(origins: list[str] | tuple[str, ...], but: str = "") -> bool:
    """Some origin is external (other than ``external:<but>``)."""
    return any(o.startswith("external:") and o != f"external:{but}" for o in origins)


def _d25(row: _ast_v1.Finding) -> bool:
    """A CWE-78 row with no external origin: D25's."""
    return row["category"] == "CWE-78" and not _external(row["validation"]["flow"]["origins"])


def test_command_param_rows_keep_their_token(ast_v1_rows: list[_ast_v1.Finding]) -> None:
    """D25: a CWE-78 row with no external origin is reported on ``command_param`` only."""
    rows = list(filter(_d25, _ast_v1.ast_rows(ast_v1_rows)))
    assert {_heuristic(r) for r in rows} == {"command_param"}, "no D25 row, or another token"


def _recording(decide: Any, trace: Trace) -> Any:
    """``flow.decide``, recording (file name, family, sink line, origins, verdict) per call."""
    from shared.ast.declines import render_origins

    def recorded(flow: Any, rule: Any, ctx: Any, **kwargs: Any) -> str:
        verdict = decide(flow, rule, ctx, **kwargs)
        trace.append((Path(str(kwargs["path"])).name, flow.family, flow.sink_line,
                       tuple(render_origins(flow.origins)), verdict))
        return verdict

    return recorded


def _labelled(row: _ast_v1.Finding) -> bool:
    return _heuristic(row) == HINT


def _key(row: _ast_v1.Finding) -> tuple[str, str, int]:
    """(file name, family, sink line) of a row, as the trace names a flow."""
    return Path(row["file_path"]).name, FAMILY[row["category"]], row["line_start"]


@pytest.fixture(scope="module")
def traced(
    request: pytest.FixtureRequest, ast_v1_rows: list[_ast_v1.Finding],
) -> Iterator[tuple[list[_ast_v1.Finding], Trace]]:
    """The corpus files holding a labelled row (the flow pass is single-file), scanned again
    with ``decide`` recorded."""
    from shared.ast import flow

    names = sorted({_key(r)[0] for r in _ast_v1.ast_rows(ast_v1_rows) if _labelled(r)})
    trace: Trace = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(flow, "decide", _recording(flow.decide, trace))
        rows = _ast_v1.migrated_rows(_ast_v1.stage(request, names))
    yield rows, trace


def _reports(row: _ast_v1.Finding, trace: Trace) -> list[tuple[str, ...]]:
    """The origins of each flow the trace reports at the row's sink line, in its family."""
    return [t[3] for t in trace if (*t[:3], t[4]) == (*_key(row), "report")]


def _misread(row: _ast_v1.Finding, trace: Trace) -> bool:
    """The row is labelled, yet the trace shows no hint flow reported at its line (the spy saw
    nothing), or a flow there with another external origin."""
    reports = _reports(row, trace)
    own = any(f"external:{HINT}" in origins for origins in reports)
    return not own or any(_external(origins, but=HINT) for origins in reports)


def test_no_labelled_row_shares_its_line_with_a_non_hint_flow(
    traced: tuple[list[_ast_v1.Finding], Trace], ast_v1_rows: list[_ast_v1.Finding],
) -> None:
    rows, trace = traced
    labelled = list(filter(_labelled, _ast_v1.ast_rows(rows)))
    session = sorted(map(_key, filter(_labelled, _ast_v1.ast_rows(ast_v1_rows))))
    assert sorted(map(_key, labelled)) == session and len(session) >= len(PINS), session
    assert [_key(r) for r in labelled if _misread(r, trace)] == []
