"""Feature 0104 WS-A2 (LLD §4.1 as ruled by A66; D-O (1)): a file's hint-only rows of one rule
reported as ONE row -- the candidate group, the fold, the validate stage's re-check.

Rule. ``consume.hint_groups(spans, excluded)`` is one file's candidate group for one rule: the
sink lines of the rows the head appends, less ``excluded`` (a line a child replaces or the
head never reads), sorted, the anchor's -- the lowest -- first; only when there are two to
``limits.MAX_GROUP_SINKS`` of them and each is hint-only (S1, S3, S4), else ``()``. The head
stamps each member's row (``stamp_member``). ``fold_hint_groups`` (run by
``audit_runner._fold_hint_groups`` after the code window, before validate) puts the group row
(``group_to_finding``: the anchor's row, ``validation.flow.sinks``, a description naming the
count of sinks and never an identifier) in the anchor row's place and drops the other
members' rows -- unless the group is refused and every row is kept (R1, R2): a member's row
missing or out of order; one the line collapse kept for another (``collapsed_from``); another
row of no LLM-family provenance at a member's line that one line reconciles with it -- of the
backend's dedup family (``finding_collapse._DEDUP_FAMILIES``, pinned below to
``backend/internal/cwe/taxonomy.go``) or a ChildOf ancestor or descendant -- its path compared
as the dedup compares it. An LLM-family row, or a member's ``merged_llm``, never refuses (D-S
(2); ``test_0104_fold_deterministic.py``). A fold that raises keeps every row. The validate
stage keeps a group row whole only when every member's L1 result on its own reads equals the
anchor's and no other finding shares its L2 rollup key; else the members' rows replace it, each
with its own result (R5). No ``_hint_*`` key reaches a finalized row.

Green since A2 landed: every test here names an A2 function or constant.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from shared import audit_runner
from shared.tools import finding_collapse
from tests.unit.ast._0104 import (
    _FILE_SINKS,
    _PATH,
    _SINKS,
    HINT,
    ROOT,
    Rows,
    _carrying,
    _file_members,
    _file_rows,
    _finalized,
    _flow_sinks,
    _fold,
    _hint,
    _members,
    _other,
    _private,
    _row,
    _written,
    cases,
    family_rule,
    required,
    spans_of,
)
from tests.unit.ast._analysis import TOKEN, Spec, external, finding_of, subject, unknown

_TAXONOMY = Path(__file__).resolve().parents[5] / "backend" / "internal" / "cwe" / "taxonomy.go"
_GO_FAMILIES = ("path-traversal", "os-command-injection")


def _api(module: ModuleType, name: str) -> Any:
    """``module.name``, failing the test that needs it while it does not exist."""
    found = getattr(module, name, None)
    assert found is not None, f"{module.__name__}.{name} does not exist"
    return found


def _shape(rows: Rows) -> list[tuple[int, str, Any]]:
    """Each row's line, category and ``sinks``, in order."""
    return [(row["line_start"], row["category"], _flow_sinks(row)) for row in rows]


# ── the candidate group (S1, S3, S4) ──

GROUPS: list[tuple[str, dict[int, Any], set[int], tuple[int, ...]]] = [
    ("the lowest sink line first", {10: _hint(10), 3: _hint(3), 7: _hint(7)}, set(), _SINKS),
    ("a replaced lowest sink: the next is the anchor",
     {3: _hint(3), 7: _hint(7), 10: _hint(10)}, {3}, (7, 10)),
    ("a span's other lines are no rows",
     {2: _hint(3), 3: _hint(3), 4: _hint(3), 7: _hint(7)}, set(), (3, 7)),
    ("one row is no group", {3: _hint(3)}, set(), ()),
    ("every row but one excluded", {3: _hint(3), 7: _hint(7)}, {7}, ()),
    ("a request row keeps the file's rows (S1)",
     {3: _hint(3), 7: _hint(7, "path", external("request"))}, set(), ()),
    ("the hint and a request in one flow (S1)",
     {3: _hint(3), 7: _hint(7, "path", external(HINT), external("request"))}, set(), ()),
    ("a D25 row keeps the file's rows (S4)",
     {3: _hint(3, "command"), 7: _hint(7, "command", unknown("param"))}, set(), ()),
]


@pytest.mark.parametrize(("spans", "excluded", "want"), cases(GROUPS))
def test_candidate_group(spans: dict[int, Any], excluded: set[int], want: tuple) -> None:
    assert required("consume", "hint_groups")(spans, frozenset(excluded)) == want


def test_group_cap_is_a_limits_constant() -> None:
    assert required("limits", "MAX_GROUP_SINKS") == 64


@pytest.mark.parametrize("extra", [0, 1], ids=["the cap", "the cap + 1"])
def test_group_cap(extra: int) -> None:
    """At most ``MAX_GROUP_SINKS`` rows make one group; a file with more keeps its rows."""
    lines = range(1, required("limits", "MAX_GROUP_SINKS") + extra + 1)
    got = required("consume", "hint_groups")({n: _hint(n) for n in lines}, frozenset())
    assert got == (() if extra else tuple(lines))


# ── the group row (S3) ──

_THREE: Spec = ("js", """
    const fs = require("fs");

    function readAlbum(filePath) {
      return fs.readFileSync(filePath, "utf8");
    }

    function tagAlbum(filePath, label) {
      fs.appendFileSync(filePath, label);
    }

    function dropAlbum(fileName) {
      fs.unlinkSync(fileName);
    }

    module.exports = { readAlbum, tagAlbum, dropAlbum };
""")


def _program_rows(spec: Spec) -> Rows:
    """The head's rows on ``spec``'s program: one per reported sink line, in line order."""
    flows = {flow.sink_line: flow for flow in spans_of(spec, "path").values()}
    nl_lines = subject(spec).nl_lines
    return [finding_of(flows[n], family_rule("path"), ROOT / "f", nl_lines) for n in sorted(flows)]


def _words(text: str) -> set[str]:
    """Every identifier-shaped token of ``text``, case-folded."""
    return {token.lower() for token in TOKEN.findall(text)}


@pytest.mark.usefixtures("real_pool")
def test_group_row_names_the_count_never_an_identifier() -> None:
    """The description names how many sinks, and no identifier of the program (the
    ``test_0102_finding.py`` description rule); the row lists the members' sink lines."""
    rows = _program_rows(_THREE)
    group = required("consume", "group_to_finding")(rows)
    sinks, description = [row["line_start"] for row in rows], group["description"]
    counted = "3" in re.findall(r"\d+", description) and 3 not in sinks
    named = sorted(_words(description) & _words(_THREE[1]))
    assert (len(rows), counted, named, _flow_sinks(group)) == (3, True, [], sinks)


# ── the fold (R1, R2) ──


def _beside(line: int, category: str, path: Path = _PATH) -> Callable[[Rows], Rows]:
    def mutate(rows: Rows) -> Rows:
        return [*rows, _other(line, category, path)]
    return mutate


REFUSED: list[tuple[str, str, Callable[[Rows], Rows]]] = [
    ("a member's row missing", "path", lambda rows: [rows[0], rows[2]]),
    ("the members out of order", "path", lambda rows: rows[::-1]),
    ("a member the line collapse kept", "path",
     lambda rows: _carrying(rows, {1: {"collapsed_from": ["CWE-706"]}})),
    ("CWE-23 at a member's line", "path", _beside(7, "CWE-23")),
    ("CWE-36 at the anchor's line", "path", _beside(3, "CWE-36")),
    ("CWE-73 at a member's line", "path", _beside(10, "CWE-73")),
    ("CWE-073 at a member's line", "path", _beside(10, "CWE-073")),
    ("a ChildOf ancestor (CWE-706) at a member's line", "path", _beside(7, "CWE-706")),
    ("a ChildOf descendant (CWE-24) at a member's line", "path", _beside(7, "CWE-24")),
    ("CWE-77 at a member's line", "command", _beside(7, "CWE-77")),
    ("CWE-88 at the anchor's line", "command", _beside(3, "CWE-88")),
    ("a ChildOf ancestor (CWE-74) at a member's line", "command", _beside(10, "CWE-74")),
]
FOLDED: list[tuple[str, str, Callable[[Rows], Rows]]] = [
    ("CWE-20 at a member's line", "path", _beside(7, "CWE-20")),
    ("CWE-79 at a member's line", "path", _beside(7, "CWE-79")),
    ("CWE-23 at another line", "path", _beside(5, "CWE-23")),
    ("CWE-23 at a member's line of another file", "path", _beside(7, "CWE-23", ROOT / "x.js")),
    ("CWE-20 at a command member's line", "command", _beside(7, "CWE-20")),
    ("CWE-79 at a command member's line", "command", _beside(10, "CWE-79")),
]


@pytest.mark.parametrize(("family", "mutate"), cases(REFUSED))
def test_fold_refuses_a_crowded_group(family: str, mutate: Callable[[Rows], Rows]) -> None:
    """Refused: every row stays as it was, in its place, and no stamp is left on it."""
    findings = mutate(_members(family))
    want = _shape(findings)
    got = _fold(findings)
    assert (_shape(got), _private(got)) == (want, [])


@pytest.mark.parametrize(("family", "mutate"), cases(FOLDED))
def test_fold_ignores_an_unrelated_row(family: str, mutate: Callable[[Rows], Rows]) -> None:
    """Folded: the group row in the anchor's place, the other row kept."""
    findings = mutate(_members(family))
    other = findings[-1]
    group = (_SINKS[0], family_rule(family).category, list(_SINKS))
    assert _shape(_fold(findings)) == [group, (other["line_start"], other["category"], None)]


def test_fold_puts_the_group_row_in_the_anchors_place() -> None:
    first, second, third = _members()
    got = _fold([_other(1, "CWE-20"), first, _other(5, "CWE-20"), second, third])
    assert _shape(got) == [(1, "CWE-20", None), (3, "CWE-22", list(_SINKS)), (5, "CWE-20", None)]
    assert "_hint_group" not in got[1]


def test_fold_compares_paths_as_the_dedup_does(tmp_path: Path) -> None:
    """An LLM row names its file relative to the root, a skill row absolutely: one file."""
    fold = _api(audit_runner, "_fold_hint_groups")
    path = tmp_path / "app" / "store.py"
    refused = fold([*_members(path=path), _other(7, "CWE-73", "app/store.py")], str(tmp_path), "r")
    folded = fold([*_members(path=path), _other(7, "CWE-79", "app/store.py")], str(tmp_path), "r")
    assert [_flow_sinks(row) for row in refused] == [None] * 4
    assert [_flow_sinks(row) for row in folded] == [list(_SINKS), None]


def test_a_fold_that_raises_keeps_every_row(monkeypatch: pytest.MonkeyPatch) -> None:
    fold = _api(audit_runner, "_fold_hint_groups")

    def boom(*_args: Any) -> Rows:
        raise RuntimeError("fold")

    monkeypatch.setattr(audit_runner, "fold_hint_groups", boom)
    findings = _members()
    want = copy.deepcopy(findings)
    assert fold(findings, str(ROOT), "r") == want


def test_dedup_families_are_the_backends() -> None:
    """Drift guard (A66 (4)): the families a member's line is refused for are the backend's
    cross-agent dedup families of CWE-22 and CWE-78, read from its Go source."""
    assert _TAXONOMY.is_file(), f"{_TAXONOMY} is missing"
    text = _TAXONOMY.read_text(encoding="utf-8")
    go = {frozenset(re.findall(r"CWE-(\d+)", _go_family(text, name))) for name in _GO_FAMILIES}
    assert set(_api(finding_collapse, "_DEDUP_FAMILIES")) == go


def _go_family(text: str, name: str) -> str:
    found = re.search(rf'"{re.escape(name)}":\s*\{{([^}}]*)\}}', text)
    assert found, f"no {name} family in {_TAXONOMY}"
    return found.group(1)


# ── the validate stage (R5) ──


def _statuses(rows: Rows) -> list[tuple[int, str, str, Any]]:
    """Each non-parent row's line, category, status and ``sinks``."""
    return sorted((row["line_start"], row["category"], row["validation_status"],
                   _flow_sinks(row)) for row in rows if not row.get("is_rollup"))


def _unstamped(rows: Rows) -> Rows:
    return [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]


def _expected_ungrouped(rows: Rows, root: Path) -> list[tuple[int, str, str, Any]]:
    """What the stage gives these rows had they never been grouped."""
    return _statuses(_finalized(_unstamped(copy.deepcopy(rows)), root))


@pytest.mark.usefixtures("fresh_quotes")
def test_an_l1_equal_group_stays_one_row(tmp_path: Path) -> None:
    got = _finalized(_file_members(_written(tmp_path, "# keep")), tmp_path)
    assert [(row[0], row[3]) for row in _statuses(got)] == [(4, list(_FILE_SINKS))]
    assert _private(got) == [] and [row for row in got if row.get("is_rollup")] == []


EXTRA: list[tuple[str, str, Callable[[Path], Rows]]] = [
    ("a member validates apart on the stage's reads", "# nosec", lambda path: []),
    ("another finding shares the group's rollup key", "# keep",
     lambda path: [_row(1, path=path, nl_lines=["x"] * 12)]),
]


@pytest.mark.usefixtures("fresh_quotes")
@pytest.mark.parametrize(("marker", "extra"), cases(EXTRA))
def test_the_stage_ungroups_a_group_it_cannot_keep(
    tmp_path: Path, marker: str, extra: Callable[[Path], Rows]
) -> None:
    """R5: the members' own rows, each with its own status, as if never grouped."""
    path = _written(tmp_path, marker)
    rows = [*_file_members(path), *extra(path)]
    want = _expected_ungrouped(rows, tmp_path)
    got = _finalized(rows, tmp_path)
    assert (_statuses(got), _private(got)) == (want, [])
    assert len(want) == len(rows) and {row[3] for row in want} == {None}


@pytest.mark.usefixtures("fresh_quotes")
def test_the_stage_hands_on_no_member_rows(tmp_path: Path) -> None:
    """The stage is the last reader of the members a group row keeps (``without_rows``)."""
    rows = _file_rows(_written(tmp_path, "# keep"))
    group = required("consume", "group_to_finding")(rows)
    validated = audit_runner._validate_without_llm([group], str(tmp_path), "run-0104")
    assert (_shape(validated)[0][2], _private(validated)) == (list(_FILE_SINKS), [])
