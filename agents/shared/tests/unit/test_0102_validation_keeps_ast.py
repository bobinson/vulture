"""Feature 0102 (LLD §10.1; A42 (3)): the validate stage keeps the AST tier's evidence.

An AST-owned row (``consume.flow_to_finding``) carries its evidence as two top-level keys of
its ``validation`` blob, ``ast`` and ``flow``, named once by ``shared.ast.VALIDATION_KEYS``.
The validate stage replaces a finding's blob with its own vote (``status``, ``confidence``,
``checks``, ``validated_at``): at the provisional vote, and again wherever L5 re-votes a
judged finding (the offline backfill; the streaming callback and the final re-vote). Each of
those keeps the two keys whole, the way 0074's ``provenance_origins`` rides the blob:
top-level, never a ``checks[]`` entry, never a voter input. So the ``result`` snapshot, and
the row Go persists whole, carry them.

A finding without them is validated as before: its blob holds the stage's keys alone, in the
stage's order, and its row is, as text, the row of the same finding validated with the keys
once they are taken out again.

Deterministic and offline: the judge is the suite's fake (``tests._fake_llm``) and the
validate stage's clock is pinned, so two rows compare as text.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime, tzinfo
from typing import Any

import pytest

from shared.ast import VALIDATION_KEYS
from shared.ast.consume import FamilyRule, flow_to_finding
from shared.ast.flow import Flow, Guard, Hop, external
from shared.validate import ValidateConfig, validate
from shared.validate import types as validate_types
from tests._fake_llm import patch_l5_judge

type Finding = dict[str, Any]
type Route = Callable[[list[Finding], list[Finding]], list[Finding]]

# The validate stage's own blob keys, in the order it writes them (FindingValidation.to_json).
STAGE_KEYS = ("status", "confidence", "checks", "validated_at")
# The file the row is in, split by "\n" (D21): the sink is line 5.
LINES = (
    "import os",
    "",
    "def handler(req):",
    "    name = os.path.basename(req.args['f'])",
    "    return open(name)",
)
RULE = FamilyRule(
    family="path", check_id="cwe.input_validation.path_traversal", category="CWE-22",
    title="Path traversal", severity="high",
    recommendation="Resolve the path and confine it to the base directory.", cwe_id="22",
)
FLOW = Flow(
    family="path", sink=0, sink_line=5, span=(0, 1), arg=0,
    origins=frozenset({external("request", frozenset({"path_basename"}))}),
    hops=(Hop(3, "param", "req"), Hop(4, "assign", "name"), Hop(5, "sink", "open")),
    guards=(Guard(0, frozenset({"validate"})),), truncated=False,
)
# The judge on, through the suite's fake (no model, no network).
L5_ON = ValidateConfig(enable_l5=True, l5_model_override="fake-judge-model")


class _PinnedClock(datetime):
    """``datetime`` whose ``now`` is one instant: the stage's ``validated_at`` compares."""

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> datetime:
        return datetime(2026, 10, 19, 12, 0, tzinfo=tz or UTC)


@pytest.fixture(autouse=True)
def _offline_judge_and_pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every judged row is answered by the fake judge; the stage's clock is pinned."""
    patch_l5_judge(monkeypatch)
    monkeypatch.setattr(validate_types, "datetime", _PinnedClock)


def _ast_row() -> Finding:
    """The row the AST head emits for ``FLOW`` (§10.1), with the id the runner gives it."""
    return {"id": "ast-1", **flow_to_finding(FLOW, RULE, file_path="app.py", nl_lines=LINES)}


def _bare_row() -> Finding:
    """The same row without a ``validation`` blob: a finding without the tier's keys."""
    row = _ast_row()
    del row["validation"]
    return row


# ── the three places the stage rebuilds a blob ───────────────────────────────


def _provisional_vote(rows: list[Finding], streamed: list[Finding]) -> list[Finding]:
    """The vote alone: L5 off, the stage's default."""
    return validate(rows, config=ValidateConfig()).findings


def _l5_offline(rows: list[Finding], streamed: list[Finding]) -> list[Finding]:
    """The vote, then L5's offline backfill re-votes the judged row (no update callback)."""
    return validate(rows, config=L5_ON).findings


def _l5_streaming(rows: list[Finding], streamed: list[Finding]) -> list[Finding]:
    """The vote, L5's per-batch re-vote streamed (copied into ``streamed`` as it leaves),
    then the final re-vote of every judged row."""
    return validate(
        rows, config=L5_ON, emit_validation_update=lambda batch: streamed.extend(copy.deepcopy(batch)),
    ).findings


ROUTES: dict[str, Route] = {
    "provisional_vote": _provisional_vote,
    "l5_offline": _l5_offline,
    "l5_streaming": _l5_streaming,
}
L5_ROUTES = {name: ROUTES[name] for name in ("l5_offline", "l5_streaming")}


def _tier(blob: dict[str, Any]) -> dict[str, Any]:
    """The AST tier's part of a ``validation`` blob."""
    return {key: blob[key] for key in VALIDATION_KEYS if key in blob}


def _stage(blob: dict[str, Any]) -> dict[str, Any]:
    """A ``validation`` blob without the AST tier's part, in its own order."""
    return {key: value for key, value in blob.items() if key not in VALIDATION_KEYS}


def _rest(row: Finding) -> dict[str, Any]:
    """A row without its ``validation`` blob, in its own order."""
    return {key: value for key, value in row.items() if key != "validation"}


# ── the tests ────────────────────────────────────────────────────────────────


def test_the_ast_row_carries_the_keys_the_one_constant_names() -> None:
    """``consume`` builds the row's blob with exactly ``VALIDATION_KEYS``: ``ast``, ``flow``."""
    assert VALIDATION_KEYS == ("ast", "flow")
    assert tuple(_ast_row()["validation"]) == VALIDATION_KEYS


@pytest.mark.parametrize("route", ROUTES.values(), ids=ROUTES)
def test_validate_keeps_ast_and_flow_unchanged(route: Route) -> None:
    """The validated row's blob is the stage's keys, then ``ast`` and ``flow`` exactly as the
    head wrote them."""
    (out,) = route([_ast_row()], [])
    blob = out["validation"]
    assert tuple(blob) == STAGE_KEYS + VALIDATION_KEYS
    assert json.dumps(_tier(blob)) == json.dumps(_ast_row()["validation"])


@pytest.mark.parametrize("route", ROUTES.values(), ids=ROUTES)
def test_the_keys_become_no_check_and_the_input_row_is_untouched(route: Route) -> None:
    """Neither key became a ``checks[]`` entry, and the stage left its input row as it was
    (V1: a pure function)."""
    row = _ast_row()
    (out,) = route([row], [])
    assert {c["id"] for c in out["validation"]["checks"]}.isdisjoint(VALIDATION_KEYS)
    assert json.dumps(row) == json.dumps(_ast_row())


@pytest.mark.parametrize("route", L5_ROUTES.values(), ids=L5_ROUTES)
def test_the_l5_paths_judged_the_row(route: Route) -> None:
    """Non-vacuity: on both L5 paths the judge answered, so the row was re-voted there."""
    (out,) = route([_ast_row()], [])
    assert "llm_judge" in [c["id"] for c in out["validation"]["checks"]]


def test_every_streamed_update_carries_ast_and_flow() -> None:
    """The ``validation_update`` batches L5 streams carry the two keys as the head wrote them."""
    streamed: list[Finding] = []
    _l5_streaming([_ast_row()], streamed)
    sent = _ast_row()["validation"]
    assert streamed, "the judge streamed no update: the streaming re-vote was not exercised"
    assert [_tier(update["validation"]) for update in streamed] == [sent] * len(streamed)


@pytest.mark.parametrize("route", ROUTES.values(), ids=ROUTES)
def test_a_row_without_the_keys_is_validated_as_before(route: Route) -> None:
    """The keys are no voter input and move nothing else: the row without them validates to
    the stage's keys alone, in the stage's order, and as text to the row with them once they
    are taken out again — blob and the rest of the row alike."""
    (with_keys,) = route([_ast_row()], [])
    (without,) = route([_bare_row()], [])
    assert tuple(without["validation"]) == STAGE_KEYS
    assert json.dumps(without["validation"]) == json.dumps(_stage(with_keys["validation"]))
    assert json.dumps(_rest(without)) == json.dumps(_rest(with_keys))
