"""Feature 0104 WS-A2 on the production path: ``run_combined_audit`` folds a file's hint-only
rows of one rule into one row (LLD §4.1 A2; D-S (2)).

``finalize_skill_findings`` and ``run_combined_audit`` each call ``_fold_hint_groups``; only
the first had a test. Here the real runner audits a neutral copy of one synthetic JavaScript
file whose three CWE-22 sinks each read a hint-named parameter of an entry function
(``SOURCE``, modelled on ``e2e/fixtures/0104_hint_tier/a2/three_hint``) with the CWE skills
``_0104_sites.scan`` runs on ``a2/`` (``SKILLS``):

* LLM off, one audit the pins share: the ``result`` snapshot holds ONE CWE-22 row for the
  file, listing the three sink lines as ``validation.flow.sinks``, and no row keeps a private
  (``_``-prefixed) key, the ``_hint`` stamps included; the live ``finding`` events, which leave
  before the fold, carry the three member rows (PIN);
* that group row is the one ``finalize_skill_findings`` makes of the same skill rows on the
  same tree (PIN: the two callers of the fold cannot drift);
* LLM on, the model reporting one row at a member line (``MODEL_ROWS``: a CWE-22 row the LLM
  tier keeps, a CWE-22 row its dedup absorbs into a member as ``merged_llm``, a CWE-23 row):
  the fold decides on deterministic rows only, so the file's deterministic CWE-22 rows are
  still that one group row (D-S (2); RED while an LLM row standing at a member line, or a
  member's ``merged_llm``, refuses the group).

Deterministic and offline: the model is the shared suite's fake (``_fake_llm``), the preflight
probe is off and the L5 judge is not asked.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills import SKILL_MAP, SKILL_TOOLS
from shared import audit_runner, quote_store
from shared.provenance import is_llm_provenance
from shared.testing.isolation import isolate
from tests import _ast_v1
from tests._0104_sites import A2, CHECK, row_sinks, scan
from tests._neutral import neutral_dir

# The shared suite's fake model, loaded by file: its ``tests`` package is not ours.
_FAKE_LLM = Path(__file__).resolve().parents[3] / "shared" / "tests" / "_fake_llm.py"
_spec = importlib.util.spec_from_file_location("_0104_fold_fake_llm", _FAKE_LLM)
_fake_llm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fake_llm)

NAME = "folios.js"
SOURCE = """const fs = require("fs");

function openFolio(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function noteFolio(destPath, caption) {
  fs.appendFileSync(destPath, caption);
}

function dropFolio(fileName) {
  fs.unlinkSync(fileName);
}

module.exports = { openFolio, noteFolio, dropFolio };
"""
# The three sink lines (each a hint-only CWE-22 row), the anchor's first.
SINKS = [4, 8, 12]
CATEGORY = "CWE-22"
TRAVERSAL = CHECK[CATEGORY]
# What the file's one group row is (``_identity`` less its file).
GROUP = (SINKS[0], TRAVERSAL, SINKS)
# The CWE skills ``_0104_sites.scan`` runs on ``a2/``: the two AST heads and CWE-23's.
SKILLS = ("input_validation", "injection", "path_equivalence")
RUN_ID = "0104-combined-fold"
# The generate phase as the CWE agent asks for it; the fake model never calls a tool.
LLM_ON = {
    "use_llm": True, "validate_use_llm": False, "skill_tools": SKILL_TOOLS,
    "instructions": "audit", "model": "gpt-4o",
}
# The model's one row at the second member line. The LLM tier's dedup keys a row with a check
# id by (check id, file): ``cwe22_merged`` is absorbed into a member as ``merged_llm``; the
# other two (no check id) stand at the member line, CWE-23 a ChildOf CWE-22. No title is the
# skill's, so no L2 parent pairs a model row with the group row.
MODEL_ROWS: dict[str, dict[str, str]] = {
    "cwe22_kept": {"category": "CWE-22", "title": "Untrusted path reaches a file call"},
    "cwe22_merged": {
        "category": "CWE-22", "title": "Path reaches a file call", "check_id": TRAVERSAL,
    },
    "cwe23_kept": {"category": "CWE-23", "title": "Relative traversal reaches a file call"},
}


def _isolate(patch: pytest.MonkeyPatch, home: Path) -> None:
    """The documented defaults and a private, empty L5 cache (as ``_0104_sites.finalized``)."""
    isolate(patch, home)
    # ``isolate`` opens a new cache, but leaves the quote table marked as made in the last.
    patch.setattr(quote_store, "_table_ready", False)


@pytest.fixture(scope="module")
def tree(request: pytest.FixtureRequest) -> Path:
    """``a2/<NAME>`` holding ``SOURCE`` under a neutral root: every test audits this path."""
    root = neutral_dir(request) / A2
    root.mkdir()
    (root / NAME).write_text(SOURCE, encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def skills_only(tree: Path, tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """The SSE events of one LLM-off audit of ``tree``, isolated as ``isolated`` isolates."""
    with pytest.MonkeyPatch.context() as patch:
        _isolate(patch, tmp_path_factory.mktemp("fold0104_home"))
        return _audit(tree, use_llm=False, validate_use_llm=False)


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)


def _audit(root: Path, **llm: Any) -> list[str]:
    """The SSE events of the real runner over ``root`` with ``SKILLS``."""
    return list(audit_runner.run_combined_audit(
        run_id=RUN_ID, source_path=str(root), categories=list(SKILLS),
        skill_map={name: SKILL_MAP[name] for name in SKILLS}, **llm,
    ))


def _result(events: list[str]) -> list[dict[str, Any]]:
    """The findings of the ``result`` snapshot."""
    return _ast_v1.payloads(events, "result")[0]["findings"]


def _traversal(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The CWE-22 rows of ``rows`` that cite ``NAME``."""
    return [r for r in rows if r.get("category") == CATEGORY and _cites(r)]


def _cites(row: dict[str, Any]) -> bool:
    return Path(str(row.get("file_path") or "")).name == NAME


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    """What a group row is: its file, line, check id and member sink lines (None on a row that
    lists none, a rollup parent's included)."""
    head = tuple(row.get(key) for key in ("file_path", "line_start", "check_id"))
    return *head, row_sinks({**row, "validation": row.get("validation") or {}})


def _private(rows: list[dict[str, Any]]) -> list[str]:
    """Every ``_``-prefixed top-level key of ``rows``."""
    return [key for row in rows for key in row if key.startswith("_")]


def _group_row(events: list[str]) -> dict[str, Any]:
    """The one CWE-22 row the ``result`` snapshot holds for ``NAME``."""
    rows = _traversal(_result(events))
    assert len(rows) == 1, [_identity(r) for r in rows]
    return rows[0]


# ── LLM off (PIN) ────────────────────────────────────────────────────────────


def test_the_result_holds_one_group_row_for_the_file(skills_only: list[str]) -> None:
    assert _identity(_group_row(skills_only))[1:] == GROUP


def test_no_result_row_keeps_a_hint_stamp(skills_only: list[str]) -> None:
    """No private key at all, the ``_hint`` stamps included."""
    rows = _result(skills_only)

    assert rows
    assert _private(rows) == []


def test_the_live_events_carry_the_member_rows(skills_only: list[str]) -> None:
    """Each member's own row, listing no sinks, with no private key."""
    streamed = sorted(_traversal(_ast_v1.payloads(skills_only, "finding")), key=_identity)

    assert [_identity(r)[1:] for r in streamed] == [(n, TRAVERSAL, None) for n in SINKS]
    assert _private(streamed) == []


# ── parity with finalize_skill_findings (PIN) ────────────────────────────────


@pytest.mark.usefixtures("isolated")
def test_the_group_row_is_the_one_finalize_makes(tree: Path, skills_only: list[str]) -> None:
    rows = scan(tree.parent, (A2,))[A2]

    finalized = _traversal(audit_runner.finalize_skill_findings(rows, str(tree), RUN_ID))

    assert [_identity(r) for r in finalized] == [_identity(_group_row(skills_only))]


# ── LLM on: the fold decides on deterministic rows only (RED until D-S (2)) ───


def _model_row(fields: dict[str, str]) -> dict[str, Any]:
    """The model's row with ``fields`` at the second member line, quoting it."""
    line = SINKS[1]
    quote = SOURCE.splitlines()[line - 1].strip()
    return _fake_llm.fake_finding(
        file_path=NAME, line_start=line, line_end=line, evidence_quote=quote, **fields,
    )


def _deterministic(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if not is_llm_provenance(r.get("provenance"))]


@pytest.mark.usefixtures("isolated")
@pytest.mark.parametrize("case", sorted(MODEL_ROWS))
def test_a_model_row_at_a_member_line_keeps_the_group(
    tree: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "off")
    fake = _fake_llm.FakeLLMProvider(scripted_per_call=[[_model_row(MODEL_ROWS[case])]])
    _fake_llm.install_fake_runner(monkeypatch, fake)

    result = _result(_audit(tree, **LLM_ON))

    assert fake.calls >= 1, "the LLM phase never asked the model"
    assert [_identity(r)[1:] for r in _deterministic(_traversal(result))] == [GROUP]
