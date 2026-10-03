"""Feature 0074 P4, T4.5 (AC19, AC31, version-skew rule) — agent-side buckets.

The agent is the FIRST place an LLM row can disappear (plan §3 F6 / G6):
``_deduplicate_findings`` drops an LLM row that matches a skill row on
``(check_id or normalised title, path)`` — with no line — and the batch sweep
drops a row a previous batch already reported. Go cannot see either collapse;
it only sees what survives. So the agent counts, and publishes on its
``result`` payload (which Go reads as ``ScanResult``):

* ``llm_emitted`` — LLM rows produced, counted BEFORE any agent dedup;
* ``llm_collapsed_agent`` — LLM rows the agent's own dedup removed.

Go then derives ``lost = emitted - collapsed_agent - collapsed_go - unique``.
That derivation is only sound if, for the agent alone,
``llm_emitted - llm_collapsed_agent`` equals the LLM rows actually sent —
which is the invariant pinned below.

Version skew: a new agent always sends both counters, as 0 when it had no LLM
phase. ABSENCE is reserved for an older agent (Go reports it ``unavailable``),
so a skills-only run must not omit them.

The model is never called: ``_collect_llm_findings_async`` (one batch's call)
is replaced by a script, so the REAL batch loop and the REAL final dedup run.
All fixtures are synthetic.
"""

from __future__ import annotations

import json

import pytest

from shared import audit_runner
from shared.llm import provider

SKILL_CHECK_ID = "cwe.sql_injection.string_concat"


def _skill_row(source_path: str) -> dict:
    return {
        "severity": "high", "category": "injection", "title": "SQL injection",
        "description": "string-built query", "file_path": f"{source_path}/a0.py",
        "line_start": 1, "line_end": 1, "recommendation": "bind parameters",
        "check_id": SKILL_CHECK_ID,
    }


def _skill(source_path: str) -> dict:
    return {"findings": [_skill_row(source_path)]}


def _llm_row(title: str, path: str, line: int, check_id: str = "") -> dict:
    row = {
        "severity": "high", "category": "injection", "title": title,
        "description": "model reasoning", "file_path": path,
        "line_start": line, "line_end": line, "recommendation": "fix",
    }
    if check_id:
        row["check_id"] = check_id
    return row


class _ScriptedBatches:
    """Each batch answers three rows: one that collides with the skill row on
    (check_id, path) at a DIFFERENT line (F6), one repeated in every batch
    (cross-batch duplicate), and one unique to the batch."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, *args, **kwargs):
        k = self.calls
        self.calls += 1
        rows = [
            _llm_row("Query built by concatenation", "a0.py", 9, SKILL_CHECK_ID),
            _llm_row("Hardcoded credential", "b.py", 3),
            _llm_row(f"Unique weakness {k}", "c.py", k + 1),
        ]
        return rows, None, 10, 10


def _data_line(event: str) -> str:
    return next(ln for ln in event.split("\n") if ln.startswith("data:"))


def _result_payload(events: list[str]) -> dict:
    results = [e for e in events if e.startswith("event: result\n")]
    assert len(results) == 1, "expected exactly one result event"
    return json.loads(_data_line(results[0])[5:])


def _llm_rows(payload: dict) -> list[dict]:
    return [f for f in payload["findings"]
            if str(f.get("provenance", "")).strip().lower().startswith("llm")]


@pytest.fixture
def llm_env(monkeypatch, tmp_path):
    """A hermetic LLM-on run over many small batches; no network."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    monkeypatch.setattr(audit_runner, "_preflight_vetoes", lambda *a, **k: (False, ""))
    for i in range(6):
        (tmp_path / f"a{i}.py").write_text(f"# file {i}\n" + ("q = 1\n" * 30))
    script = _ScriptedBatches()
    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", script)
    return tmp_path, script


def _run(source_path, run_id: str, use_llm: bool, skill=_skill) -> dict:
    return _result_payload(list(audit_runner.run_combined_audit(
        run_id=run_id,
        source_path=str(source_path),
        categories=["injection"],
        skill_map={"injection": skill},
        skill_tools=["tool"],
        instructions="inst",
        use_llm=use_llm,
    )))


def test_counters_reach_the_result_payload(llm_env):
    """AC19/T4.5: both counters are published on the agent's result."""
    src, script = llm_env
    payload = _run(src, "0074-counters", use_llm=True)
    assert script.calls >= 2, "fixture must produce several batches"
    assert "llm_emitted" in payload, f"result keys: {sorted(payload)}"
    assert "llm_collapsed_agent" in payload, f"result keys: {sorted(payload)}"


def test_emitted_is_counted_before_dedup(llm_env):
    """AC19: every row the model produced counts, including the ones dedup drops.

    N batches x 3 rows = 3N emitted; survivors are the cross-batch row once
    plus one unique row per batch (1 + N); the rest (2N - 1) collapsed in the
    agent — the skill collision anywhere in the file (F6) and the repeats.
    """
    src, script = llm_env
    payload = _run(src, "0074-exact", use_llm=True)
    n = script.calls
    assert payload.get("llm_emitted") == 3 * n
    assert payload.get("llm_collapsed_agent") == 2 * n - 1


def test_emitted_minus_collapsed_equals_llm_rows_sent(llm_env):
    """AC19: the agent's half of the ledger balances, so Go's `lost` is real."""
    src, _ = llm_env
    payload = _run(src, "0074-ledger", use_llm=True)
    sent = len(_llm_rows(payload))
    assert sent > 0, "fixture must send LLM rows"
    assert payload.get("llm_emitted", -1) - payload.get("llm_collapsed_agent", 0) == sent


def test_skill_collision_anywhere_in_the_file_is_counted(llm_env):
    """§8 'agent-side collapse': a model check_id equal to a skill row's, at
    another line of the same file, is dropped — and must be counted, never silent."""
    src, script = llm_env
    payload = _run(src, "0074-f6", use_llm=True)
    titles = {f["title"] for f in _llm_rows(payload)}
    assert "Query built by concatenation" not in titles, "precondition: F6 collapse happens"
    assert payload.get("llm_collapsed_agent", 0) >= script.calls


def test_skills_only_run_reports_zero_not_absence(llm_env):
    """Version skew: absence means an OLDER agent. A new agent with no LLM
    phase says 0, so Go never reports a current agent as `unavailable`."""
    src, _ = llm_env
    payload = _run(src, "0074-skills-only", use_llm=False)
    assert payload.get("llm_emitted") == 0, f"result keys: {sorted(payload)}"
    assert payload.get("llm_collapsed_agent") == 0, f"result keys: {sorted(payload)}"


TITLE_ONLY_SKILL_TITLE = "Missing request timeout"


def _title_only_skill(source_path: str) -> dict:
    """A skill row WITHOUT a check_id: the agent keys it on (title, path)."""
    row = _skill_row(source_path)
    del row["check_id"]
    row.update(title=TITLE_ONLY_SKILL_TITLE, file_path=f"{source_path}/a1.py")
    return {"findings": [row]}


class _TitleCollisionBatches(_ScriptedBatches):
    """Each batch answers a row equal to the skill row on (title, path), with
    no check_id and at another line, plus one row unique to the batch."""

    async def __call__(self, *args, **kwargs):
        k = self.calls
        self.calls += 1
        rows = [
            _llm_row(TITLE_ONLY_SKILL_TITLE, "a1.py", 7),
            _llm_row(f"Unique weakness {k}", "c.py", k + 1),
        ]
        return rows, None, 10, 10


def test_title_and_path_collision_with_a_skill_row_is_counted(llm_env, monkeypatch):
    """§8 'agent-side collapse', positive row: an LLM row matching a skill row
    on (title, path) with no check_id is dropped by the agent's dedup and is
    counted in llm_collapsed_agent, one per batch that produced it (AC19)."""
    src, _ = llm_env
    script = _TitleCollisionBatches()
    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", script)
    payload = _run(src, "0074-title", use_llm=True, skill=_title_only_skill)
    _assert_title_collapse_happened(payload, script.calls)
    assert (payload.get("llm_emitted"), payload.get("llm_collapsed_agent")) == (2 * script.calls, script.calls)


def _assert_title_collapse_happened(payload: dict, calls: int) -> None:
    """Precondition: several batches ran, and the (title, path) row is gone."""
    assert calls >= 2, "fixture must produce several batches"
    llm_titles = {f["title"] for f in _llm_rows(payload)}
    assert TITLE_ONLY_SKILL_TITLE not in llm_titles, "precondition: the (title, path) collapse happens"
