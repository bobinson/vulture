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

from collections.abc import Callable

import pytest

from shared import audit_runner
from tests.support.agent_run import llm_rows, result_payload
from tests.support.isolation import isolate

SKILL_CHECK_ID = "cwe.sql_injection.string_concat"
TITLE_ONLY_SKILL_TITLE = "Missing request timeout"


def _skill_row(source_path: str) -> dict:
    return {
        "severity": "high", "category": "injection", "title": "SQL injection",
        "description": "string-built query", "file_path": f"{source_path}/a0.py",
        "line_start": 1, "line_end": 1, "recommendation": "bind parameters",
        "check_id": SKILL_CHECK_ID,
    }


def _skill(source_path: str) -> dict:
    return {"findings": [_skill_row(source_path)]}


def _title_only_skill(source_path: str) -> dict:
    """A skill row WITHOUT a check_id: the agent keys it on (title, path)."""
    row = _skill_row(source_path)
    del row["check_id"]
    row.update(title=TITLE_ONLY_SKILL_TITLE, file_path=f"{source_path}/a1.py")
    return {"findings": [row]}


def _llm_row(title: str, path: str, line: int, check_id: str = "") -> dict:
    row = {
        "severity": "high", "category": "injection", "title": title,
        "description": "model reasoning", "file_path": path,
        "line_start": line, "line_end": line, "recommendation": "fix",
    }
    if check_id:
        row["check_id"] = check_id
    return row


def _check_id_rows(k: int) -> list[dict]:
    """Three rows: one that collides with the skill row on (check_id, path) at
    a DIFFERENT line (F6), one repeated in every batch (cross-batch
    duplicate), and one unique to batch ``k``."""
    return [
        _llm_row("Query built by concatenation", "a0.py", 9, SKILL_CHECK_ID),
        _llm_row("Hardcoded credential", "b.py", 3),
        _llm_row(f"Unique weakness {k}", "c.py", k + 1),
    ]


def _title_rows(k: int) -> list[dict]:
    """A row equal to the title-only skill row on (title, path), with no
    check_id and at another line, plus one row unique to batch ``k``."""
    return [
        _llm_row(TITLE_ONLY_SKILL_TITLE, "a1.py", 7),
        _llm_row(f"Unique weakness {k}", "c.py", k + 1),
    ]


class _ScriptedBatches:
    """Stands in for one batch's model call; batch ``k`` answers ``rows(k)``."""

    def __init__(self, rows: Callable[[int], list[dict]]) -> None:
        self.rows = rows
        self.calls = 0

    async def __call__(self, *args, **kwargs):
        k = self.calls
        self.calls += 1
        return self.rows(k), None, 10, 10


def _llm_env(monkeypatch, root, rows: Callable[[int], list[dict]]) -> _ScriptedBatches:
    """A hermetic LLM-on run over many small batches; no network."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    monkeypatch.setattr(audit_runner, "_preflight_vetoes", lambda *a, **k: (False, ""))
    for i in range(6):
        (root / f"a{i}.py").write_text(f"# file {i}\n" + ("q = 1\n" * 30))
    script = _ScriptedBatches(rows)
    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", script)
    return script


def _run(source_path, run_id: str, use_llm: bool, skill=_skill) -> dict:
    return result_payload(list(audit_runner.run_combined_audit(
        run_id=run_id,
        source_path=str(source_path),
        categories=["injection"],
        skill_map={"injection": skill},
        skill_tools=["tool"],
        instructions="inst",
        use_llm=use_llm,
    )))


@pytest.fixture(scope="module")
def check_id_run(tmp_path_factory):
    """ONE LLM-on pipeline run feeding the four counter assertions below.

    Module-scoped, so it applies the suite's isolation itself.
    Returns ``(payload, batches)``.
    """
    root = tmp_path_factory.mktemp("check_id_run")
    with pytest.MonkeyPatch.context() as mp:
        isolate(mp, root)
        script = _llm_env(mp, root, _check_id_rows)
        payload = _run(root, "0074-counters", use_llm=True)
    return payload, script.calls


@pytest.fixture
def llm_env(monkeypatch, tmp_path):
    """The same hermetic environment for a test that needs its own run."""
    return tmp_path, _llm_env(monkeypatch, tmp_path, _check_id_rows)


def test_counters_reach_the_result_payload(check_id_run):
    """AC19/T4.5: both counters are published on the agent's result."""
    payload, calls = check_id_run
    assert calls >= 2, "fixture must produce several batches"
    assert "llm_emitted" in payload, f"result keys: {sorted(payload)}"
    assert "llm_collapsed_agent" in payload, f"result keys: {sorted(payload)}"


def test_emitted_is_counted_before_dedup(check_id_run):
    """AC19: every row the model produced counts, including the ones dedup drops.

    N batches x 3 rows = 3N emitted; survivors are the cross-batch row once
    plus one unique row per batch (1 + N); the rest (2N - 1) collapsed in the
    agent — the skill collision anywhere in the file (F6) and the repeats.
    """
    payload, n = check_id_run
    assert payload.get("llm_emitted") == 3 * n
    assert payload.get("llm_collapsed_agent") == 2 * n - 1


def test_emitted_minus_collapsed_equals_llm_rows_sent(check_id_run):
    """AC19: the agent's half of the ledger balances, so Go's `lost` is real."""
    payload, _ = check_id_run
    sent = len(llm_rows(payload))
    assert sent > 0, "fixture must send LLM rows"
    assert payload.get("llm_emitted", -1) - payload.get("llm_collapsed_agent", 0) == sent


def test_skill_collision_anywhere_in_the_file_is_counted(check_id_run):
    """§8 'agent-side collapse': a model check_id equal to a skill row's, at
    another line of the same file, is dropped — and must be counted, never silent."""
    payload, calls = check_id_run
    titles = {f["title"] for f in llm_rows(payload)}
    assert "Query built by concatenation" not in titles, "precondition: F6 collapse happens"
    assert payload.get("llm_collapsed_agent", 0) >= calls


def test_skills_only_run_reports_zero_not_absence(llm_env):
    """Version skew: absence means an OLDER agent. A new agent with no LLM
    phase says 0, so Go never reports a current agent as `unavailable`."""
    src, _ = llm_env
    payload = _run(src, "0074-skills-only", use_llm=False)
    assert payload.get("llm_emitted") == 0, f"result keys: {sorted(payload)}"
    assert payload.get("llm_collapsed_agent") == 0, f"result keys: {sorted(payload)}"


def test_title_and_path_collision_with_a_skill_row_is_counted(monkeypatch, tmp_path):
    """§8 'agent-side collapse', positive row: an LLM row matching a skill row
    on (title, path) with no check_id is dropped by the agent's dedup and is
    counted in llm_collapsed_agent, one per batch that produced it (AC19)."""
    script = _llm_env(monkeypatch, tmp_path, _title_rows)
    payload = _run(tmp_path, "0074-title", use_llm=True, skill=_title_only_skill)
    assert script.calls >= 2, "fixture must produce several batches"
    llm_titles = {f["title"] for f in llm_rows(payload)}
    assert TITLE_ONLY_SKILL_TITLE not in llm_titles, "precondition: the (title, path) collapse happens"
    assert (payload.get("llm_emitted"), payload.get("llm_collapsed_agent")) == (2 * script.calls, script.calls)


# --------------------------------------------------------------------------- #
# Review item 3 (contract C3) — what the agent's skill/LLM collapse swallowed
# --------------------------------------------------------------------------- #


def _skill_survivor(payload: dict) -> dict:
    return next(f for f in payload["findings"] if f.get("check_id") == SKILL_CHECK_ID
                and f.get("provenance") == "skill")


def test_skill_survivor_records_the_collapsed_llm_row(check_id_run):
    """C3: the skill row an LLM row collapsed onto carries `merged_llm`, one
    entry per DISTINCT dropped (provenance, description), so Go can fold the
    LLM tier into provenance_origins and merged_descriptions."""
    payload, _ = check_id_run
    assert _skill_survivor(payload).get("merged_llm") == [
        {"provenance": "llm", "description": "model reasoning"},
    ]


def test_llm_survivors_never_carry_merged_llm(check_id_run):
    """C3: an LLM row collapsing onto an LLM row (the cross-batch repeat) is
    not a tier merge; only a deterministic survivor records one."""
    payload, _ = check_id_run
    assert not [f for f in llm_rows(payload) if "merged_llm" in f]


def test_merged_llm_absent_when_nothing_collapsed(llm_env):
    """C3: omitted when empty — a skills-only run never carries the field."""
    src, _ = llm_env
    payload = _run(src, "0074-no-merge", use_llm=False)
    assert not [f for f in payload["findings"] if "merged_llm" in f]


@pytest.mark.parametrize(("survivor_prov", "dropped_prov", "recorded"), [
    ("skill", None, True),           # an unstamped row in `new` is an LLM row
    ("skill", "llm", True),
    ("signature_trusted", "llm_l5_verified", True),
    ("llm", "llm", False),           # LLM onto LLM: no tier merge
    ("skill", "skill", False),       # deterministic onto deterministic
])
def test_deduplicate_records_only_llm_onto_deterministic(survivor_prov, dropped_prov, recorded):
    """C3 at the unit: `_deduplicate_findings` decides by the LLM-family rule."""
    base = [{"check_id": "x.y", "file_path": "a.py", "provenance": survivor_prov,
             "description": "skill text"}]
    dropped = {"check_id": "x.y", "file_path": "a.py", "description": "llm text"}
    dropped.update({"provenance": dropped_prov} if dropped_prov else {})
    assert audit_runner._deduplicate_findings(base, [dropped]) == []
    assert ("merged_llm" in base[0]) is recorded


# --------------------------------------------------------------------------- #
# Review item 10 — the counters never understate a loss
# --------------------------------------------------------------------------- #


class _RaisesAfter(_ScriptedBatches):
    """Batches below ``ok`` answer normally; the next one raises out of the sweep."""

    def __init__(self, rows: Callable[[int], list[dict]], ok: int) -> None:
        super().__init__(rows)
        self.ok = ok

    async def __call__(self, *args, **kwargs):
        if self.calls >= self.ok:
            raise RuntimeError("synthetic sweep failure")
        return await super().__call__(*args, **kwargs)


def test_emitted_counts_every_row_as_it_is_deduplicated() -> None:
    """Item 10: `emitted` grows at each batch dedup, before any settle."""
    tally = audit_runner._LLMDedupTally()
    rows = [{"title": f"t{i}", "file_path": "a.py"} for i in range(3)]
    tally.dedup([], rows, "")
    tally.dedup(rows, [dict(r) for r in rows], "")
    assert (tally.emitted, tally.collapsed) == (6, 3)


def test_settle_does_not_recount_the_sweep_output() -> None:
    """Item 10: the final dedup only collapses; its rows were counted already."""
    tally = audit_runner._LLMDedupTally()
    rows = [{"title": f"t{i}", "file_path": "a.py"} for i in range(3)]
    kept = tally.dedup([], rows, "")
    tally.settle([rows[0]], kept, "")
    assert tally.as_result() == {"llm_emitted": 3, "llm_collapsed_agent": 1}


def test_counters_unavailable_when_the_phase_degraded_by_exception(monkeypatch, tmp_path):
    """Item 10: a sweep that raised after some batches discarded rows Go cannot
    see; the counters are published as unavailable (absent), never as a
    balanced ledger that hides the loss."""
    _llm_env(monkeypatch, tmp_path, _check_id_rows)
    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async",
                        _RaisesAfter(_check_id_rows, ok=2))
    payload = _run(tmp_path, "0074-degraded", use_llm=True)
    assert payload.get("degraded_reason"), "precondition: the phase degraded"
    assert "llm_emitted" not in payload and "llm_collapsed_agent" not in payload
