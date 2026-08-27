"""Provenance must ride the per-finding SSE event, not only the `result` snapshot.

The defect: ``_set_provenance`` was reached ONLY from inside
``_attach_code_snippet``, which ``run_combined_audit`` calls at the "Combine &
emit final result" step — i.e. AFTER every per-finding ``finding`` event has
already been yielded. So the live delta stream carried no ``provenance`` at all
while the ``result`` StateSnapshot carried the full vocabulary.

Why that reaches the database rather than only the UI: the backend merges
snapshot findings for every agent PLUS delta findings for agents that never sent
a snapshot (``stream_handler.go``, "rescued N delta findings"). An agent cut off
by a context deadline before its ``result`` therefore persists provenance-less
rows — which is why the same target scanned three times had a DIFFERENT set of
agents with an empty ``provenance`` column each time. Nothing about the finding
decides it; only whether that agent got to finish.

The invariant pinned here is the same one ``test_category_enum_scope.py`` pins
for ``category``: one finding must not have two different contents depending on
whether you watched the stream or replayed the run.

Provenance is a pure in-memory classification with no I/O (its own comment in
``_attach_code_snippet`` says so, which is why it is a separate pass from the
snippet loop), so there is nothing to defer. These tests assert it is stamped at
``_finalize_finding_inplace`` — the one choke point both tiers already pass
through immediately before their emit — and that the later pass in
``_attach_code_snippet`` stays a harmless no-op backstop.
"""

import json

import pytest

from shared.audit_runner import run_combined_audit


@pytest.fixture(autouse=True)
def _skills_only(monkeypatch):
    """Skill tier only, no validate stage, no line collapse.

    Each of those is an independent writer of finding fields; switching them off
    keeps these tests measuring the provenance choke point rather than theirs.
    The rollup test below re-enables validate deliberately.
    """
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    monkeypatch.setenv("VULTURE_DISABLE_LINE_COLLAPSE", "true")


def _finding(**over) -> dict:
    base = {
        "severity": "medium",
        "category": "retry",
        "title": "No retry on outbound call",
        "description": "d",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "recommendation": "r",
    }
    base.update(over)
    return base


def _skill(findings: list[dict]):
    def run(source_path: str) -> dict:
        return {"findings": [dict(f) for f in findings]}
    return run


def _event_data(events: list[str], name: str) -> list[dict]:
    out = []
    for ev in events:
        if not ev.startswith(f"event: {name}\n"):
            continue
        line = next(ln for ln in ev.split("\n") if ln.startswith("data:"))
        out.append(json.loads(line[5:]))
    return out


def _delta_findings(events: list[str]) -> list[dict]:
    """What a client (or the backend's delta-rescue path) sees LIVE."""
    return _event_data(events, "finding")


def _snapshot_findings(events: list[str]) -> list[dict]:
    results = _event_data(events, "result")
    assert len(results) == 1, "expected exactly one result event"
    return results[0]["findings"]


def _run(tmp_path, run_id, findings, **kw) -> list[str]:
    return list(run_combined_audit(
        run_id=run_id,
        source_path=str(tmp_path),
        categories=["retry"],
        skill_map={"retry": _skill(findings)},
        use_llm=False,
        **kw,
    ))


# --- the deterministic (skill) tier -------------------------------------------

class TestSkillTierDelta:

    def test_delta_finding_event_carries_provenance(self, tmp_path):
        """The bug, stated directly: a live `finding` event has a provenance."""
        events = _run(tmp_path, "prov-1", [_finding(check_id="chaos.retry.missing")])
        deltas = _delta_findings(events)
        assert len(deltas) == 1
        assert deltas[0].get("provenance") == "skill"

    @pytest.mark.parametrize("extra,expected", [
        ({"check_id": "chaos.retry.missing"}, "skill"),
        ({"signature_status": "trusted"}, "signature_trusted"),
        ({"signature_status": "candidate"}, "signature_candidate"),
        ({"check_id": "cwe.catalog.cwe_79.rollup"}, "catalog_rollup"),
    ])
    def test_delta_carries_the_whole_vocabulary(self, tmp_path, extra, expected):
        """Not just "some" tag: the same classification the snapshot would give.

        A delta defaulted to a single flat value would be worse than empty —
        indistinguishable from a real classification and wrong for three of
        these four shapes.
        """
        events = _run(tmp_path, "prov-2", [_finding(**extra)])
        assert _delta_findings(events)[0].get("provenance") == expected

    @pytest.mark.parametrize("extra", [
        {"check_id": "chaos.retry.missing"},
        {"signature_status": "trusted"},
        {"signature_status": "candidate"},
        {"check_id": "cwe.catalog.cwe_79.rollup"},
    ])
    def test_delta_agrees_with_the_result_snapshot(self, tmp_path, extra):
        """The persisted row must not depend on whether the agent finished."""
        events = _run(tmp_path, "prov-3", [_finding(**extra)])
        delta = _delta_findings(events)[0]
        snap = _snapshot_findings(events)[0]
        assert delta["provenance"] == snap["provenance"]

    def test_snapshot_still_carries_provenance(self, tmp_path):
        """Regression guard: moving the stamp earlier must not lose the snapshot."""
        events = _run(tmp_path, "prov-4", [_finding(check_id="chaos.retry.missing")])
        assert _snapshot_findings(events)[0].get("provenance") == "skill"


# --- the LLM tier -------------------------------------------------------------

class TestLLMTierDelta:
    """`provenance="llm"` is set by the tier itself, via setdefault, BEFORE its
    finalize call. Stamping at the choke point must not overwrite it — an LLM row
    relabelled "skill" would be read by the validate stage as deterministic and
    exempt from L5 demotion, which is a worse failure than an empty column.
    """

    def _run_llm(self, tmp_path, monkeypatch, llm_findings):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        import shared.audit_runner as ar

        def _fake_collect(**kwargs):
            return ([dict(f) for f in llm_findings], None, 0, 0, None)

        monkeypatch.setattr(ar, "_collect_llm_findings", _fake_collect)
        return list(run_combined_audit(
            run_id="prov-llm",
            source_path=str(tmp_path),
            categories=["retry"],
            skill_map={"retry": _skill([])},
            use_llm=True,
            instructions="inst",
            # The LLM phase gate is `use_llm and skill_tools and instructions`;
            # the collector itself is stubbed, so the tool list is only a gate.
            skill_tools=["tool"],
        ))

    def test_llm_delta_is_tagged_llm_not_skill(self, tmp_path, monkeypatch):
        events = self._run_llm(tmp_path, monkeypatch, [
            _finding(title="LLM-only finding", file_path="other.py"),
        ])
        deltas = _delta_findings(events)
        assert len(deltas) == 1, f"expected one LLM delta, got {deltas}"
        assert deltas[0].get("provenance") == "llm"

    def test_llm_check_id_does_not_win_over_the_llm_tag(self, tmp_path, monkeypatch):
        """A model-supplied `check_id` must not reclassify the row as "skill"."""
        events = self._run_llm(tmp_path, monkeypatch, [
            _finding(title="LLM-only finding", file_path="other.py",
                     check_id="chaos.retry.missing"),
        ])
        assert _delta_findings(events)[0].get("provenance") == "llm"


# --- the third emit site: rollup parents --------------------------------------

class TestRollupParentDelta:
    """Rollup parents are emitted at a third site, after the validate stage.

    They are built by `validate/rollup.py`, which stamps "catalog_rollup" itself
    — so this site is already correct. Pinned here so a later refactor that
    routes parents through the shared choke point cannot silently mislabel them
    "skill" (they carry no check_id / signature_status, so the deterministic
    classifier would).
    """

    def test_rollup_parent_event_carries_provenance(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        events = _run(tmp_path, "prov-rollup", [
            _finding(check_id="chaos.retry.missing", line_start=1, line_end=1),
            _finding(check_id="chaos.retry.missing", line_start=9, line_end=9),
        ])
        parents = [f for f in _delta_findings(events) if f.get("is_rollup")]
        assert len(parents) == 1, f"expected one rollup parent, got {parents}"
        assert parents[0].get("provenance") == "catalog_rollup"
