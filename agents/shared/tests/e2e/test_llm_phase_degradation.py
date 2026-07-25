"""§32.1 #19: a failure ANYWHERE in the Phase-2 LLM path (including setup —
broker provider construction, ModelSettings, Agent build — not just the LLM
call) must degrade to skills-only. The audit MUST still emit a `result` and
`agent_end`; a completed skill scan must never be thrown away because the
optional LLM phase raised.
"""
from __future__ import annotations

import json

from shared.audit_runner import run_combined_audit


def _make_source(tmp_path, name, body):
    f = tmp_path / name
    f.write_text(body)
    return str(tmp_path)


def _skill_returning(findings):
    def _skill(_source_path):
        return {"findings": [dict(f) for f in findings]}
    return _skill


def _has_event(events, name):
    return any(f"event: {name}" in e for e in events)


def _result(events):
    for e in events:
        if "event: result" in e:
            data = [ln for ln in e.split("\n") if ln.startswith("data:")][0]
            return json.loads(data[5:])
    raise AssertionError("no result event")


_SKILL_FINDING = {
    "severity": "high", "category": "CWE-89", "title": "skill finding",
    "description": "d", "file_path": "app.py", "line_start": 1, "line_end": 1,
    "recommendation": "fix",
}


def test_llm_setup_exception_degrades_to_skills(tmp_path, monkeypatch):
    src = _make_source(tmp_path, "app.py", "x = 1\n")

    # Simulate a Phase-2 SETUP failure (e.g. broker provider / Agent construction
    # incompatibility) by making the collector raise — this is the class of bug
    # that previously suppressed result/agent_end.
    import shared.audit_runner as ar

    def _boom(*_a, **_k):
        raise RuntimeError("broker provider construction blew up")

    monkeypatch.setattr(ar, "_collect_llm_findings", _boom)

    events = list(run_combined_audit(
        run_id="degrade-1",
        source_path=src,
        categories=["x"],
        skill_map={"x": _skill_returning([_SKILL_FINDING])},
        skill_tools=["__dummy_tool__"],
        instructions="audit",
        model="gpt-4o",
        use_llm=True,
    ))

    # The audit must survive: result + agent_end still emitted.
    assert _has_event(events, "result"), "result event suppressed by LLM setup failure"
    assert _has_event(events, "agent_end"), "agent_end suppressed by LLM setup failure"
    # The skill finding must still be present.
    titles = [f["title"] for f in _result(events)["findings"]]
    assert "skill finding" in titles, "skill findings lost when LLM phase failed"
