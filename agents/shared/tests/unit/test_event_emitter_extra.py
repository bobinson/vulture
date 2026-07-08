"""result_event(extra=...) merges structured payload (feature 0063)."""

import json

from shared.transport.event_emitter import AgUiEventEmitter


def _result_data(s: str) -> dict:
    return json.loads(s.split("data: ", 1)[1])


def test_result_event_merges_extra():
    e = AgUiEventEmitter("r1")
    s = e.result_event(findings=[], summary="s", score=1.0,
                       extra={"owasp_coverage": {"edition": "2021"}})
    data = _result_data(s)
    assert data["owasp_coverage"]["edition"] == "2021"
    assert data["summary"] == "s"
    assert data["findings_count"] == 0


def test_result_event_without_extra_unchanged():
    e = AgUiEventEmitter("r1")
    data = _result_data(e.result_event(findings=[], summary="s", score=1.0))
    assert "owasp_coverage" not in data
