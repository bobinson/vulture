"""Feature 0089 Phase 0.a prerequisites — L5 judge response parsing.

Two silent-loss defects in `shared.validate.llm_judge`:

P2 — `_coerce_verdict` accepted `exploitable` only as int/float, so a model
     answering `"exploitable": "0.8"` lost the whole verdict without a log
     line. The line fields already tolerate a numeric string (`_coerce_line`
     in `audit_runner.py`); the probability did not.

P3 — `_parse_response` returned `[]` when the model DID return verdicts but
     every one was dropped by `_coerce_verdict`. Callers read `[]` as a
     successful parse, so the strict-JSON retry never fired and the batch was
     lost. `None` (structural failure) must be returned instead; a genuinely
     empty `verdicts` array still parses to `[]` and must NOT retry.
"""
from __future__ import annotations

from typing import Any

import pytest

from shared.validate import l5_cache, llm_judge

# ── P2: exploitable as a plain-decimal string ────────────────────────


def _verdict(prob: Any) -> dict[str, Any]:
    return {"id": "f0", "exploitable": prob, "reasoning": "r"}


@pytest.mark.parametrize(
    "raw,expected",
    [
        (0.8, 0.8),          # float — the pre-existing accepted shape
        (1, 1.0),            # int
        ("0.8", 0.8),        # the defect: plain decimal string
        (".8", 0.8),         # leading-dot decimal
        ("0.8 ", 0.8),       # stripped before parsing
        ("1", 1.0),          # integral string
        (2.0, 1.0),          # clamped to [0,1] exactly as before
        ("-3", 0.0),
        ("2", 1.0),
    ],
)
def test_prereq_exploitable_numeric_string(raw, expected):
    out = llm_judge._coerce_verdict(_verdict(raw))
    assert out is not None, f"{raw!r} must yield a verdict"
    assert out["exploitable"] == pytest.approx(expected)


@pytest.mark.parametrize("raw", ["80%", "abc", "1e-1", "1E-1", "", "  ",
                                 None, [0.8], {"p": 0.8},
                                 "nan", "inf", "-inf",
                                 float("nan"), float("inf")])
def test_prereq_exploitable_non_plain_decimal_dropped(raw):
    # A percentage, an exponent or a non-number is NOT a plain decimal: the
    # verdict is still dropped, so this widening cannot admit a guess.
    # NaN/Infinity get their own cases because the clamp does not stop them:
    # `max(0.0, min(1.0, nan))` is 1.0, so a junk probability would otherwise
    # arrive as CERTAINLY exploitable.
    assert llm_judge._coerce_verdict(_verdict(raw)) is None


# ── P3: an all-dropped verdict list is a parse FAILURE ───────────────


def _finding() -> dict[str, Any]:
    return {
        "id": "f0", "check_id": "cwe.test", "severity": "high",
        "file_path": "nonexistent_0089.py", "line_start": 3, "line_end": 3,
        "description": "d", "code_snippet": "x = 1",
    }


def _counting_llm(response: str, calls: list[str]):
    def _call(system_prompt, user_msg, model, timeout_s):
        calls.append(user_msg)
        return response
    return _call


def _run_batch(monkeypatch, response: str) -> tuple[dict, list[str], dict]:
    calls: list[str] = []
    finding = _finding()
    monkeypatch.setattr(llm_judge, "_call_llm", _counting_llm(response, calls))
    verdicts = llm_judge._judge_batch(
        batch_idx=0, batch=[(0, finding, "python")], audit_id="a0",
        system_prompt="sys", model="test-model", per_batch_timeout_s=5.0,
    )
    return verdicts, calls, finding


def test_prereq_all_dropped_triggers_retry(monkeypatch):
    # Every verdict malformed -> _parse_response must report structural
    # failure so _call_with_strict_retry issues the strict-JSON second call.
    verdicts, calls, finding = _run_batch(
        monkeypatch, '{"verdicts":[{"id":"f0","exploitable":{"p":1}}]}')
    assert len(calls) == 2, "an all-dropped batch must trigger the strict retry"
    assert "not valid JSON" in calls[1], "the second call must be the strict nudge"
    assert verdicts == {}
    # A batch that produced no verdict must leave nothing behind, or the
    # 30-day cache would freeze the loss in for every later audit.
    assert l5_cache.lookup(
        llm_judge._cache_key_for(finding, "test-model")) is None

    # A genuinely empty array is a successful parse: no retry.
    verdicts, calls, _ = _run_batch(monkeypatch, '{"verdicts":[]}')
    assert len(calls) == 1, "an empty verdicts array must NOT retry"
    assert verdicts == {}


# ── RED pass: adversarial follow-ups on the P2/P3 fixes ──────────────


@pytest.mark.parametrize("raw", ["1_0", "٨", "١.٥", "１", " 1_0 "])
def test_prereq_exploitable_rejects_non_decimal_digit_forms(raw):
    # `float()` accepts PEP-515 underscores and any Unicode decimal digit, so
    # the string widening quietly admitted "1_0" (10.0) and "٨" (8.0) — both
    # clamped to 1.0, i.e. CERTAINLY exploitable. That is the same harm the
    # NaN guard exists to prevent, reached by a different route: a token that
    # is not a plain ASCII decimal must be no verdict, never a maximal one.
    assert llm_judge._coerce_verdict(_verdict(raw)) is None


@pytest.mark.parametrize(
    "field,value,expected",
    [
        # window_sufficient: only a literal True passes the closure gate. Any
        # other truthy spelling must normalise to None so the gate fails closed.
        ("window_sufficient", True, True),
        ("window_sufficient", False, None),
        ("window_sufficient", 1, None),
        ("window_sufficient", "true", None),
        ("window_sufficient", None, None),
        # evidence_line: a positive non-bool int, or nothing.
        ("evidence_line", 1, 1),
        ("evidence_line", 5, 5),
        ("evidence_line", 0, None),
        ("evidence_line", -1, None),
        ("evidence_line", True, None),
        ("evidence_line", 3.0, None),
        ("evidence_line", "3", None),
        ("evidence_line", None, None),
    ],
)
def test_prereq_verdict_other_fields_unchanged(field, value, expected):
    # The P2 widening touched `exploitable` only. These two fields gate the
    # closure assertion and the citation class, so a normalisation drift here
    # would move confirmed-tier verdicts, not just parse counts. Verified
    # value-for-value against the pre-0089 `_coerce_verdict`.
    v = _verdict(0.8)
    v[field] = value
    out = llm_judge._coerce_verdict(v)
    assert out is not None
    assert out[field] is expected


def test_prereq_verdict_field_whitelist_unchanged():
    # The rebuilt dict is a whitelist: an unnamed field must not survive, and
    # the five named ones must always be present (a caller reads them with
    # `v["exploitable"]`, not `.get`).
    out = llm_judge._coerce_verdict(
        {"id": "f0", "exploitable": "0.8", "bogus": "x"})
    assert set(out) == {"id", "exploitable", "reasoning",
                        "window_sufficient", "evidence_line"}


# ── P3 end to end: at the HTTP boundary, not the _call_llm seam ──────


class _FakeCompletions:
    def __init__(self, content: str, requests: list[dict]) -> None:
        self._content = content
        self.requests = requests

    def create(self, **kw):
        self.requests.append(kw)
        msg = type("M", (), {"content": self._content})()
        choice = type("C", (), {"message": msg, "finish_reason": "stop"})()
        return type("R", (), {"choices": [choice]})()


def _fake_client(content: str, requests: list[dict]):
    chat = type("Chat", (), {"completions": _FakeCompletions(content, requests)})()
    return type("Client", (), {"chat": chat})()


def _run_batch_http(monkeypatch, response: str) -> tuple[dict, list[dict], list]:
    """Drive `_judge_batch` with a stub OpenAI client, counting REQUESTS."""
    requests: list[dict] = []
    stored: list[tuple] = []
    monkeypatch.setattr(
        llm_judge, "_get_client", lambda: _fake_client(response, requests))
    monkeypatch.setattr(l5_cache, "lookup", lambda key: None)
    monkeypatch.setattr(
        llm_judge.l5_cache, "store",
        lambda key, **kw: stored.append((key, kw)))
    verdicts = llm_judge._judge_batch(
        batch_idx=0, batch=[(0, _finding(), "python")], audit_id="a0",
        system_prompt="sys", model="test-model", per_batch_timeout_s=5.0,
    )
    return verdicts, requests, stored


def test_prereq_all_dropped_issues_second_http_request(monkeypatch):
    # The green test counted `_call_llm` calls; this counts what actually
    # leaves the process. `_call_llm` fans one logical call out to as many as
    # four requests (json_object -> plain, then a widened budget), so only a
    # request count proves the strict-JSON retry is a SECOND round trip and
    # not a mode fallback inside the first.
    verdicts, requests, stored = _run_batch_http(
        monkeypatch, '{"verdicts":[{"id":"f0","exploitable":{"p":1}}]}')
    assert len(requests) == 2, [r["messages"][-1]["content"][-60:] for r in requests]
    assert "not valid JSON" in requests[1]["messages"][-1]["content"]
    assert verdicts == {}
    # An all-dropped batch must leave nothing in the 30-day cache, or the loss
    # is frozen in for every later audit of the same code.
    assert stored == []


def test_prereq_empty_verdicts_issues_one_http_request(monkeypatch):
    # A model that genuinely judged nothing exploitable answered correctly:
    # spending a second round trip on it would double the L5 bill.
    verdicts, requests, stored = _run_batch_http(monkeypatch, '{"verdicts":[]}')
    assert len(requests) == 1
    assert verdicts == {}
    assert stored == []


def test_prereq_string_prob_survives_to_the_verdict_dict(monkeypatch):
    # P2 end to end: the quoted probability reaches `_judge_batch`'s output
    # AND the cache, in one request — the widening is what makes the batch
    # succeed rather than retry.
    verdicts, requests, stored = _run_batch_http(
        monkeypatch, '{"verdicts":[{"id":"f0","exploitable":"0.8"}]}')
    assert len(requests) == 1
    assert verdicts["f0"]["exploitable"] == pytest.approx(0.8)
    assert len(stored) == 1 and stored[0][1]["exploitable"] == pytest.approx(0.8)
