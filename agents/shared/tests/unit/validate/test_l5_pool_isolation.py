"""Feature 0061/0072 — a retired L5 pool must not let an orphaned worker
issue an LLM call.

Root cause of the `test_t13d` flake: `_run_l5_pool` retires its pool with
`shutdown(wait=False)`, so a queued worker can outlive `run_l5`. When it
finally runs it calls `_call_llm` — a module global a later test's monkeypatch
has swapped — inflating that test's call count (and, in production, issuing an
LLM call after the audit returned). The `pool_active` gate, cleared before
shutdown, makes `_judge_batch` bail at entry once its pool has retired. These
tests pin that gate directly and deterministically, without touching the
(E2E business-contract) t13d assertion.
"""

from __future__ import annotations

import threading

from shared.validate import llm_judge
from shared.validate.llm_judge import _call_with_strict_retry, _judge_batch


def _batch():
    f = {"id": "f0", "severity": "high", "file_path": "a.py",
         "line_start": 1, "line_end": 1, "code_snippet": "1: x = 1",
         "check_id": "c"}
    return [(0, f, "python")]


def test_retired_pool_worker_issues_no_llm_call(monkeypatch):
    calls = []
    monkeypatch.setattr(llm_judge, "_call_llm",
                        lambda *a, **k: calls.append(1) or '{"verdicts":[]}')
    retired = threading.Event()          # cleared == pool already shut down
    verdicts = _judge_batch(
        batch_idx=0, batch=_batch(), audit_id="a",
        system_prompt="s", model="m", per_batch_timeout_s=1.0,
        pool_active=retired,
    )
    assert calls == [], "an orphan of a retired pool must not call _call_llm"
    assert verdicts == {}


def test_callsite_gate_blocks_slow_orphan(monkeypatch):
    """The load-bearing guard: a worker that got PAST the entry gate while its
    pool was active, then reaches the call site after the pool retired, must
    still issue no `_call_llm`. This is the case the entry gate alone missed
    (the t13d flake)."""
    calls = []
    monkeypatch.setattr(llm_judge, "_call_llm",
                        lambda *a, **k: calls.append(1) or "not json")
    retired = threading.Event()          # cleared: pool retired since entry
    out = _call_with_strict_retry(
        "s", "u", "m", 1.0, batch_size=1, batch_idx=0,
        cancel=None, pool_active=retired,
    )
    assert calls == [], "a retired pool's worker must not call _call_llm at the site"
    assert out == []


def test_callsite_gate_skips_retry_when_pool_retires_between_calls(monkeypatch):
    """If the pool retires between the first call and the retry, the retry is
    skipped even without a cancel token."""
    calls = []
    active = threading.Event()
    active.set()

    def fake(*a, **k):
        calls.append(1)
        active.clear()                   # pool retires right after the 1st call
        return "not valid json"          # force the retry path

    monkeypatch.setattr(llm_judge, "_call_llm", fake)
    out = _call_with_strict_retry(
        "s", "u", "m", 1.0, batch_size=1, batch_idx=0,
        cancel=None, pool_active=active,
    )
    assert calls == [1], "retry must be skipped once the pool retired"
    assert out == []


def test_active_pool_worker_still_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(
        llm_judge, "_call_llm",
        lambda *a, **k: (calls.append(1),
                         '{"verdicts":[{"id":"f0","exploitable":0.9,"reasoning":"x"}]}')[1],
    )
    active = threading.Event()
    active.set()
    verdicts = _judge_batch(
        batch_idx=0, batch=_batch(), audit_id="a",
        system_prompt="s", model="m", per_batch_timeout_s=1.0,
        pool_active=active,
    )
    assert calls == [1], "an active pool's worker must judge normally"
    assert "f0" in verdicts


class _Cancelled:
    def cancelled(self):
        return True


def test_cancelled_non_first_batch_bails(monkeypatch):
    """t13c root cause: once cancelled, a batch that is NOT the first to execute
    must issue no `_call_llm` — this is what stops a fast worker judging the
    whole sweep after a mid-sweep cancel, regardless of consumer timing."""
    calls = []
    monkeypatch.setattr(llm_judge, "_call_llm",
                        lambda *a, **k: calls.append(1) or '{"verdicts":[]}')
    verdicts = _judge_batch(
        batch_idx=3, batch=_batch(), audit_id="a",
        system_prompt="s", model="m", per_batch_timeout_s=1.0,
        cancel=_Cancelled(),
        claim_first=lambda: False,          # a later batch — not the first
    )
    assert calls == [], "a cancelled non-first batch must not call _call_llm"
    assert verdicts == {}


def test_cancelled_first_batch_still_runs(monkeypatch):
    """The in-flight batch (first to execute) still makes its initial call even
    when cancelled — the t13d contract. Only the retry is skipped."""
    calls = []
    monkeypatch.setattr(llm_judge, "_call_llm",
                        lambda *a, **k: calls.append(1) or "not valid json")
    _judge_batch(
        batch_idx=0, batch=_batch(), audit_id="a",
        system_prompt="s", model="m", per_batch_timeout_s=1.0,
        cancel=_Cancelled(),
        claim_first=lambda: True,           # the first batch to execute
    )
    assert calls == [1], "the first in-flight batch still makes its initial call"


def test_first_claim_is_exclusive():
    """Exactly one batch may claim first, so exactly one runs on the cancel
    path under any concurrency."""
    import threading
    lock = threading.Lock()
    claimed = [False]

    def claim():
        with lock:
            if claimed[0]:
                return False
            claimed[0] = True
            return True

    results = [claim() for _ in range(5)]
    assert results.count(True) == 1
    assert results[0] is True


def test_absent_flag_preserves_legacy_behaviour(monkeypatch):
    # pool_active defaults to None (callers other than _run_l5_pool) — the
    # guard must be a no-op then.
    calls = []
    monkeypatch.setattr(
        llm_judge, "_call_llm",
        lambda *a, **k: (calls.append(1),
                         '{"verdicts":[{"id":"f0","exploitable":0.9,"reasoning":"x"}]}')[1],
    )
    verdicts = _judge_batch(
        batch_idx=0, batch=_batch(), audit_id="a",
        system_prompt="s", model="m", per_batch_timeout_s=1.0,
    )
    assert calls == [1]
    assert "f0" in verdicts


def test_run_l5_clears_flag_by_return(monkeypatch):
    """After run_l5 returns, a late orphan reusing the SAME batch path must
    find its pool retired. We simulate the sequential-test scenario: capture
    the pool_active passed to workers, then assert it is cleared once run_l5
    has returned."""
    from shared.validate.types import ValidateConfig

    seen = {}

    real_judge = llm_judge._judge_batch

    def _capture(**kw):
        seen["pool_active"] = kw.get("pool_active")
        return real_judge(**kw)

    monkeypatch.setattr(llm_judge, "_judge_batch", _capture)
    monkeypatch.setattr(
        llm_judge, "_call_llm",
        lambda *a, **k: '{"verdicts":[{"id":"f0","exploitable":0.5,"reasoning":"x"}]}',
    )
    f = {"id": "f0", "severity": "high", "file_path": "a.py",
         "line_start": 1, "line_end": 1, "code_snippet": "1: x", "check_id": "c"}
    llm_judge.run_l5([f], [[]],
                     ValidateConfig(enable_l5=True, l5_model_override="m"))
    flag = seen.get("pool_active")
    assert flag is not None, "run_l5 must pass a pool_active flag to its workers"
    assert not flag.is_set(), (
        "the pool's active flag must be cleared once run_l5 has returned, so a "
        "late orphan bails instead of calling the (possibly swapped) _call_llm"
    )
