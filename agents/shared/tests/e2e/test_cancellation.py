"""Feature 0061 — cooperative cancellation, end to end (behavioral).

Covers: T1 Phase-2 gated on cancel, T2 cancel mid-sweep (≤1 in-flight),
T3 wall-clock backstop, T4 transport disconnect → token, T7 hung LLM call
bounded, T8 hung skill bounded, T10 dedicated executor, T11 cancel escapes
cooldown, T12 generator exception surfaces, T13 L5 gated on cancel,
T14 L5 caps deadline at the shared audit ceiling.

All LLM-free: fake collectors / stubbed skills. No live model.
"""
from __future__ import annotations

import asyncio
import threading
import time
import types

import pytest

from shared import audit_runner
from shared.audit_runner import run_combined_audit
from shared.cancellation import (
    CancelToken,
    current_cancel_token,
    set_audit_deadline,
    set_cancel_token,
)
from shared.llm.errors import retry_llm_call
from shared.models.audit_request import AuditRequest
from shared.transport import sse_app
from shared.transport.sse_app import _cancellable_stream
from shared.validate.llm_judge import run_l5
from shared.validate.types import ValidateConfig


def _l5_finding(idx: int, sev: str = "high") -> dict:
    """A finding that passes the L5 grounding gate (has a code window)."""
    return {
        "id": f"f{idx}",
        "severity": sev,
        "title": f"finding-{idx}",
        "file_path": f"src/x{idx}.py",
        "line_start": 10,
        "line_end": 10,
        "description": "x",
        "code_snippet": "x = 1\n",
    }


def _fake_l5_verdicts(user_msg: str) -> str:
    import re

    ids = re.findall(r"id=(f\d+)", user_msg)
    body = ",".join(f'{{"id":"{i}","exploitable":0.2,"reasoning":"x"}}' for i in ids)
    return f'{{"verdicts":[{body}]}}'


@pytest.fixture(autouse=True)
def _clean_ambient_context():
    """Isolate each test from ambient cancel/deadline leakage (and prevent
    leaking into other test modules)."""
    from shared import cancellation
    from shared.validate import l5_cache

    tok_reset = cancellation._current_token.set(None)
    dl_reset = cancellation._current_deadline.set(None)
    # Isolate the persistent L5 verdict cache so cross-test cache hits don't
    # mask real LLM-call behavior in the L5 tests.
    _prev_disabled = l5_cache._DISABLED
    l5_cache._DISABLED = True
    try:
        yield
    finally:
        cancellation._current_token.reset(tok_reset)
        cancellation._current_deadline.reset(dl_reset)
        l5_cache._DISABLED = _prev_disabled


def _skill(source_path: str) -> dict:
    return {
        "findings": [
            {
                "severity": "low",
                "category": "test",
                "title": "Stub finding",
                "description": "d",
                "file_path": "a.py",
                "line_start": 1,
                "line_end": 1,
                "recommendation": "r",
            }
        ]
    }


def _text(events) -> str:
    return "\n".join(events)


# ── T1: Phase-2 (generate) skipped when cancelled ─────────────────────────
def test_t1_phase2_skipped_when_cancelled(monkeypatch, tmp_path):
    called = []

    def spy_collect(*a, **k):
        called.append(1)
        return ([], None, 0, 0, None)

    monkeypatch.setattr(audit_runner, "_collect_llm_findings", spy_collect)

    tok = CancelToken()
    set_cancel_token(tok)

    gen = run_combined_audit(
        run_id="t1",
        source_path=str(tmp_path),
        categories=["c"],
        skill_map={"c": _skill},
        skill_tools=["tool"],
        instructions="instr",
        use_llm=True,
    )
    events = []
    for ev in gen:
        events.append(ev)
        # Cancel AFTER the skill phase reports progress, before Phase 2.
        if "event: progress" in ev and not tok.cancelled():
            tok.cancel("mid")

    text = _text(events)
    assert "Enhancing with LLM analysis" not in text
    assert called == [], "Phase-2 collector must not run once cancelled"
    assert "event: agent_end" in text
    # skill finding produced before cancel is still present
    assert "Stub finding" in text


# ── T2: cancel mid-sweep stops within one batch ───────────────────────────
def test_t2_cancel_mid_sweep(monkeypatch, tmp_path):
    tok = CancelToken()
    set_cancel_token(tok)

    batches = [(f"b{i}", [f"f{i}"]) for i in range(5)]
    monkeypatch.setattr(audit_runner, "_build_source_batches", lambda *a, **k: batches)

    calls = []

    async def fake_call(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            tok.cancel("test")
        return ([], None, 0, 0)

    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", fake_call)

    acc, err, ti, to, notice = asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            "t2", str(tmp_path), ["c"], ["tool"], "instr", "domain",
        )
    )
    assert len(calls) == 1, f"expected ≤1 in-flight call, got {len(calls)}"
    assert notice and "cancelled" in notice
    # broke at batch index 1 (after the single in-flight call), not later
    assert "after 1 of 5" in notice, notice
    assert acc == []


# ── T3: wall-clock backstop halts the sweep ───────────────────────────────
def test_t3_wall_clock_backstop(monkeypatch, tmp_path):
    set_audit_deadline(time.monotonic() - 1.0)  # already expired

    batches = [(f"b{i}", [f"f{i}"]) for i in range(5)]
    monkeypatch.setattr(audit_runner, "_build_source_batches", lambda *a, **k: batches)

    calls = []

    async def fake_call(*a, **k):
        calls.append(1)
        return ([], None, 0, 0)

    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", fake_call)

    acc, err, ti, to, notice = asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            "t3", str(tmp_path), ["c"], ["tool"], "instr", "domain",
        )
    )
    assert calls == [], "no LLM call once the deadline is already past"
    assert notice and "wall-clock" in notice


# ── T4: client disconnect cancels the producer (transport) ────────────────
async def test_t4_disconnect_cancels_producer():
    captured = {}
    stopped = threading.Event()

    def handler(run_id, source_path, config, prior):
        captured["tok"] = current_cancel_token()
        for i in range(1_000_000):
            tok = current_cancel_token()
            if tok is not None and tok.cancelled():
                stopped.set()
                return
            yield f"data: tick{i}\n\n"
            time.sleep(0.005)

    req = AuditRequest(run_id="t4", source_path="/x", config={}, prior_findings=[])
    agen = _cancellable_stream(handler, req)
    first = await agen.__anext__()
    assert "tick" in first

    await agen.aclose()  # simulate client disconnect → Starlette-style teardown

    assert stopped.wait(timeout=5.0), "producer did not observe cancellation"
    assert captured["tok"].cancelled()


# ── T7: a hung LLM call is bounded so the loop regains control ────────────
def test_t7_hung_call_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_LLM_CALL_TIMEOUT_SEC", "1")

    batches = [("b0", ["f0"])]
    monkeypatch.setattr(audit_runner, "_build_source_batches", lambda *a, **k: batches)

    async def hung(*a, **k):
        await asyncio.sleep(30)
        return ([], None, 0, 0)

    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", hung)

    t0 = time.monotonic()
    acc, err, ti, to, notice = asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            "t7", str(tmp_path), ["c"], ["tool"], "instr", "domain",
        )
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 10, f"hung call not bounded (took {elapsed:.1f}s)"
    assert err and "timed out" in err


# ── T8: a hung skill cannot pin the audit (whole-audit deadline) ──────────
def test_t8_hung_skill_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_AGENT_MAX_AUDIT_SECONDS", "1")
    release = threading.Event()

    def slow_skill(source_path):
        release.wait(timeout=30)
        return {"findings": []}

    try:
        t0 = time.monotonic()
        events = list(
            run_combined_audit(
                run_id="t8",
                source_path=str(tmp_path),
                categories=["slow"],
                skill_map={"slow": slow_skill},
                use_llm=False,
            )
        )
        elapsed = time.monotonic() - t0
        assert elapsed < 10, f"hung skill pinned the audit (took {elapsed:.1f}s)"
        text = _text(events)
        assert "skill phase wall-clock cap" in text
        assert "event: agent_end" in text
    finally:
        release.set()  # let the leaked skill thread exit promptly


# ── T10: audit producers run on a dedicated, bounded executor ─────────────
def test_t10_dedicated_audit_pool():
    from concurrent.futures import ThreadPoolExecutor

    assert isinstance(sse_app._AUDIT_POOL, ThreadPoolExecutor)
    assert sse_app._AUDIT_POOL._max_workers == 8  # documented default


def test_t10b_pool_size_env(monkeypatch):
    monkeypatch.setenv("VULTURE_AUDIT_EXECUTOR_WORKERS", "3")
    assert sse_app._int_env("VULTURE_AUDIT_EXECUTOR_WORKERS", 8) == 3
    monkeypatch.setenv("VULTURE_AUDIT_EXECUTOR_WORKERS", "bad")
    assert sse_app._int_env("VULTURE_AUDIT_EXECUTOR_WORKERS", 8) == 8


# ── T11 (behavioral): a cancel/timeout must not be swallowed as a model error ──
# F7 relies on CancelledError being a BaseException that escapes the
# `except Exception` blocks where cooldown/failure is recorded. These tests
# exercise that mechanism directly rather than grepping source.
async def test_t11a_retry_does_not_swallow_cancellederror():
    async def factory():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await retry_llm_call(factory, max_attempts=3)


async def test_t11b_waitfor_cancel_skips_except_exception():
    """The exact F7 mechanism: wait_for injects CancelledError, which bypasses
    an `except Exception` handler — so cooldown/failure recording never runs."""
    except_exception_ran = []

    async def coro():
        try:
            await asyncio.sleep(10)
        except Exception:  # noqa: BLE001 — mirrors _collect_llm_findings_async
            except_exception_ran.append(1)  # would be the cooldown-record site
            raise

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        await asyncio.wait_for(coro(), timeout=0.05)
    assert except_exception_ran == [], "cancel path must skip the except-Exception (cooldown) block"


# ── T12: a generator exception surfaces to the consumer (no hang) ─────────
async def test_t12_generator_exception_surfaces():
    def handler(run_id, source_path, config, prior):
        yield "data: one\n\n"
        raise ValueError("boom")

    req = AuditRequest(run_id="t12", source_path="/x", config={}, prior_findings=[])
    agen = _cancellable_stream(handler, req)
    first = await agen.__anext__()
    assert "one" in first
    with pytest.raises(ValueError, match="boom"):
        await agen.__anext__()


# ── T13: L5 LLM judge is disabled when the audit is cancelled ─────────────
def _fake_validate_capturing(captured):
    def fake_validate(findings, **kw):
        captured["enable_l5"] = kw["config"].enable_l5
        return types.SimpleNamespace(event_texts=[], findings=findings, rollups=[])

    return fake_validate


def test_t13_l5_disabled_when_cancelled(monkeypatch, tmp_path):
    import shared.validate as sv

    captured = {}
    monkeypatch.setattr(sv, "validate", _fake_validate_capturing(captured))

    tok = CancelToken()
    tok.cancel("disconnect")
    set_cancel_token(tok)

    list(
        run_combined_audit(
            run_id="t13",
            source_path=str(tmp_path),
            categories=["c"],
            skill_map={"c": _skill},
            validate_use_llm=True,
            use_llm=False,
        )
    )
    assert captured.get("enable_l5") is False


def test_t13b_l5_enabled_when_not_cancelled(monkeypatch, tmp_path):
    import shared.validate as sv

    captured = {}
    monkeypatch.setattr(sv, "validate", _fake_validate_capturing(captured))

    list(
        run_combined_audit(
            run_id="t13b",
            source_path=str(tmp_path),
            categories=["c"],
            skill_map={"c": _skill},
            validate_use_llm=True,
            use_llm=False,
        )
    )
    assert captured.get("enable_l5") is True


# ── F11c (behavioral): the cancel token crosses the raw-thread boundary ───
def test_f11c_token_crosses_raw_thread_via_copy_context():
    import contextvars as _cv

    tok = CancelToken()
    set_cancel_token(tok)
    seen = {}

    def worker(key):
        seen[key] = current_cancel_token()

    # WITH the copy_context wrap (as run_combined_audit does for _vthread):
    ctx = _cv.copy_context()
    t = threading.Thread(target=lambda: ctx.run(worker, "wrapped"))
    t.start()
    t.join()
    # WITHOUT it: a raw Thread starts with an empty context.
    t2 = threading.Thread(target=worker, args=("bare",))
    t2.start()
    t2.join()

    assert seen["wrapped"] is tok, "copy_context().run must carry the token into the thread"
    assert seen["bare"] is None, "a bare threading.Thread must NOT inherit the token (why the wrap is needed)"


# ── T13c (behavioral): the real L5 pool loop stops early on cancel ────────
def test_t13c_l5_stops_mid_sweep_on_cancel(monkeypatch):
    cfg = ValidateConfig(
        enable_l5=True, l5_model_override="test-model",
        l5_batch_size=1, l5_max_concurrency=1,
    )
    findings = [_l5_finding(i) for i in range(6)]
    l1 = [[] for _ in findings]

    tok = CancelToken()
    set_cancel_token(tok)
    calls = []

    def fake_call(system, user_msg, model, timeout):
        calls.append(1)
        tok.cancel("mid-l5")  # cancel during the first judge call
        return _fake_l5_verdicts(user_msg)

    monkeypatch.setattr("shared.validate.llm_judge._call_llm", fake_call)
    run_l5(findings, l1, cfg)
    # the consumer checks the token at the top of its loop → breaks before
    # judging all 6 batches (proves the token is visible AND honored).
    assert len(calls) < len(findings), f"L5 judged all {len(calls)} batches despite cancel"


# ── #4 (behavioral): an in-flight L5 batch skips its retry once cancelled ─
def test_t13d_l5_retry_skipped_after_cancel(monkeypatch):
    cfg = ValidateConfig(
        enable_l5=True, l5_model_override="test-model",
        l5_batch_size=1, l5_max_concurrency=1,
    )
    findings = [_l5_finding(0)]
    l1 = [[]]

    tok = CancelToken()
    tok.cancel("pre")  # already cancelled when the batch runs
    set_cancel_token(tok)
    calls = []

    def fake_call(system, user_msg, model, timeout):
        calls.append(1)
        return "this is not valid json"  # forces the strict-JSON retry path

    monkeypatch.setattr("shared.validate.llm_judge._call_llm", fake_call)
    run_l5(findings, l1, cfg)
    # without the guard this would be 2 (initial + strict-retry); the cancel
    # check before the retry keeps it at 1.
    assert len(calls) == 1, f"cancelled batch still issued a retry call ({len(calls)} calls)"


# ── T14 (behavioral): L5 caps its deadline at the shared audit ceiling ────
def test_t14_l5_deadline_capped_by_audit_ceiling(monkeypatch):
    cfg = ValidateConfig(
        enable_l5=True, l5_model_override="test-model",
        l5_batch_size=1, l5_max_concurrency=2,
    )
    monkeypatch.setattr(
        "shared.validate.llm_judge._call_llm",
        lambda s, u, m, t: _fake_l5_verdicts(u),
    )
    findings = [_l5_finding(i) for i in range(4)]
    l1 = [[] for _ in findings]

    # Control: no ambient audit deadline → L5 runs and produces verdicts.
    out_ctrl = run_l5([dict(f) for f in findings], [list(x) for x in l1], cfg)
    assert any(len(x) > 0 for x in out_ctrl), "control run should produce L5 verdicts"

    # Capped: an already-past shared audit deadline must pre-empt L5 entirely.
    set_audit_deadline(time.monotonic() - 1.0)
    out_capped = run_l5([dict(f) for f in findings], [list(x) for x in l1], cfg)
    assert all(len(x) == 0 for x in out_capped), "past audit ceiling must cap L5 (no verdicts)"


# ── Config plumbing: the knobs reach every agent's docker-compose block ───
def test_config_plumbing_compose_conformance():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]  # .../vulture
    compose = root / "docker-compose.yml"
    if not compose.exists():
        pytest.skip("docker-compose.yml not present in this checkout")
    text = compose.read_text()
    baseline = text.count("VULTURE_LLM_CTX_SIZE=")  # one per agent block
    assert baseline >= 8
    for var in (
        "VULTURE_AGENT_MAX_AUDIT_SECONDS",
        "VULTURE_LLM_CALL_TIMEOUT_SEC",
        "VULTURE_AUDIT_EXECUTOR_WORKERS",
    ):
        assert text.count(var) >= baseline, f"{var} missing from some agent block(s)"
