"""Feature 0070 P5 — LLM transport defects A (oversized request body / 413)
and C (the loop guard that has never once been attached).

Defect C, measured on the installed SDK:

    RunConfig  accepts hooks= : False
    Runner.run accepts hooks= : True

``hooks`` is not a ``RunConfig`` parameter on ANY SDK version — it belongs to
``Runner.run()``.  The old code put it on ``RunConfig``, caught the resulting
TypeError every single run, logged a false "SDK version does not support"
warning and dropped the guard.  ``_LoopGuardHooks`` therefore never ran.

Defect A: the source budget is computed in *tokens* while the gateway rejects
on *bytes*, and an unknown model behind a custom gateway was credited with a
128K window by family inference.
"""

import asyncio
import inspect
import json
import re

import pytest

from shared import audit_runner
from shared.llm import loop_guard, provider

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _FakeResult:
    """Minimal stand-in for an Agents SDK RunResult."""

    def __init__(self, payload: str = "```json\n[]\n```") -> None:
        self.final_output = payload
        self.raw_responses = []


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _SpyRunner:
    """Records the kwargs every Runner.run call receives."""

    def __init__(self, behaviour=None) -> None:
        self.calls: list[dict] = []
        self._behaviour = behaviour

    async def run(self, agent, **kwargs):
        self.calls.append(kwargs)
        if self._behaviour is not None:
            return await self._behaviour(len(self.calls), agent, kwargs)
        return _FakeResult()


def _install_runner(monkeypatch, runner: _SpyRunner) -> None:
    import agents

    monkeypatch.setattr(agents, "Runner", runner)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """Deterministic model resolution; no real endpoint, no sleeping retries."""
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.delenv("VULTURE_LLM_MAX_BODY_BYTES", raising=False)
    monkeypatch.delenv("VULTURE_REQUIRE_LOOP_GUARD", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    from shared.llm.broker import set_context_window

    set_context_window(None)
    yield
    set_context_window(None)


def _collect(monkeypatch, tmp_path, **kwargs):
    """Drive _collect_llm_findings_async once, synchronously."""
    defaults = dict(
        run_id="p5",
        source_path=str(tmp_path),
        categories=["injection"],
        skill_tools=[],
        instructions="audit it",
        domain_label="categories",
    )
    defaults.update(kwargs)
    return asyncio.run(audit_runner._collect_llm_findings_async(**defaults))


def _collect_batched(monkeypatch, tmp_path, **kwargs):
    """Drive the BATCH loop (_collect_llm_findings_batched_async), not the
    single-call path — D.2's abort lives in the sweep."""
    defaults = dict(
        run_id="p5d",
        source_path=str(tmp_path),
        categories=["injection"],
        skill_tools=[],
        instructions="audit it",
        domain_label="categories",
    )
    defaults.update(kwargs)
    # Tier-3 files (no deterministic findings, not entry/config) are dropped
    # from the LLM sweep by the 0059 cost guard. These fixtures are synthetic
    # filler with no skill findings, so without this the loop receives ONE
    # batch and there is no sweep to abort.
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    return asyncio.run(
        audit_runner._collect_llm_findings_batched_async(**defaults)
    )


def _abort_denominator(caplog) -> int:
    """Return M from the abort log's `batch=N/M`, guarding the sweep premise.

    D.2's abort deliberately fires only while batches REMAIN, so a fixture
    yielding one or two batches would pass vacuously. Reading the denominator
    back out of the real run is the only faithful check: computing batches
    independently misses the tier filter that the sweep applies.
    """
    for record in caplog.records:
        match = re.search(r"batch=(\d+)/(\d+)", record.getMessage())
        if match and "consecutive_failure_abort" in record.getMessage():
            return int(match.group(2))
    raise AssertionError("no abort record carrying batch=N/M was logged")


def _source_context(n_files: int = 6, body: str = "x" * 400) -> str:
    return "\n\n".join(f"--- f{i}.py ---\n{body}" for i in range(n_files))


# ---------------------------------------------------------------------------
# C.1 / C.2 — the loop guard must actually be attached, and must fire
# ---------------------------------------------------------------------------


def test_sdk_places_hooks_on_runner_run_not_run_config():
    """The measurement that invalidates the old 'SDK version' diagnosis."""
    from agents import RunConfig, Runner

    assert "hooks" not in inspect.signature(RunConfig).parameters
    assert "hooks" in inspect.signature(Runner.run).parameters


def test_hooks_reach_runner_run(monkeypatch, tmp_path):
    """C.1: the guard object must be handed to Runner.run(hooks=...)."""
    sentinel_hooks = object()
    monkeypatch.setattr(
        loop_guard, "create_loop_guard_hooks",
        lambda *a, **k: (sentinel_hooks, None),
    )
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    _collect(monkeypatch, tmp_path)

    assert len(runner.calls) == 1
    assert runner.calls[0].get("hooks") is sentinel_hooks
    # And never smuggled onto RunConfig, which cannot carry it.
    rc = runner.calls[0].get("run_config")
    assert rc is None or getattr(rc, "hooks", None) is None


def test_loop_guard_kills_at_global_limit():
    """C.2: drive the detector past VULTURE_LOOP_GLOBAL_LIMIT."""
    from shared.llm.loop_detector import GLOBAL_CALL_LIMIT

    hooks, detector = loop_guard.create_loop_guard_hooks()
    assert hooks is not None

    async def _drive():
        for i in range(GLOBAL_CALL_LIMIT + 5):
            await hooks.on_tool_end(None, None, _Tool("read_file"), f"r{i}")

    with pytest.raises(loop_guard.LoopDetectedError) as exc:
        asyncio.run(_drive())
    assert exc.value.total_calls >= GLOBAL_CALL_LIMIT
    assert detector.total_calls >= GLOBAL_CALL_LIMIT


def test_loop_detected_propagates_through_collect(monkeypatch, tmp_path):
    """C.2 end-to-end: a tool loop inside the run aborts the LLM phase."""
    from shared.llm.loop_detector import GLOBAL_CALL_LIMIT

    async def _behaviour(attempt, agent, kwargs):
        hooks = kwargs["hooks"]
        for i in range(GLOBAL_CALL_LIMIT + 5):
            await hooks.on_tool_end(None, agent, _Tool("read_file"), f"r{i}")
        return _FakeResult()

    runner = _SpyRunner(_behaviour)
    _install_runner(monkeypatch, runner)

    findings, error, _in, _out = _collect(monkeypatch, tmp_path)
    assert findings == []
    assert error is not None and "aborted" in error
    # Not retried: a reasoning loop is not a transient model failure.
    assert len(runner.calls) == 1


# ---------------------------------------------------------------------------
# C.3 — VULTURE_REQUIRE_LOOP_GUARD
# ---------------------------------------------------------------------------


def test_require_loop_guard_refuses_llm_phase(monkeypatch, tmp_path):
    monkeypatch.setattr(
        loop_guard, "create_loop_guard_hooks", lambda *a, **k: (None, None),
    )
    monkeypatch.setenv("VULTURE_REQUIRE_LOOP_GUARD", "true")
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    findings, error, _in, _out = _collect(monkeypatch, tmp_path)
    assert findings == []
    assert error is not None and "loop guard" in error.lower()
    assert runner.calls == [], "must not call the model without a guard"


def test_loop_guard_unavailable_warns_once_not_per_run(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(
        loop_guard, "create_loop_guard_hooks", lambda *a, **k: (None, None),
    )
    monkeypatch.setattr(audit_runner, "_LOOP_GUARD_WARNED", False)
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    with caplog.at_level("WARNING"):
        _collect(monkeypatch, tmp_path)
        _collect(monkeypatch, tmp_path)

    warns = [r for r in caplog.records if "loop_guard_unavailable" in r.getMessage()]
    assert len(warns) == 1, f"expected one process-level warning, got {len(warns)}"
    assert len(runner.calls) == 2, "default must degrade, not refuse"


# ---------------------------------------------------------------------------
# A.1 — VULTURE_LLM_MAX_BODY_BYTES, measured on the ENCODED payload
# ---------------------------------------------------------------------------


# The measured 413 carried ~192 KB of inlined source (196,608 chars from a
# 131,072-token window). A ceiling ABOVE that number cannot fire on the very
# request this cap exists to stop, so assert the property rather than the value:
# the default must sit below the observed failure.
_OBSERVED_413_SOURCE_BYTES = 196_608


def test_max_body_bytes_default_would_have_prevented_the_observed_413(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_MAX_BODY_BYTES", raising=False)
    default = audit_runner._get_max_body_bytes()
    assert default < _OBSERVED_413_SOURCE_BYTES, (
        f"default cap {default} >= the {_OBSERVED_413_SOURCE_BYTES}-byte body that "
        "triggered the 413; a cap above the failure can never prevent it"
    )
    # Still generous enough to be useful: tens of source files per request.
    assert default >= 64 * 1024


def test_max_body_bytes_is_env_overridable(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "8000")
    assert audit_runner._get_max_body_bytes() == 8000


def test_char_budget_does_not_pretend_to_be_a_byte_budget(monkeypatch):
    """A char cap CANNOT enforce a byte limit (1 char = 1-4 bytes), so the byte
    ceiling is enforced on the encoded payload, not folded into the char cap.
    The pre-existing VULTURE_MAX_SOURCE_CHARS contract is untouched."""
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "50000")
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert audit_runner._get_max_source_chars("gemini-pro") == audit_runner._MAX_SOURCE_CHARS


def test_body_cap_counts_bytes_not_chars(monkeypatch, caplog):
    """Multibyte source: 1 char can be 3 bytes — the cap is on bytes."""
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "2000")
    text = "\n\n".join(f"--- f{i}.py ---\n" + "中" * 300 for i in range(6))
    assert len(text) < 2000 < len(text.encode())

    with caplog.at_level("WARNING"):
        out = audit_runner._enforce_body_byte_cap(text)

    assert len(out.encode()) <= 2000
    assert "f0.py" in out and "f5.py" not in out
    msgs = [r.getMessage() for r in caplog.records]
    assert any("llm_body_truncated" in m and "PARTIAL" in m for m in msgs)


def test_body_cap_applied_before_the_request(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "1500")
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    _collect(monkeypatch, tmp_path, source_context=_source_context(8))

    sent = runner.calls[0]["input"] if "input" in runner.calls[0] else ""
    assert sent, "prompt not captured"
    assert "f7.py" not in sent
    assert "dropped" in sent.lower()


def test_body_cap_costs_latency_not_coverage(monkeypatch, tmp_path):
    """The ceiling must split the sweep into MORE batches, not drop files."""
    for i in range(8):
        (tmp_path / f"m{i}.py").write_text("# pad\n" + ("a = 1\n" * 120))
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "3000")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    findings, error, _in, _out, notice = asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            "p5-cov", str(tmp_path), ["injection"], [], "inst", "categories",
        )
    )
    assert error is None
    sent = "\n".join(c.get("input", "") for c in runner.calls)
    assert len(runner.calls) > 1, "cap should force several batches"
    for i in range(8):
        assert f"m{i}.py" in sent, f"m{i}.py was never analyzed"
    assert "dropped" not in sent.lower(), "files must roll over, not be dropped"


# ---------------------------------------------------------------------------
# A.2 — one halved retry on a size error, then degrade
# ---------------------------------------------------------------------------


def test_context_overflow_retries_once_with_half_the_source(monkeypatch, tmp_path):
    prompts: list[str] = []

    async def _behaviour(attempt, agent, kwargs):
        prompts.append(kwargs.get("input", ""))
        if attempt == 1:
            raise RuntimeError("Error code: 413 - request_too_large")
        return _FakeResult()

    runner = _SpyRunner(_behaviour)
    _install_runner(monkeypatch, runner)

    findings, error, _in, _out = _collect(
        monkeypatch, tmp_path, source_context=_source_context(8),
    )
    assert error is None, f"retry should have succeeded: {error}"
    assert len(runner.calls) == 2, "exactly one size retry"
    assert len(prompts[1]) < len(prompts[0])


def test_context_overflow_retry_is_not_a_generic_retry(monkeypatch, tmp_path):
    async def _behaviour(attempt, agent, kwargs):
        raise RuntimeError("Error code: 413 - request_too_large")

    runner = _SpyRunner(_behaviour)
    _install_runner(monkeypatch, runner)

    findings, error, _in, _out = _collect(
        monkeypatch, tmp_path, source_context=_source_context(8),
    )
    assert findings == []
    assert error is not None and "context_overflow" in error
    assert len(runner.calls) == 2, "one retry only — never the 3x transient loop"


# ---------------------------------------------------------------------------
# A.4 (reworked) — an INFERRED window behind a custom gateway must not size the
# request body. The spec said "use 32K in get_context_window()", but §31 added
# family inference *for* custom endpoints and three tests pin it
# (test_get_context_window_family_inference_{qwen,llama,deepseek}), so the guess
# stays for token budgeting and is clamped only where it caused the 413: the
# body. Authoritative windows (env / broker / exact table) are never clamped.
# ---------------------------------------------------------------------------


def test_window_provenance_is_exposed(monkeypatch):
    from shared.llm.broker import set_context_window

    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert provider.resolve_context_window("gpt-4o") == (128_000, "table")
    assert provider.resolve_context_window("glm-5-2-260617") == (131_072, "family")
    assert provider.resolve_context_window("no-such-family-xyz") == (32_000, "default")
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "70000")
    assert provider.resolve_context_window("glm-5-2-260617") == (70_000, "env")
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE")
    set_context_window(131_072)
    try:
        assert provider.resolve_context_window("glm-5-2-260617") == (131_072, "broker")
    finally:
        set_context_window(None)


def test_inferred_window_behind_gateway_clamps_the_body(monkeypatch, caplog):
    """The measured 413: glm-5-2-260617 → 131072 tokens → 196,608 chars."""
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "https://gateway.example/v1")
    with caplog.at_level("WARNING"):
        chars = audit_runner._get_max_source_chars("glm-5-2-260617")
    # 32000 tokens * 0.35 (the <=32K small-model fraction) * 3 chars/token
    # = 33,600 chars — not the 196,608 the inferred window produced.
    assert chars == 33_600
    assert any("VULTURE_LLM_CTX_SIZE" in r.getMessage() for r in caplog.records)
    # The window itself is untouched: §31 token budgeting still sees 128K.
    assert provider.get_context_window("glm-5-2-260617") == 131_072


def test_family_inference_body_not_clamped_without_a_gateway(monkeypatch):
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert audit_runner._get_max_source_chars("glm-5-2-260617") == 196_608


def test_broker_injected_window_not_clamped(monkeypatch):
    """§31 priority preserved: the broker registry knows the gateway's models."""
    from shared.llm.broker import set_context_window

    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "https://gateway.example/v1")
    set_context_window(131_072)
    try:
        assert audit_runner._get_max_source_chars("glm-5-2-260617") == 196_608
    finally:
        set_context_window(None)


def test_explicit_ctx_size_not_clamped(monkeypatch):
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "https://gateway.example/v1")
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "70000")
    assert audit_runner._get_max_source_chars("glm-5-2-260617") == 105_000


# ---------------------------------------------------------------------------
# A.3 — a lost LLM phase must be visible on the result event
# ---------------------------------------------------------------------------


def _stub_skill(source_path: str) -> dict:
    return {
        "findings": [{
            "severity": "high", "category": "injection", "title": "SQLi",
            "description": "d", "file_path": f"{source_path}/db.py",
            "line_start": 1, "line_end": 1, "recommendation": "r",
        }]
    }


def _result_payload(events: list[str]) -> dict:
    for event in events:
        if "event: result" in event:
            line = next(ln for ln in event.split("\n") if ln.startswith("data:"))
            return json.loads(line[5:])
    raise AssertionError("no result event")


def test_llm_failure_surfaces_on_result_event(monkeypatch, tmp_path):
    def _fail(*a, **k):
        return [], "LLM analysis failed (context_overflow): boom", 0, 0, None

    monkeypatch.setattr(audit_runner, "_collect_llm_findings", _fail)
    events = list(audit_runner.run_combined_audit(
        run_id="p5-a3",
        source_path=str(tmp_path),
        categories=["injection"],
        skill_map={"injection": _stub_skill},
        skill_tools=["tool"],
        instructions="inst",
        use_llm=True,
    ))
    payload = _result_payload(events)
    assert "context_overflow" in payload.get("degraded_reason", "")
    assert len(payload["findings"]) == 1, "skill findings survive"


def test_llm_phase_exception_surfaces_on_result_event(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise RuntimeError("setup exploded")

    monkeypatch.setattr(audit_runner, "_collect_llm_findings", _boom)
    events = list(audit_runner.run_combined_audit(
        run_id="p5-a3b",
        source_path=str(tmp_path),
        categories=["injection"],
        skill_map={"injection": _stub_skill},
        skill_tools=["tool"],
        instructions="inst",
        use_llm=True,
    ))
    payload = _result_payload(events)
    assert payload.get("degraded_reason"), "degradation must not be silent"


def test_clean_audit_has_no_degraded_reason(monkeypatch, tmp_path):
    events = list(audit_runner.run_combined_audit(
        run_id="p5-a3c",
        source_path=str(tmp_path),
        categories=["injection"],
        skill_map={"injection": _stub_skill},
        use_llm=False,
    ))
    payload = _result_payload(events)
    assert "degraded_reason" not in payload


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------------------------------------------------------------------------
# A.2 (follow-up): the classifier must recognise a 413 in the shape LiteLLM
# actually produces, or the size-aware retry silently never fires.
# Found by an end-to-end run against a gateway that 413s every completion:
# the audit made 606 attempts and every one classified as `unknown`.
# ---------------------------------------------------------------------------


def test_litellm_wrapped_413_is_context_overflow():
    from shared.llm.errors import LLMErrorKind, classify_llm_error

    shapes = [
        # raw provider JSON — the error CODE
        "Error code: 413 - {'error': {'code': 'request_too_large'}}",
        # LiteLLM's wrapping — the human MESSAGE, which is what actually arrives
        "litellm.APIError: APIError: OpenAIException - request body too large",
        "OpenAIException - Request Body Too Large",
    ]
    for s in shapes:
        assert classify_llm_error(Exception(s)) is LLMErrorKind.CONTEXT_OVERFLOW, (
            f"a 413 must classify as context_overflow so the halve-and-retry "
            f"path engages; got {classify_llm_error(Exception(s))} for {s!r}"
        )


def test_unrelated_body_errors_are_not_size_errors():
    from shared.llm.errors import LLMErrorKind, classify_llm_error

    for s in ("malformed request body", "request body is not valid JSON"):
        assert classify_llm_error(Exception(s)) is not LLMErrorKind.CONTEXT_OVERFLOW


# ===========================================================================
# P5.D — bounding the work. Found by an end-to-end run against a gateway that
# 413s every completion: P5.A-C all behaved correctly and the audit still made
# 625 completion attempts before degrading.
#   19 batches x 2 of our attempts = 38 ... but 625 HTTP calls,
#   i.e. ~16 model calls inside a single Runner.run, invisible to our accounting.
# ===========================================================================


def test_consecutive_failure_threshold_default_and_override(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", raising=False)
    assert audit_runner._max_consecutive_failures() == 3
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "1")
    assert audit_runner._max_consecutive_failures() == 1
    # 0 disables the abort entirely
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "0")
    assert audit_runner._max_consecutive_failures() == 0


def test_max_turns_default_and_override(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_MAX_TURNS", raising=False)
    assert audit_runner._max_turns() > 0, "an unset cap leaves the SDK loop unbounded"
    monkeypatch.setenv("VULTURE_LLM_MAX_TURNS", "7")
    assert audit_runner._max_turns() == 7


def test_max_turns_is_passed_to_runner_run(monkeypatch, tmp_path):
    """D.3: the SDK agent loop must be bounded per attempt.

    625 HTTP completions came from 38 of our attempts — ~16 model calls inside a
    single Runner.run, which no retry budget of ours can see.
    """
    monkeypatch.setenv("VULTURE_LLM_MAX_TURNS", "5")
    runner = _SpyRunner()
    _install_runner(monkeypatch, runner)

    _collect(monkeypatch, tmp_path)

    assert len(runner.calls) == 1
    assert runner.calls[0].get("max_turns") == 5, (
        f"max_turns must bound the SDK loop; got {runner.calls[0].get('max_turns')!r}"
    )


def test_litellm_client_retries_are_pinned():
    """D.1: retry authority must be single-source OFF the broker path too.

    broker.py already sets max_retries=0 on its AsyncOpenAI client, naming the
    hazard: "broker 3x x SDK 2x x agent retry_llm_call 3x". With OPENAI_BASE_URL
    set and the broker off, get_model() returns litellm/openai/<model> so that
    constructor is never reached — and openai's DEFAULT_MAX_RETRIES is 2, a
    hidden 3x on any retryable status (408/409/429/500).
    """
    audit_runner._pin_llm_client_retries()
    import litellm

    assert litellm.num_retries == 0, (
        "litellm.num_retries must be pinned to 0 so retry_llm_call is the only "
        "retry authority; None means 'unset', which leaves the client default"
    )


def test_consecutive_failures_abort_the_sweep(monkeypatch, tmp_path, caplog):
    """D.2 behaviour: a permanently-failing gateway must stop the sweep early.

    The measured case: 19 batches, every one failing, every one burning its full
    attempt budget. With a cap of 3 the loop must stop at the 3rd failure rather
    than walking all 19.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "3")
    # Force many small batches so there is a sweep to abort.
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    for i in range(20):
        (tmp_path / f"f{i}.py").write_text(f"# file {i}\n" + ("x = 1\n" * 30))

    async def _always_413(n, agent, kw):
        raise RuntimeError("Error code: 413 - {'code': 'request_too_large'}")

    runner = _SpyRunner(behaviour=_always_413)
    _install_runner(monkeypatch, runner)

    with caplog.at_level("WARNING"):
        result = _collect_batched(monkeypatch, tmp_path)
        error = result[1]

    assert any("llm_consecutive_failure_abort" in r.getMessage() for r in caplog.records), \
        "the abort must be logged so a truncated sweep is never silent"
    assert _abort_denominator(caplog) >= 8, (
        "premise: the abort must be observed with many batches still pending, "
        "otherwise the sweep ended on its own and proves nothing"
    )
    # Each failing batch costs at most 2 attempts (original + one halved retry),
    # so 3 consecutive failures is at most 6 Runner calls — nowhere near 12+.
    assert len(runner.calls) <= 6, (
        f"expected the sweep to abort after ~3 failures; got {len(runner.calls)} "
        "Runner calls, i.e. it kept walking batches"
    )
    assert error, "an aborted phase must report a reason"


def test_a_single_bad_batch_does_not_abort_the_sweep(monkeypatch, tmp_path):
    """D.2: the counter is CONSECUTIVE — one blip must not end the phase."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "3")
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    for i in range(20):
        (tmp_path / f"g{i}.py").write_text(f"# file {i}\n" + ("y = 2\n" * 30))

    async def _fail_first_only(n, agent, kw):
        if n == 1:
            raise RuntimeError("Error code: 500 - transient")
        return _FakeResult()

    runner = _SpyRunner(behaviour=_fail_first_only)
    _install_runner(monkeypatch, runner)

    _collect_batched(monkeypatch, tmp_path)

    assert len(runner.calls) > 3, (
        "a single failure reset by later successes must not abort the sweep; "
        f"only {len(runner.calls)} calls were made"
    )
