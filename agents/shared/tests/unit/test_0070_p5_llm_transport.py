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
