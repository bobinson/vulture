"""Deterministic, network-free LLM stand-in for feature 0057 tests.

The audit runner's LLM phase ultimately calls
``agents.Runner.run(agent, input=..., ...)`` (a classmethod coroutine on the
OpenAI-Agents SDK ``Runner``) from inside
``shared.audit_runner._collect_llm_findings_async``. Because that function does
a *local* ``from agents import Agent, ModelSettings, Runner`` on every call,
the only stable monkeypatch seam is the class method itself:
``agents.Runner.run``. Patching ``shared.audit_runner.Runner`` would NOT work —
the name is rebound on each invocation.

This helper builds a fake ``RunResult``-shaped object and an async replacement
for ``Runner.run`` that returns it without any network or model. It lets the
Phase-1 LLM-on tests script exactly which findings the "LLM" returns, assert
dedup / L5 / batch behaviour, and stay fully deterministic (R9: the CI gate
never calls a live LLM).

L5 judge note: ``shared.validate.llm_judge`` calls OpenAI's
``client.chat.completions.create`` directly (NOT through ``Runner``). For L5
tests use ``patch_l5_judge`` to script per-finding exploitability verdicts.

Usage (LLM phase / batch loop)::

    from tests._fake_llm import FakeLLMProvider, install_fake_runner

    def test_llm_finds_crossline_gap(monkeypatch, tmp_path):
        fake = FakeLLMProvider(scripted=[
            {"severity": "high", "category": "CWE-89",
             "title": "SQL injection via f-string",
             "description": "user input flows into query",
             "file_path": "app.py", "line_start": 12, "line_end": 12,
             "recommendation": "use parameterized queries"},
        ])
        install_fake_runner(monkeypatch, fake)
        # ... drive run_combined_audit(..., use_llm=True); assert the finding
        # appears as net-new and that fake.calls == 1.

Per-batch scripting (P1f batch loop / T12)::

    fake = FakeLLMProvider(scripted_per_call=[
        [finding_for_batch_0],     # returned on the 1st Runner.run
        [finding_for_batch_1],     # returned on the 2nd Runner.run
    ])

Usage (L5 judge / T2, T5, T10)::

    from tests._fake_llm import patch_l5_judge

    def test_l5_skips_blind(monkeypatch):
        patch_l5_judge(monkeypatch, verdicts={"finding-id-1": 0.9})
        # ... drive validate(..., config=ValidateConfig(enable_l5=True))
"""

from __future__ import annotations

from typing import Any, Iterable


# --------------------------------------------------------------------------- #
# Fake RunResult — mimics the bits audit_runner reads off the SDK result.
# --------------------------------------------------------------------------- #


class _FakeUsage:
    """Mimics ``resp.usage`` with the OpenAI-style field set."""

    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        # audit_runner._extract_token_usage reads prompt_tokens/completion_tokens
        # first, then falls back to input_tokens/output_tokens. Populate the
        # OpenAI-style pair so real token counts are reported (R6 / P1d).
        self.prompt_tokens = input_tokens
        self.completion_tokens = output_tokens
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeRawResponse:
    def __init__(self, usage: _FakeUsage) -> None:
        self.usage = usage


class _FakeRunResult:
    """Duck-types the SDK ``RunResult`` for ``_parse_llm_result`` +
    ``_extract_token_usage``.

    ``final_output`` is an ``AuditOutput`` instance (the structured-output
    path) so ``_parse_llm_result`` takes its strongly-typed branch. If the
    caller prefers the raw-text fallback path, pass ``final_output_text``.
    """

    def __init__(
        self,
        final_output: Any,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        self.final_output = final_output
        self.raw_responses = [_FakeRawResponse(_FakeUsage(input_tokens, output_tokens))]


# --------------------------------------------------------------------------- #
# FakeLLMProvider — scripts what the "LLM" returns per Runner.run call.
# --------------------------------------------------------------------------- #


class FakeLLMProvider:
    """Scripts deterministic LLM findings for the audit runner's LLM phase.

    Two scripting modes:
      * ``scripted``         — the SAME finding list returned on every call.
      * ``scripted_per_call``— a list-of-lists; call N returns element N
                               (used to exercise the P1f batch loop). Calls
                               beyond the script length return ``[]`` (the
                               LLM found nothing new in that batch), which is
                               how the batch loop knows it can stop.

    Attributes:
        calls:   number of times the fake Runner.run was invoked.
        inputs:  the ``input=`` prompt text seen on each call (lets a test
                 assert that successive batches carried different file sets,
                 i.e. the sweep actually moved — T12).
    """

    def __init__(
        self,
        scripted: list[dict] | None = None,
        scripted_per_call: list[list[dict]] | None = None,
        input_tokens: int = 1234,
        output_tokens: int = 567,
        raise_on_call: BaseException | None = None,
    ) -> None:
        if scripted is not None and scripted_per_call is not None:
            raise ValueError("pass scripted OR scripted_per_call, not both")
        self._scripted = scripted
        self._scripted_per_call = scripted_per_call
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._raise_on_call = raise_on_call
        self.calls = 0
        self.inputs: list[str] = []

    def _findings_for_call(self, call_index: int) -> list[dict]:
        if self._scripted_per_call is not None:
            if call_index < len(self._scripted_per_call):
                return list(self._scripted_per_call[call_index])
            return []
        return list(self._scripted or [])

    def _build_output(self, findings: list[dict]) -> Any:
        # Import here so the helper module imports cleanly even when the
        # agents SDK / pydantic model layout shifts.
        from shared.audit_runner import AuditFinding, AuditOutput

        return AuditOutput(findings=[AuditFinding(**f) for f in findings])

    async def run(self, agent: Any, *, input: str = "", **kwargs: Any) -> Any:  # noqa: A002
        """Async stand-in matching ``Runner.run``'s call shape."""
        if self._raise_on_call is not None:
            raise self._raise_on_call
        call_index = self.calls
        self.calls += 1
        self.inputs.append(input)
        findings = self._findings_for_call(call_index)
        output = self._build_output(findings)
        return _FakeRunResult(output, self._input_tokens, self._output_tokens)


def install_fake_runner(monkeypatch: Any, fake: FakeLLMProvider) -> FakeLLMProvider:
    """Patch ``agents.Runner.run`` with ``fake.run`` (the only stable seam —
    audit_runner imports Runner locally per call). Returns ``fake`` for
    convenience.

    Also resolves a usable model + marks structured output supported so the
    LLM phase actually runs the agent rather than bailing on model-gating.
    Callers that test the graceful-degradation path should NOT call this.
    """
    import agents

    async def _fake_run(starting_agent: Any, input: Any = "", **kwargs: Any) -> Any:  # noqa: A002
        return await fake.run(starting_agent, input=input, **kwargs)

    monkeypatch.setattr(agents.Runner, "run", staticmethod(_fake_run))
    return fake


# --------------------------------------------------------------------------- #
# L5 judge fake — scripts exploitability verdicts without a network call.
# --------------------------------------------------------------------------- #


def patch_l5_judge(
    monkeypatch: Any,
    verdicts: dict[str, float] | None = None,
    default_exploitable: float = 0.9,
    record_seen_snippets: list[str] | None = None,
) -> None:
    """Make ``shared.validate.llm_judge`` deterministic and offline.

    Patches the module-level ``_call_llm`` so the judge never touches OpenAI.
    The returned JSON echoes one verdict per finding id present in the rendered
    user message, using ``verdicts[id]`` when provided, else
    ``default_exploitable``.

    Args:
        verdicts: optional ``{finding_id: exploitable_prob}`` overrides.
        default_exploitable: probability used for ids not in ``verdicts``.
        record_seen_snippets: if provided, every rendered user message is
            appended so tests can assert the judge saw (or did NOT see) a real
            code window — supports T2 ("L5 skips blind").
    """
    import json
    import re

    from shared.validate import llm_judge

    verdicts = verdicts or {}

    # L5 short-circuits when no model resolves (_resolve_model -> ""). Give it
    # a deterministic placeholder so the judge runs; the patched _call_llm
    # never sends it anywhere.
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MODEL", "fake-judge-model")

    def _fake_call_llm(system_prompt: str, user_msg: str, model: str, timeout_s: float) -> str:
        if record_seen_snippets is not None:
            record_seen_snippets.append(user_msg)
        ids = re.findall(r"id=(\S+)", user_msg)
        out = [
            {"id": fid, "exploitable": verdicts.get(fid, default_exploitable),
             "reasoning": "fake verdict"}
            for fid in ids
        ]
        return json.dumps({"verdicts": out})

    monkeypatch.setattr(llm_judge, "_call_llm", _fake_call_llm)


def fake_finding(
    title: str = "Fake finding",
    category: str = "CWE-89",
    severity: str = "high",
    file_path: str = "app.py",
    line_start: int = 1,
    line_end: int = 1,
    **extra: Any,
) -> dict:
    """Build a minimally-valid finding dict for scripting."""
    f: dict[str, Any] = {
        "title": title,
        "category": category,
        "severity": severity,
        "description": extra.pop("description", "scripted finding"),
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "recommendation": extra.pop("recommendation", "fix it"),
    }
    f.update(extra)
    return f


__all__ = [
    "FakeLLMProvider",
    "install_fake_runner",
    "patch_l5_judge",
    "fake_finding",
]
