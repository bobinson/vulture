"""Feature 0074 review item 34 — the request path sizes from the EFFECTIVE window.

The context guard (``_check_context_budget``), the whole-file truncation
(``_truncate_prompt_to_budget``) and the per-call ``max_tokens`` budget (in
``_collect_llm_findings_async``) must use ``effective_context_window(model)
.effective`` — the same window the per-batch source budget and the prompt profile use —
not the unclamped ``get_context_window``. Behind a gateway a family guess of
131072 tokens for a ``glm`` id is clamped to 32000; before the fix the source
budget was computed for 32000 while truncation and ``max_tokens`` used 131072.

All fixtures are synthetic.
"""

from __future__ import annotations

from shared import audit_runner
from shared.llm import provider
from tests.support.window import GATEWAY, set_gateway
from tests.unit.test_0070_p5_llm_transport import (  # noqa: F401 — autouse fixture
    _collect,
    _FakeResult,
    _hermetic,
    _install_runner,
    _source_context,
    _SpyRunner,
)

GLM = "glm-fixture-260617"
CEILING = 32_000


def _prompt(tokens: int) -> str:
    """Two file blocks of synthetic text, ~``tokens`` estimated tokens in all."""
    half = "word " * int(tokens / 2.2)
    return f"head\n\n--- a.py ---\n{half}\n\n--- b.py ---\n{half}"


def test_effective_window_is_clamped_for_the_fixture(monkeypatch) -> None:
    """Precondition: the fixture model is a clamped family guess."""
    set_gateway(monkeypatch, GATEWAY)
    window = provider.effective_context_window(GLM)
    assert (window.resolved, window.effective) == (131_072, CEILING)


def test_context_guard_uses_effective_window(monkeypatch) -> None:
    """A prompt over 80% of 32000 (but far under 131072) trips the guard."""
    set_gateway(monkeypatch, GATEWAY)
    warning, _ = audit_runner._check_context_budget(_prompt(30_000), GLM)
    assert warning is not None and str(CEILING) in warning


def test_truncation_targets_effective_window(monkeypatch) -> None:
    """Truncation drops file blocks until the prompt fits 80% of 32000."""
    set_gateway(monkeypatch, GATEWAY)
    text = _prompt(30_000)
    cut = audit_runner._truncate_prompt_to_budget(text, GLM)
    assert audit_runner.safe_estimate_tokens(cut) <= int(CEILING * 0.8)


def _max_tokens_sent(monkeypatch, tmp_path, n_files: int) -> int:
    """Drive the real generate call once; return the ``max_tokens`` it sent."""
    agents_seen: list = []

    async def _capture(attempt, agent, kwargs):
        agents_seen.append(agent)
        return _FakeResult()

    runner = _SpyRunner(_capture)
    _install_runner(monkeypatch, runner)
    monkeypatch.setenv("VULTURE_LLM_MAX_OUTPUT_TOKENS", "200000")
    _collect(monkeypatch, tmp_path, model=GLM,
             source_context=_source_context(n_files, body="word " * 400))
    return agents_seen[0].model_settings.max_tokens


def test_max_tokens_never_exceeds_effective_window(monkeypatch, tmp_path) -> None:
    """``max_tokens`` is bounded by the effective window (32000), not 131072."""
    set_gateway(monkeypatch, GATEWAY)
    assert _max_tokens_sent(monkeypatch, tmp_path, 4) < CEILING


def test_max_tokens_without_gateway_uses_the_resolved_window(monkeypatch, tmp_path) -> None:
    """No gateway, no clamp: the room is today's, against 131072."""
    assert _max_tokens_sent(monkeypatch, tmp_path, 4) > CEILING
