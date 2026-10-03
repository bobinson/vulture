"""Feature 0074 P1 (agent side) — window source and the ONE effective window.

Plan §5.1 rev 3 (owner decision O5) and §6 T1.2 / T1.3 / T1.8.

What this file pins, as business behaviour:

* AC1 / AC3 — the request model declares ``context_window_source``; the
  broker's source is held per run beside the injected window for PUBLICATION
  only. ``resolve_context_window`` still labels an injected window ``broker``,
  so the gateway clamp's decision is untouched whatever the source says.
* AC2 — Mode A: an agent-resolved family guess behind a custom endpoint is
  clamped exactly as before 0074 (regression pin).
* AC2b / AC41 — a broker-injected window is never clamped, whatever its
  source, with or without the custom-endpoint marker, so the per-batch source
  budget is never lower than before for identical inputs.
* AC36 — the prompt budget (the generate call's ``output_budget_hint``) and
  the per-batch source budget follow the SAME effective window, and no
  process-wide cache holds a per-run window: two runs in one process with
  different injected windows each see their own.

The source accessor is named after the existing per-run pair in
``shared.llm.broker`` (``set_context_window`` / ``current_context_window``):
``set_context_window_source`` / ``current_context_window_source``.

All fixtures are synthetic.
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any

import pytest

from shared import audit_runner
from shared.llm import provider
from shared.llm.broker import set_context_window
from shared.models.audit_request import AuditRequest

MODEL = "qwen3-fixture-coder-32b"   # no table entry; `qwen3` family -> 32768
FAMILY_WINDOW = 32_768
GATEWAY = "https://gateway.invalid/v1"
SOURCES = ("env", "probe", "table", "family", "default")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _clear_profile_cache() -> None:
    """Start each test from an empty prompt-profile cache, if one exists.

    The two-runs test below deliberately does NOT call this between its runs.
    """
    from shared.prompt import profile_for

    clear = getattr(profile_for, "cache_clear", None)
    if clear is not None:
        clear()


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name in (
        "VULTURE_LLM_CTX_SIZE", "VULTURE_LLM_ENDPOINT_KIND", "VULTURE_LLM_BROKER",
        "VULTURE_MAX_SOURCE_CHARS", "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)
    _gateway(monkeypatch, "")
    set_context_window(None)
    _clear_profile_cache()
    yield
    set_context_window(None)
    _clear_profile_cache()


def _gateway(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", url)
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", url)


def _bind_source(source: str | None) -> None:
    from shared.llm.broker import set_context_window_source

    set_context_window_source(source)


def _in_run(window: int | None, source: str | None, fn: Any) -> Any:
    """Run *fn* in a fresh copied context, the way the transport binds a run."""

    def _body() -> Any:
        set_context_window(window)
        _bind_source(source)
        return fn()

    return contextvars.copy_context().run(_body)


def _in_window_only_run(window: int, fn: Any) -> Any:
    """*fn* in a fresh copied context with only the injected window bound
    (the pre-0074 transport shape), so the cache property is tested alone."""

    def _body() -> Any:
        set_context_window(window)
        return fn()

    return contextvars.copy_context().run(_body)


def _prompt_budget() -> int:
    """The generate call's prompt budget for MODEL (render's output hint)."""
    rp = audit_runner._generate_rendered(
        source_path="/src", categories=["x"], domain_label="X",
        source_context="", prior_context="", model=MODEL,
    )
    return rp.output_budget_hint


def _authoritative(monkeypatch: pytest.MonkeyPatch, window: int, fn: Any) -> Any:
    """*fn* evaluated with an operator-set window (never clamped, never cached)."""
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", str(window))
    _clear_profile_cache()
    try:
        return fn()
    finally:
        monkeypatch.delenv("VULTURE_LLM_CTX_SIZE")
        _clear_profile_cache()


# --------------------------------------------------------------------------- #
# AC1 / AC3 — the request field and the publication-only source
# --------------------------------------------------------------------------- #


class TestRequestDeclaresTheSource:

    def test_audit_request_retains_context_window_source(self) -> None:
        """AC1: pydantic drops an undeclared key silently; the field must exist."""
        req = AuditRequest(
            run_id="r", source_path="/x", context_window=FAMILY_WINDOW,
            context_window_source="family",
        )
        assert req.context_window_source == "family"

    def test_absent_source_is_none(self) -> None:
        """AC3: an older backend sends no source; absent is None, not invented."""
        assert AuditRequest(run_id="r", source_path="/x").context_window_source is None


class TestSourceIsForPublicationOnly:

    @pytest.mark.parametrize("source", SOURCES)
    def test_injected_window_still_labelled_broker(self, source: str) -> None:
        """AC1 / AC3: who decided stays `broker`; the source never relabels it."""
        got = _in_run(FAMILY_WINDOW, source, lambda: provider.resolve_context_window(MODEL))
        assert got == (FAMILY_WINDOW, provider.WINDOW_FROM_BROKER)

    @pytest.mark.parametrize("source", SOURCES)
    def test_broker_source_is_exposed_per_run(self, source: str) -> None:
        """AC1: the bound source is readable for publication within its run."""
        from shared.llm.broker import current_context_window_source

        assert _in_run(FAMILY_WINDOW, source, current_context_window_source) == source

    def test_source_does_not_leak_into_the_next_run(self) -> None:
        """AC1: a run without a source never inherits a previous run's source."""
        from shared.llm.broker import current_context_window_source

        _in_run(FAMILY_WINDOW, "family", current_context_window_source)
        assert _in_run(FAMILY_WINDOW, None, current_context_window_source) is None


# --------------------------------------------------------------------------- #
# AC2 — Mode A clamp unchanged (regression pin)
# --------------------------------------------------------------------------- #


class TestModeAClampUnchanged:

    def test_family_guess_behind_gateway_still_clamped(self, monkeypatch, caplog) -> None:
        """AC2 (pin): 32768 guessed behind a gateway -> 32000 -> 33,600 chars."""
        _gateway(monkeypatch, GATEWAY)
        with caplog.at_level(logging.WARNING):
            assert audit_runner._get_max_source_chars(MODEL) == 33_600
        assert any("llm_body_window_clamped" in r.getMessage() for r in caplog.records)

    def test_family_guess_without_gateway_not_clamped(self) -> None:
        """AC2 (pin): no custom endpoint, no clamp: 32768 * 0.5 * 3."""
        assert audit_runner._get_max_source_chars(MODEL) == 49_152


# --------------------------------------------------------------------------- #
# AC2b / AC41 — a broker window is never clamped, whatever its source
# --------------------------------------------------------------------------- #


class TestBrokerWindowNeverClamped:

    @pytest.mark.parametrize("source", SOURCES + (None,))
    @pytest.mark.parametrize("marker", ["endpoint_kind", "base_url"])
    def test_source_budget_is_the_injected_windows(self, source, marker, monkeypatch) -> None:
        """AC2b + AC41: native (endpoint-kind marker) and base-URL wiring alike."""
        if marker == "endpoint_kind":
            monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
        else:
            _gateway(monkeypatch, GATEWAY)
        got = _in_run(FAMILY_WINDOW, source, lambda: audit_runner._get_max_source_chars(MODEL))
        assert got == 49_152

    @pytest.mark.parametrize(("window", "expected"), [
        (8_192, 8_601),        # 8192   * 0.35 * 3
        (32_000, 33_600),      # 32000  * 0.35 * 3
        (32_768, 49_152),      # 32768  * 0.5  * 3
        (131_072, 196_608),    # 131072 * 0.5  * 3
        (1_048_576, 400_000),  # capped at VULTURE_MAX_SOURCE_CHARS' default
    ])
    def test_budget_never_lower_than_before(self, window, expected, monkeypatch) -> None:
        """AC41: for identical inputs the budget equals today's formula, with
        the family source bound and the gateway marker set."""
        monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
        got = _in_run(window, "family", lambda: audit_runner._get_max_source_chars(MODEL))
        assert got >= expected


# --------------------------------------------------------------------------- #
# AC36 — one effective window for the source budget AND the prompt budget
# --------------------------------------------------------------------------- #


class TestOneEffectiveWindow:

    def test_mode_a_prompt_budget_follows_the_clamped_window(self, monkeypatch) -> None:
        """AC36: behind a gateway the guess is clamped to 32000 for the SOURCE
        budget; the prompt budget must be computed from that same 32000, not
        from the unclamped 32768."""
        _gateway(monkeypatch, GATEWAY)
        source_budget = audit_runner._get_max_source_chars(MODEL)
        prompt_budget = _prompt_budget()
        ref_source = _authoritative(monkeypatch, 32_000, lambda: audit_runner._get_max_source_chars(MODEL))
        ref_prompt = _authoritative(monkeypatch, 32_000, _prompt_budget)
        assert source_budget == ref_source
        assert prompt_budget == ref_prompt

    def test_broker_prompt_budget_follows_the_injected_window(self, monkeypatch) -> None:
        """AC36 + AC2b: an injected window is the effective window for both."""
        monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
        got = _in_run(FAMILY_WINDOW, "family", lambda: (
            audit_runner._get_max_source_chars(MODEL), _prompt_budget()))
        ref = _authoritative(monkeypatch, FAMILY_WINDOW, lambda: (
            audit_runner._get_max_source_chars(MODEL), _prompt_budget()))
        assert got == ref

    def test_two_runs_each_see_their_own_window(self) -> None:
        """AC36: no process-wide cache freezes the first run's window.

        Same model, same process, two runs with different injected windows. The
        prompt budget must move by exactly the window difference, and the source
        budget must be each run's own.
        """
        first = _in_window_only_run(65_536, lambda: (
            audit_runner._get_max_source_chars(MODEL), _prompt_budget()))
        second = _in_window_only_run(131_072, lambda: (
            audit_runner._get_max_source_chars(MODEL), _prompt_budget()))
        assert (first[0], second[0]) == (98_304, 196_608)
        assert second[1] - first[1] == 131_072 - 65_536
