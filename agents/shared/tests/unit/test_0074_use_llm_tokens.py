"""Feature 0074 re-audit R2 (contract T2) — every agent reader of
``VULTURE_USE_LLM`` takes the ONE token list the Go backend reads.

The backend (``config.ParseFlag``) records the configured model as the audit's
LLM and ``doctor`` reports the LLM enabled for ``true/1/yes/on``. The agents
enabled the LLM phase only on an exact ``true``, so ``VULTURE_USE_LLM=on`` made
the metadata and diagnostics claim an LLM run while every agent ran skills-only.

One list for both directions: ``true/1/yes/on`` (any case, surrounding
whitespace ignored) is on; ``false/0/no/off``, blank, unset and any
unrecognised value is off. All fixtures are synthetic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from shared.env import env_truthy

_VAR = "VULTURE_USE_LLM"
_ON = ["true", "1", "yes", "on", "ON", " Yes ", "\ttrue\n"]
_OFF = ["", "   ", "false", "0", "no", "off", "OFF", "maybe", "enable"]
_PROVIDER_ENV = (
    "VULTURE_LLM_MODEL", "OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY", "OLLAMA_API_BASE", "VULTURE_LLM_BROKER", "VULTURE_LLM_BROKER_URL",
)
_CASES = [(raw, True) for raw in _ON] + [(raw, False) for raw in _OFF]


@pytest.mark.parametrize(("raw", "on"), _CASES, ids=repr)
def test_mode_reader_takes_the_shared_token_list(raw, on, monkeypatch) -> None:
    from shared.llm import mode

    monkeypatch.setenv(_VAR, raw)
    assert mode.is_skills_only() is (not on)


def test_unset_is_skills_only(monkeypatch) -> None:
    from shared.llm import mode

    monkeypatch.delenv(_VAR, raising=False)
    assert mode.is_skills_only() is True


@pytest.mark.parametrize(("raw", "on"), _CASES, ids=repr)
def test_health_probe_takes_the_shared_token_list(raw, on, monkeypatch) -> None:
    """``disabled`` exactly when the token list says off."""
    from shared.llm.health import check_llm_health

    for name in _PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VULTURE_LLM_MODEL", "weird-custom-model-0074")
    monkeypatch.setenv(_VAR, raw)
    status = asyncio.run(check_llm_health(timeout=0.5))
    assert (status.provider == "disabled") is (not on)


@pytest.mark.parametrize(("raw", "on"), _CASES, ids=repr)
def test_cwe_default_takes_the_shared_token_list(raw, on, monkeypatch) -> None:
    """The CWE agent's runtime default (no per-request ``use_llm``)."""
    from cwe_agent import agent as cwe_agent

    monkeypatch.delenv("VULTURE_CWE_DISABLE_LLM", raising=False)
    monkeypatch.setattr(cwe_agent, "_probe_llm_health",
                        lambda: type("S", (), {"reachable": True})())
    monkeypatch.setenv(_VAR, raw)
    assert cwe_agent._resolve_cwe_llm({})[0] is on


@pytest.mark.parametrize(("raw", "on"), [("on", True), ("yes", True), ("1", True),
                                         ("off", False), ("maybe", False)])
def test_audit_runner_module_default_takes_the_shared_token_list(raw, on) -> None:
    """``audit_runner.USE_LLM`` is captured at import, so it is read in a fresh
    interpreter."""
    env = {**os.environ, _VAR: raw}
    out = subprocess.run(
        [sys.executable, "-c", "from shared import audit_runner; print(audit_runner.USE_LLM)"],
        env=env, capture_output=True, text=True, check=True, timeout=120,
    )
    assert out.stdout.strip().splitlines()[-1] == str(on)


@pytest.mark.parametrize("raw", ["on", "ON", " on "])
def test_env_truthy_accepts_on(raw, monkeypatch) -> None:
    """``env_truthy`` and ``env_flag`` share one on-list (Go's ``ParseFlag``)."""
    monkeypatch.setenv("VULTURE_0074_TRUTHY_PROBE", raw)
    assert env_truthy("VULTURE_0074_TRUTHY_PROBE") is True


# --------------------------------------------------------------------------- #
# The Go lane's fixture, read directly: token parity with config.ParseFlag
# rests on ONE list, not on a hand-copied one.
# --------------------------------------------------------------------------- #

_GO_FIXTURE = (Path(__file__).resolve().parents[4] / "backend" / "internal" / "config"
               / "testdata" / "flag_tokens_0074.json")


def _go_cases() -> list[dict]:
    return json.loads(_GO_FIXTURE.read_text())["cases"]


@pytest.mark.parametrize("case", _go_cases(), ids=lambda c: repr(c["value"]))
@pytest.mark.parametrize("default", [False, True])
def test_env_flag_follows_the_go_fixture(case, default, monkeypatch, caplog) -> None:
    from shared import env

    env._warn_unrecognised.cache_clear()
    monkeypatch.setenv("VULTURE_T2_FIXTURE_FLAG", case["value"])
    with caplog.at_level(logging.WARNING, logger="shared.env"):
        got = env.env_flag("VULTURE_T2_FIXTURE_FLAG", default)
    want = default if case["verdict"] == "default" else case["verdict"]
    assert got is want
    warned = any("VULTURE_T2_FIXTURE_FLAG" in r.getMessage() for r in caplog.records)
    assert warned is case["warns"]


@pytest.mark.parametrize("case", _go_cases(), ids=lambda c: repr(c["value"]))
def test_use_llm_readers_follow_the_go_fixture(case, monkeypatch) -> None:
    """VULTURE_USE_LLM defaults to off: only a true verdict enables it."""
    from shared.llm import mode

    monkeypatch.setenv(_VAR, case["value"])
    on = case["verdict"] is True
    assert env_truthy(_VAR) is on
    assert mode.is_skills_only() is (not on)
