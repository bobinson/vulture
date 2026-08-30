"""Feature 0083 W1 — the L5 master switch must honour a per-request override.

`_resolve_l5_enabled` reads VULTURE_USE_VALIDATE_LLM FIRST and only falls
through to `cfg.enable_l5` when the env is unset. docker-compose pins
`VULTURE_USE_VALIDATE_LLM=${VULTURE_USE_VALIDATE_LLM:-false}` on all ten agent
blocks, so on a stock `docker compose up` an explicit `--validate-llm` is
DEFEATED by the env default: every finding is stamped `skipped_l5_disabled`.

That makes `--validate-llm` a dead flag on the default deployment, and it is the
flag feature 0083's headline command (`--no-llm --validate-llm`) depends on.

Correct precedence: explicit per-request > env > built-in default.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.validate import ValidateConfig, _resolve_l5_enabled


def _set(monkeypatch, val):
    if val is None:
        monkeypatch.delenv("VULTURE_USE_VALIDATE_LLM", raising=False)
    else:
        monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", val)


def test_non_vacuity_env_alone_still_decides_when_request_is_silent():
    """Guard: if the env var stopped working entirely, the assertions below
    would pass for the wrong reason."""
    import contextlib
    with pytest.MonkeyPatch.context() as mp:
        _set(mp, "true")
        assert _resolve_l5_enabled(ValidateConfig(enable_l5_override=None)) is True
        _set(mp, "false")
        assert _resolve_l5_enabled(ValidateConfig(enable_l5_override=None)) is False


@pytest.mark.parametrize("env", ["false", "0", "no"])
def test_explicit_request_ON_beats_env_off(monkeypatch, env):
    """THE BUG. This is the stock docker-compose shape."""
    _set(monkeypatch, env)
    cfg = ValidateConfig(enable_l5=True, enable_l5_override=True)
    assert _resolve_l5_enabled(cfg) is True, (
        f"env={env!r} defeated an explicit --validate-llm; the flag is dead on the default stack"
    )


@pytest.mark.parametrize("env", ["true", "1", "yes"])
def test_explicit_request_OFF_beats_env_on(monkeypatch, env):
    """The symmetric case: an operator must be able to opt OUT per scan."""
    _set(monkeypatch, env)
    cfg = ValidateConfig(enable_l5=False, enable_l5_override=False)
    assert _resolve_l5_enabled(cfg) is False


def test_env_still_wins_when_request_is_silent(monkeypatch):
    """Behaviour preservation: no per-request value -> today's behaviour."""
    _set(monkeypatch, "true")
    assert _resolve_l5_enabled(ValidateConfig(enable_l5=False)) is True
    _set(monkeypatch, "false")
    assert _resolve_l5_enabled(ValidateConfig(enable_l5=True)) is False


def test_field_default_falls_through_when_env_unset(monkeypatch):
    _set(monkeypatch, None)
    assert _resolve_l5_enabled(ValidateConfig(enable_l5=True)) is True
    assert _resolve_l5_enabled(ValidateConfig(enable_l5=False)) is False
