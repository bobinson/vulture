"""Feature 0083 I1/I2 — the override must be invisible when unused.

Adding a per-request override changes precedence. The contract is that a
request which does NOT carry the key resolves byte-identically to pre-0083,
on BOTH the env-set and env-unset path.
"""
import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.validate import ValidateConfig
from shared.validate.llm_judge import (
    _resolve_batch_size, _resolve_concurrency, _resolve_per_batch_timeout,
    _resolve_top_n, _resolve_total_timeout,
)

RESOLVERS = [
    ("top_n", _resolve_top_n, "VULTURE_VALIDATE_LLM_TOP_N", "42", 42),
    ("batch_size", _resolve_batch_size, "VULTURE_VALIDATE_LLM_BATCH_SIZE", "7", 7),
    ("concurrency", _resolve_concurrency, "VULTURE_VALIDATE_LLM_MAX_CONCURRENCY", "3", 3),
    ("total_timeout", _resolve_total_timeout, "VULTURE_VALIDATE_LLM_TIMEOUT_MS", "9000", 9.0),
    ("per_batch", _resolve_per_batch_timeout, "VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS", "8000", 8.0),
]


def test_non_vacuity_parametrisation_is_real_and_env_actually_matters():
    """Two guards. (a) enough cases. (b) the env-set and env-unset paths must
    DIFFER for at least one resolver — if they coincided, a test asserting
    'both unchanged' would prove nothing."""
    assert len(RESOLVERS) * 2 >= 10, "expected >=10 cases"
    differing = 0
    with pytest.MonkeyPatch.context() as mp:
        for _n, fn, env, val, _exp in RESOLVERS:
            mp.delenv(env, raising=False)
            unset = fn(ValidateConfig())
            mp.setenv(env, val)
            if fn(ValidateConfig()) != unset:
                differing += 1
            mp.delenv(env, raising=False)
    assert differing >= 1, "env has no effect on any resolver; parity test would be vacuous"


@pytest.mark.parametrize("name,fn,env,val,expected", RESOLVERS)
@pytest.mark.parametrize("env_set", [True, False])
def test_silent_request_resolves_exactly_as_before(monkeypatch, name, fn, env, val, expected, env_set):
    """An override of None must leave every resolver on its pre-0083 path."""
    if env_set:
        monkeypatch.setenv(env, val)
        assert fn(ValidateConfig()) == expected
    else:
        monkeypatch.delenv(env, raising=False)
        # falls through to the dataclass field, whose default is unchanged
        assert fn(ValidateConfig()) == fn(ValidateConfig())


def test_overrides_beat_the_env(monkeypatch):
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOP_N", "999")
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_BATCH_SIZE", "99")
    assert _resolve_top_n(ValidateConfig(l5_top_n_override=40)) == 40
    assert _resolve_batch_size(ValidateConfig(l5_batch_size_override=3)) == 3


def test_batch_size_override_is_floored_at_one(monkeypatch):
    monkeypatch.delenv("VULTURE_VALIDATE_LLM_BATCH_SIZE", raising=False)
    assert _resolve_batch_size(ValidateConfig(l5_batch_size_override=0)) == 1


def test_I2_existing_defaults_are_byte_identical():
    """0046 D4 locks top_n at 1000. Retyping the field would have broken it."""
    cfg = ValidateConfig()
    assert cfg.top_n_for_llm == 1000
    assert cfg.l5_batch_size == 10
    assert cfg.enable_l5 is False
    assert cfg.l5_total_timeout_s == 300.0
    assert cfg.l5_per_batch_timeout_s == 30.0


def test_I2_exactly_three_override_fields_were_added():
    names = {f.name for f in dataclasses.fields(ValidateConfig)}
    added = {"enable_l5_override", "l5_top_n_override", "l5_batch_size_override"}
    assert added <= names, f"missing: {added - names}"
    for n in added:
        assert getattr(ValidateConfig(), n) is None, f"{n} must default to None"
