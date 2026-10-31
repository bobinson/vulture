"""Feature 0074 re-audit (contract T1) — the agents trim with EXACTLY Go's
whitespace set.

Provenance, origin, override and switch strings are trimmed by Go with
``strings.TrimSpace`` (``unicode.IsSpace``). Bare ``str.strip()`` is not that
set: it also strips the separators U+001C-U+001F, which Go keeps, so ``"\\x1fllm"``
was LLM-family here and skill-family to the backend's dedup guard. U+FEFF is
whitespace nowhere. The shared fixtures pin the provenance and override rules;
this file pins the constant and the switch readers.

All fixtures are synthetic.
"""

from __future__ import annotations

import logging

import pytest

from shared.env import env_flag, env_mode
from shared.gospace import GO_SPACE, trim_go_space

# The code points Go's unicode.IsSpace reports true for.
_GO_IS_SPACE = [
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680,
    *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
]
_NOT_SPACE = ["﻿", "\x1c", "\x1d", "\x1e", "\x1f", "​"]
_VAR = "VULTURE_0074_GO_SPACE_PROBE"


def test_the_constant_is_exactly_gos_set() -> None:
    assert sorted(ord(c) for c in GO_SPACE) == _GO_IS_SPACE


@pytest.mark.parametrize("cp", _GO_IS_SPACE)
def test_trims_every_go_space(cp) -> None:
    ch = chr(cp)
    assert trim_go_space(f"{ch}{ch}llm{ch}") == "llm"


@pytest.mark.parametrize("ch", _NOT_SPACE, ids=repr)
def test_keeps_what_go_does_not_call_space(ch) -> None:
    assert trim_go_space(f"{ch}llm{ch}") == f"{ch}llm{ch}"


@pytest.mark.parametrize("ch", _NOT_SPACE, ids=repr)
def test_is_llm_provenance_keeps_non_go_space(ch) -> None:
    from shared.provenance import is_llm_provenance

    assert is_llm_provenance(f"{ch}llm") is False


@pytest.mark.parametrize("ch", _NOT_SPACE, ids=repr)
def test_flag_padded_with_non_go_space_is_unrecognised(ch, monkeypatch) -> None:
    monkeypatch.setenv(_VAR, f"{ch}false")
    assert env_flag(_VAR, True) is True


@pytest.mark.parametrize("ch", ["\xa0", "\x85", "　"], ids=repr)
def test_flag_padded_with_go_space_is_read(ch, monkeypatch) -> None:
    monkeypatch.setenv(_VAR, f"{ch}false{ch}")
    assert env_flag(_VAR, True) is False


def test_mode_padded_with_non_go_space_is_the_default_and_warns(monkeypatch, caplog) -> None:
    monkeypatch.setenv(_VAR, "\x1cobserve")
    with caplog.at_level(logging.WARNING):
        got = env_mode(_VAR, frozenset({"off", "observe", "enforce"}), "enforce")
    assert got == "enforce"
    assert any(_VAR in r.getMessage() for r in caplog.records)


def test_mode_padded_with_go_space_is_read(monkeypatch) -> None:
    monkeypatch.setenv(_VAR, "\xa0Observe\x85")
    assert env_mode(_VAR, frozenset({"off", "observe", "enforce"}), "enforce") == "observe"
