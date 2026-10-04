"""Feature 0074 review item 16 (contract C16) — the quote switches are
normalised, and an unrecognised value is never accepted silently.

``VULTURE_LLM_QUOTE_VERIFY`` resolves to exactly one of ``off`` / ``observe`` /
``enforce`` in BOTH runtimes:

* blank or unset            -> ``enforce`` (the default since O6);
* a false token (false/0/no/off, any case) -> ``off``;
* ``observe`` / ``enforce``, any case       -> itself;
* any other non-blank value -> the default, plus ONE warning naming the variable.

Before the fix ``enforced`` became a fourth mode (disarming re-anchoring while
the verifier ran), and ``false`` / ``0`` left the verifier running because the
gates test only ``mode == "off"``. ``VULTURE_LLM_QUOTE_REANCHOR=flase`` kept the
default-on actuator on with no log; a mistyped boolean now warns once too.

All fixtures are synthetic.
"""

from __future__ import annotations

import logging

import pytest

from shared import audit_runner
from shared.env import env_flag

_VERIFY = "VULTURE_LLM_QUOTE_VERIFY"
_REANCHOR = "VULTURE_LLM_QUOTE_REANCHOR"


@pytest.mark.parametrize(("raw", "mode"), [
    ("", "enforce"), ("   ", "enforce"),
    ("enforce", "enforce"), ("ENFORCE", "enforce"), (" Observe ", "observe"),
    ("off", "off"), ("OFF", "off"), ("false", "off"), ("0", "off"), ("no", "off"),
    ("enforced", "enforce"), ("true", "enforce"), ("verify", "enforce"),
])
def test_quote_mode_is_normalised(raw, mode, monkeypatch) -> None:
    monkeypatch.setenv(_VERIFY, raw)
    assert audit_runner._quote_mode() == mode


def test_unset_quote_mode_is_the_default(monkeypatch) -> None:
    monkeypatch.delenv(_VERIFY, raising=False)
    assert audit_runner._quote_mode() == "enforce"


@pytest.mark.parametrize(("raw", "armed"), [
    ("", True), ("enforce", True), ("observe", False), ("false", False), ("enforced", True),
])
def test_reanchor_gate_is_mode_and_switch(raw, armed, monkeypatch) -> None:
    """C16: the gate is (normalised mode == enforce) AND the REANCHOR flag."""
    monkeypatch.setenv(_VERIFY, raw)
    monkeypatch.delenv(_REANCHOR, raising=False)
    assert audit_runner._reanchor_enabled() is armed
    monkeypatch.setenv(_REANCHOR, "off")
    assert audit_runner._reanchor_enabled() is False


def _warnings_naming(caplog, name: str) -> int:
    return sum(name in r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)


def test_unrecognised_quote_mode_warns_once(monkeypatch, caplog) -> None:
    monkeypatch.setenv(_VERIFY, "enforced-typo-0074")
    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            audit_runner._quote_mode()
    assert _warnings_naming(caplog, _VERIFY) == 1


@pytest.mark.parametrize("raw", ["", "enforce", "observe", "off", "false"])
def test_recognised_quote_mode_never_warns(raw, monkeypatch, caplog) -> None:
    monkeypatch.setenv(_VERIFY, raw)
    with caplog.at_level(logging.WARNING):
        audit_runner._quote_mode()
    assert _warnings_naming(caplog, _VERIFY) == 0


def test_unrecognised_flag_keeps_default_and_warns_once(monkeypatch, caplog) -> None:
    monkeypatch.setenv(_REANCHOR, "flase-0074")
    with caplog.at_level(logging.WARNING):
        values = {env_flag(_REANCHOR, True) for _ in range(5)}
    assert (values, _warnings_naming(caplog, _REANCHOR)) == ({True}, 1)


@pytest.mark.parametrize("raw", ["", "true", "on", "off", "0", "NO"])
def test_recognised_flag_never_warns(raw, monkeypatch, caplog) -> None:
    monkeypatch.setenv(_REANCHOR, raw)
    with caplog.at_level(logging.WARNING):
        env_flag(_REANCHOR, True)
    assert _warnings_naming(caplog, _REANCHOR) == 0
