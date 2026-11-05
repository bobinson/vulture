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

import json
import logging
from pathlib import Path

import pytest

from shared import audit_runner
from shared import env as shared_env
from shared.env import env_flag

_VERIFY = "VULTURE_LLM_QUOTE_VERIFY"
_REANCHOR = "VULTURE_LLM_QUOTE_REANCHOR"

# The matrix Go's config.QuoteVerifyMode / QuoteReanchorEnabled read too
# (re-audit #2): ONE list, so the two runtimes cannot drift on a spelling.
_MATRIX = (Path(__file__).resolve().parents[4] / "backend" / "internal" / "config"
           / "testdata" / "quote_switch_matrix_0074.json")
_CASES = json.loads(_MATRIX.read_text())["cases"]


def _set_or_unset(monkeypatch, name: str, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("case", _CASES, ids=lambda c: f"{c['verify']!r}/{c['reanchor']!r}")
def test_quote_switch_matrix_matches_go(case, monkeypatch, caplog) -> None:
    """C16: the normalised mode, the re-anchor gate ((mode == enforce) AND the
    REANCHOR flag) and the one-time warning on an unrecognised VERIFY value."""
    _set_or_unset(monkeypatch, _VERIFY, case["verify"])
    _set_or_unset(monkeypatch, _REANCHOR, case["reanchor"])
    shared_env._warn_unrecognised.cache_clear()
    with caplog.at_level(logging.WARNING):
        got = (audit_runner._quote_mode(), audit_runner._reanchor_enabled())
    assert got == (case["mode"], case["reanchor_enabled"])
    assert (_warnings_naming(caplog, _VERIFY) == 1) is case["warns"]


@pytest.mark.parametrize("case", [c for c in _CASES if c["reanchor_enabled"]],
                         ids=lambda c: repr(c["verify"]))
def test_reanchor_off_disarms_every_armed_row(case, monkeypatch) -> None:
    """The REANCHOR runtime rollback wins over every mode that arms it."""
    _set_or_unset(monkeypatch, _VERIFY, case["verify"])
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
