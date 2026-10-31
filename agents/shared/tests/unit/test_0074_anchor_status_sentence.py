"""Feature 0074 review item 21 — the anchor attestation states the SHIPPED
re-anchor behaviour, derived from the code rather than a stale literal.

Since O6 the defaults are ``VULTURE_LLM_QUOTE_VERIFY=enforce`` and
``VULTURE_LLM_QUOTE_REANCHOR`` on, so a re-anchor IS applied at the shipped
default. The generated ``ANCHOR_STATUS.md`` still said "recorded and not
applied", and ``--check`` passed because the golden matched the stale literal.
The sentence is now derived from ``audit_runner._reanchor_enabled()`` under the
reporter's pinned (default) environment.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from shared import audit_runner

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "report_anchor_status.py"


@pytest.fixture(scope="module")
def reporter():
    spec = importlib.util.spec_from_file_location("report_anchor_status_0074", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _outcome_intro(reporter) -> str:
    return " ".join(reporter._outcome_table([])[:3])


def test_shipped_default_is_applied(reporter, monkeypatch) -> None:
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", "false")  # the pin must ignore the shell
    text = _outcome_intro(reporter)
    assert "at the shipped default it is applied" in text
    assert "not applied" not in text


def test_sentence_follows_the_gate(reporter, monkeypatch) -> None:
    monkeypatch.setattr(audit_runner, "_reanchor_enabled", lambda: False)
    assert "at the shipped default it is recorded and not applied" in _outcome_intro(reporter)


def test_docstring_no_longer_claims_inert() -> None:
    assert "Inert on ship" not in (audit_runner._apply_reanchor.__doc__ or "")
