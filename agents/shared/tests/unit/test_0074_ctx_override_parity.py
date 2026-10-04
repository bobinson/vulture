"""Feature 0074 review item 6 — ``VULTURE_LLM_CTX_SIZE`` is read by one rule
in both runtimes.

``backend/internal/broker/modelmeta/testdata/ctx_override_cases_0074.json`` is
read by the Go modelmeta resolver tests and here. An override counts only when
it trims to a POSITIVE integer; anything else (blank, zero, negative,
non-numeric) means "no override" and resolution falls through to the next
source. Before the fix Python honoured ``0`` and ``-1`` as a top-priority
``env`` window, which shrank the source budget to its 2000-char floor and
truncated a prompt to a few dozen characters.

All fixtures are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared import audit_runner
from shared.llm import provider

_FIXTURE = (Path(__file__).resolve().parents[4] / "backend" / "internal" / "broker"
            / "modelmeta" / "testdata" / "ctx_override_cases_0074.json")
_CASES = json.loads(_FIXTURE.read_text())["cases"]
_TABLE_MODEL = "gpt-4o"


@pytest.mark.parametrize("case", _CASES, ids=lambda c: repr(c["override"]))
def test_override_honoured_only_when_positive(case, monkeypatch) -> None:
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", case["override"])
    got = provider.resolve_context_window(_TABLE_MODEL)
    fallback = (provider.CONTEXT_WINDOWS[_TABLE_MODEL], provider.WINDOW_FROM_TABLE)
    expected = (case["window"], provider.WINDOW_FROM_ENV) if case["honoured"] else fallback
    assert got == expected


@pytest.mark.parametrize("case", [c for c in _CASES if not c["honoured"]],
                         ids=lambda c: repr(c["override"]))
def test_ignored_override_leaves_the_source_budget_alone(case, monkeypatch) -> None:
    """A rejected override never sizes the per-batch source budget."""
    baseline = audit_runner._get_max_source_chars(_TABLE_MODEL)
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", case["override"])
    assert audit_runner._get_max_source_chars(_TABLE_MODEL) == baseline
