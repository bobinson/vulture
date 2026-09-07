"""Feature 0079 B1: probe the provider before the LLM sweep, fleet-wide.

Six agents (chaos, soc2, ssdf, xss, do178c, asvs) had no preflight. Correcting
my first write-up: they DO degrade gracefully — reactively, via the guard at
`audit_runner.py:2346` which emits "LLM phase unavailable" and sets
`degraded_reason`. What they lacked is the ability to skip the sweep BEFORE
burning the failure budget.

Two measured costs of not having it:

* Wall clock. With an unreachable endpoint each batch is bounded by
  VULTURE_LLM_CALL_TIMEOUT_SEC and the sweep aborts only after
  VULTURE_LLM_MAX_CONSECUTIVE_FAILURES — 3 x 120s ~ 6 minutes, replaced by one
  ~3s probe.
* That abort is gated on `batch_idx + 1 < len(batches)`, so on a tree producing
  <= 3 batches it NEVER fires and the operator gets silently wasted calls with
  no notice at all.

The probe lives in run_combined_audit, not in a per-agent wrapper: one edit
reaches every agent, and it sits INSIDE the cancel token and whole-audit
deadline, which a wrapper around the runner would not.
"""

from __future__ import annotations

import pytest

from shared import audit_runner


def test_default_mode_is_observe():
    """observe runs the probe and logs; it never vetoes. Findings are
    byte-identical to pre-0079 on the shipping default."""
    assert audit_runner._preflight_mode() == "observe"


@pytest.mark.parametrize(
    "value,want",
    [("off", "off"), ("observe", "observe"), ("enforce", "enforce"),
     ("ENFORCE", "enforce"), (" observe ", "observe"),
     ("nonsense", "observe"), ("", "observe")],
)
def test_mode_parsing(monkeypatch, value, want):
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", value)
    assert audit_runner._preflight_mode() == want


def test_no_probe_when_llm_is_already_off(monkeypatch):
    """Costs nothing when there is no LLM phase to protect. A probe here would
    add a network call to every skills-only audit."""
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True
        raise AssertionError("must not probe when use_llm is False")

    monkeypatch.setattr(audit_runner, "_probe_llm_reachable", _boom)
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "enforce")
    veto, notice = audit_runner._preflight_vetoes(False, "run", "CWE")
    assert veto is False and notice == "" and not called


def test_observe_never_vetoes_even_when_unhealthy(monkeypatch):
    """THE inertness property. observe may log, but a finding count must not
    move on the shipping default."""
    monkeypatch.setattr(audit_runner, "_probe_llm_reachable",
                        lambda: (False, "connection refused"))
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "observe")
    veto, notice = audit_runner._preflight_vetoes(True, "run", "CWE")
    assert veto is False


def test_enforce_vetoes_when_unreachable(monkeypatch):
    """NON-VACUITY. An unreachable provider must actually skip the sweep, and
    say so — a guard that cannot fire has shipped in this codebase before."""
    monkeypatch.setattr(audit_runner, "_probe_llm_reachable",
                        lambda: (False, "connection refused"))
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "enforce")
    veto, notice = audit_runner._preflight_vetoes(True, "run", "CWE")
    assert veto is True
    assert notice, "a veto must be reported, never silent"
    assert "connection refused" in notice, (
        "the notice must name the CAUSE; the whole point is replacing an opaque "
        "litellm error with a legible reason"
    )


def test_enforce_allows_when_healthy(monkeypatch):
    """The reverse direction. A healthy provider must never be vetoed, or the
    feature silently disables the LLM tier."""
    monkeypatch.setattr(audit_runner, "_probe_llm_reachable", lambda: (True, ""))
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "enforce")
    veto, _ = audit_runner._preflight_vetoes(True, "run", "CWE")
    assert veto is False


def test_off_skips_the_probe_entirely(monkeypatch):
    called = False

    def _mark():
        nonlocal called
        called = True
        return (False, "down")

    monkeypatch.setattr(audit_runner, "_probe_llm_reachable", _mark)
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "off")
    veto, _ = audit_runner._preflight_vetoes(True, "run", "CWE")
    assert veto is False and not called


def test_a_probe_failure_never_vetoes(monkeypatch):
    """Fail OPEN. If the probe itself raises, that is a fault in the guard, not
    evidence the provider is down — vetoing on it would let a broken probe
    disable the LLM tier fleet-wide."""
    def _raise():
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(audit_runner, "_probe_llm_reachable", _raise)
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "enforce")
    veto, _ = audit_runner._preflight_vetoes(True, "run", "CWE")
    assert veto is False, "a probe fault must fail open"
