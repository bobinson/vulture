"""Feature 0059 (PART B): per-audit Tier-3 LLM toggle is honored fleet-wide.

The CWE agent already forwards ``config.llm_tier3`` to ``run_combined_audit``
as ``llm_tier3=``. This test pins that EVERY non-CWE scan agent does the same,
so the ``--llm-tier3`` CLI flag / ``config.llm_tier3`` request field works for
the whole fleet (resolution order: config > VULTURE_LLM_TIER3 env > OFF).

Contract proven, per agent:
  * config={"llm_tier3": True}  -> run_combined_audit receives llm_tier3=True
  * config={}                   -> run_combined_audit receives llm_tier3=None
                                   (None lets the shared collector apply the
                                    env/OFF default — i.e. OFF by default)

Fully deterministic: ``run_combined_audit`` is monkeypatched in each agent's
module to a recorder that captures kwargs and yields nothing, and
``build_prior_context`` is stubbed to avoid any memory/network round-trip.
No live LLM is ever called.
"""

from __future__ import annotations

import importlib

import pytest

# (module path under the venv, entry function name). All 7 non-CWE scan agents
# expose ``run_audit(run_id, source_path, config, prior_findings=None)`` and
# fall back to their full category set when config omits categories, so an
# empty config still reaches the run_combined_audit call.
SCAN_AGENTS = [
    ("chaos_agent.agent", "run_audit"),
    ("asvs_agent.agent", "run_audit"),
    ("owasp_agent.agent", "run_audit"),
    ("xss_agent.agent", "run_audit"),
    ("soc2_agent.agent", "run_audit"),
    ("ssdf_agent.agent", "run_audit"),
    ("do178c_agent.agent", "run_audit"),
]


def _install_recorder(monkeypatch, module):
    """Patch run_combined_audit + build_prior_context in *module*.

    Returns a dict that the recorder fills with the call kwargs. The recorder
    yields nothing (skills-only, no findings), so the agent generator completes
    without invoking any real audit work or LLM.
    """
    captured: dict = {}

    def _fake_run_combined_audit(*args, **kwargs):
        captured["kwargs"] = kwargs
        captured["args"] = args
        return []  # `yield from []` in the agent -> empty event stream

    monkeypatch.setattr(module, "run_combined_audit", _fake_run_combined_audit)
    # Stub the memory lookup so no backend HTTP call happens during the test.
    monkeypatch.setattr(module, "build_prior_context", lambda *a, **k: "")
    return captured


@pytest.mark.parametrize("module_path,entry_name", SCAN_AGENTS)
def test_tier3_true_forwarded(module_path, entry_name, tmp_path, monkeypatch):
    """config.llm_tier3=True must reach run_combined_audit as llm_tier3=True."""
    module = importlib.import_module(module_path)
    captured = _install_recorder(monkeypatch, module)
    run_audit = getattr(module, entry_name)

    list(run_audit("tier3-on", str(tmp_path), {"llm_tier3": True}))

    assert "kwargs" in captured, (
        f"{module_path} never called run_combined_audit"
    )
    assert captured["kwargs"].get("llm_tier3") is True, (
        f"{module_path} did not forward config.llm_tier3=True "
        f"(got {captured['kwargs'].get('llm_tier3')!r})"
    )


@pytest.mark.parametrize("module_path,entry_name", SCAN_AGENTS)
def test_tier3_default_is_none(module_path, entry_name, tmp_path, monkeypatch):
    """With no llm_tier3 in config, llm_tier3 must be None (env/OFF default)."""
    module = importlib.import_module(module_path)
    captured = _install_recorder(monkeypatch, module)
    run_audit = getattr(module, entry_name)

    list(run_audit("tier3-default", str(tmp_path), {}))

    assert "kwargs" in captured, (
        f"{module_path} never called run_combined_audit"
    )
    assert captured["kwargs"].get("llm_tier3") is None, (
        f"{module_path} must pass llm_tier3=None when config omits it so the "
        f"shared collector applies the VULTURE_LLM_TIER3/OFF default "
        f"(got {captured['kwargs'].get('llm_tier3')!r})"
    )
