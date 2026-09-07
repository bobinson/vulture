"""Feature 0089 Item 4.5 — soc2/ssdf/chaos plan() feed the evidence block.

Test-first (GREEN team). The drift fix restores the Code/Hints evidence block
to the three plan strategies that had lost it (soc2, ssdf, chaos). That is only
observable end to end if each strategy's `plan()` actually passes
`code_snippet` and `verification_hints` into `render_prove_prompt` — a template
change alone would leave `{code_snippet}` unfilled and show a bare literal.

These drive the live strategy with a stubbed transport (so no LLM call, no
network) and assert the finding's code and hints reach the prompt. cwe/owasp
are covered too as a regression guard; soc2/ssdf/chaos are the three that fail
before the fix.
"""

from __future__ import annotations

import asyncio

import pytest

from prove_agent.strategies import chaos as chaos_mod
from prove_agent.strategies import cwe as cwe_mod
from prove_agent.strategies import owasp as owasp_mod
from prove_agent.strategies import soc2 as soc2_mod
from prove_agent.strategies import ssdf as ssdf_mod

_MODS = {
    "cwe": (cwe_mod, "CweStrategy"),
    "owasp": (owasp_mod, "OwaspStrategy"),
    "soc2": (soc2_mod, "Soc2Strategy"),
    "ssdf": (ssdf_mod, "SsdfStrategy"),
    "chaos": (chaos_mod, "ChaosStrategy"),
}

_FINDING = {
    "title": "Missing HSTS", "category": "CC6.1", "description": "no HSTS header",
    "file_path": "server/app.py", "line_start": 10,
    "code_snippet": "app.run(ssl=False)", "verification_hints": ["check headers"],
}


def _capture_plan_prompt(monkeypatch, mod, cls_name: str) -> str:
    captured: dict[str, str] = {}

    async def _fake(prompt, **_kwargs):
        captured["prompt"] = prompt
        return {"url_path": "/api/health", "description": "probe", "method": "GET",
                "headers": {}, "body": "", "expected_indicators": ["x"]}

    # Strategies import `llm_json_call` into their own namespace.
    monkeypatch.setattr(mod, "llm_json_call", _fake)
    strat = getattr(mod, cls_name)()
    asyncio.run(strat.plan(_FINDING, "http://staging", 1, site_context="/api/health"))
    return captured["prompt"]


@pytest.mark.parametrize("name", ["cwe", "owasp", "soc2", "ssdf", "chaos"])
def test_plan_prompt_carries_the_evidence_block(monkeypatch, name):
    mod, cls_name = _MODS[name]
    prompt = _capture_plan_prompt(monkeypatch, mod, cls_name)
    assert "Code: app.run(ssl=False)" in prompt, name
    assert "Hints: check headers" in prompt, name
