"""Guardrail: the OWASP agent performs no detection (feature 0063).

Asserted via imports/introspection, not substring grep, so it stays robust
if detection logic were ever (re)introduced in a helper module.
"""

import pkgutil


def test_skills_package_exposes_no_detection():
    from owasp_agent import skills

    assert skills.SKILL_MAP == {}
    assert skills.SKILL_TOOLS == []


def test_no_detection_skill_modules_remain():
    from owasp_agent import skills

    names = [m.name for m in pkgutil.iter_modules(skills.__path__)]
    assert names == [], f"unexpected detection skill modules present: {names}"


def test_agent_does_not_bind_detection_symbols():
    from owasp_agent import agent

    assert not hasattr(agent, "run_combined_audit")
    assert not hasattr(agent, "SKILL_MAP")
    assert not hasattr(agent, "SKILL_TOOLS")
