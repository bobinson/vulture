"""ASVS compliance audit skills."""

from asvs_agent.skills.asvs_requirements_check import (
    check_asvs_requirements,
    check_asvs_requirements_tool,
)

SKILL_TOOLS = [check_asvs_requirements_tool]

SKILL_MAP = {"asvs_requirements": check_asvs_requirements}

__all__ = [
    "check_asvs_requirements",
    "check_asvs_requirements_tool",
    "SKILL_TOOLS",
    "SKILL_MAP",
]
