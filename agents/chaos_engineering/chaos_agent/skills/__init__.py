"""Chaos engineering audit skills."""

from chaos_agent.skills.retry_analysis import check_retry_patterns, check_retry_patterns_tool
from chaos_agent.skills.circuit_breaker import check_circuit_breaker, check_circuit_breaker_tool
from chaos_agent.skills.timeout_analysis import check_timeout_handling, check_timeout_handling_tool
from chaos_agent.skills.fallback_analysis import check_fallback_patterns, check_fallback_patterns_tool
from chaos_agent.skills.blast_radius import assess_blast_radius, assess_blast_radius_tool

SKILL_TOOLS = [
    check_retry_patterns_tool,
    check_circuit_breaker_tool,
    check_timeout_handling_tool,
    check_fallback_patterns_tool,
    assess_blast_radius_tool,
]

SKILL_MAP = {
    "retry": check_retry_patterns,
    "circuit_breaker": check_circuit_breaker,
    "timeout": check_timeout_handling,
    "fallback": check_fallback_patterns,
    "blast_radius": assess_blast_radius,
}

__all__ = [
    "check_retry_patterns", "check_retry_patterns_tool",
    "check_circuit_breaker", "check_circuit_breaker_tool",
    "check_timeout_handling", "check_timeout_handling_tool",
    "check_fallback_patterns", "check_fallback_patterns_tool",
    "assess_blast_radius", "assess_blast_radius_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
