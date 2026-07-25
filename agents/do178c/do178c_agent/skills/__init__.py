"""DO-178C skill registry."""

from do178c_agent.skills.dead_code_check import check_dead_code, check_dead_code_tool
from do178c_agent.skills.mcdc_coverage import check_mcdc_coverage, check_mcdc_coverage_tool
from do178c_agent.skills.recursion_check import check_recursion, check_recursion_tool
from do178c_agent.skills.malloc_check import check_malloc, check_malloc_tool
from do178c_agent.skills.traceability_check import check_traceability, check_traceability_tool
from do178c_agent.skills.timing_check import check_timing, check_timing_tool

SKILL_MAP = {
    "dead_code": check_dead_code,
    "mcdc_coverage": check_mcdc_coverage,
    "recursion": check_recursion,
    "malloc": check_malloc,
    "traceability": check_traceability,
    "timing": check_timing,
}

SKILL_TOOLS = [
    check_dead_code_tool,
    check_mcdc_coverage_tool,
    check_recursion_tool,
    check_malloc_tool,
    check_traceability_tool,
    check_timing_tool,
]
