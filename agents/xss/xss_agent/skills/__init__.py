"""XSS vulnerability scanner skills."""

from xss_agent.skills.reflected_xss_check import (
    check_reflected_xss,
    check_reflected_xss_tool,
)
from xss_agent.skills.stored_xss_check import (
    check_stored_xss,
    check_stored_xss_tool,
)
from xss_agent.skills.dom_xss_check import (
    check_dom_xss,
    check_dom_xss_tool,
)
from xss_agent.skills.template_injection_check import (
    check_template_injection,
    check_template_injection_tool,
)
from xss_agent.skills.header_injection_check import (
    check_header_injection,
    check_header_injection_tool,
)

SKILL_TOOLS = [
    check_reflected_xss_tool,
    check_stored_xss_tool,
    check_dom_xss_tool,
    check_template_injection_tool,
    check_header_injection_tool,
]

SKILL_MAP = {
    "reflected_xss": check_reflected_xss,
    "stored_xss": check_stored_xss,
    "dom_xss": check_dom_xss,
    "template_injection": check_template_injection,
    "header_injection": check_header_injection,
}

__all__ = [
    "check_reflected_xss", "check_reflected_xss_tool",
    "check_stored_xss", "check_stored_xss_tool",
    "check_dom_xss", "check_dom_xss_tool",
    "check_template_injection", "check_template_injection_tool",
    "check_header_injection", "check_header_injection_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
