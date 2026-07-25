"""SOC2 compliance audit skills."""

from soc2_agent.skills.access_logging import check_access_logging, check_access_logging_tool
from soc2_agent.skills.encryption_check import check_encryption, check_encryption_tool
from soc2_agent.skills.change_management import check_change_management, check_change_management_tool
from soc2_agent.skills.monitoring_check import check_monitoring, check_monitoring_tool
from soc2_agent.skills.data_retention import check_data_retention, check_data_retention_tool

SKILL_TOOLS = [
    check_access_logging_tool,
    check_encryption_tool,
    check_change_management_tool,
    check_monitoring_tool,
    check_data_retention_tool,
]

SKILL_MAP = {
    "access_logging": check_access_logging,
    "encryption": check_encryption,
    "change_management": check_change_management,
    "monitoring": check_monitoring,
    "data_retention": check_data_retention,
}

__all__ = [
    "check_access_logging", "check_access_logging_tool",
    "check_encryption", "check_encryption_tool",
    "check_change_management", "check_change_management_tool",
    "check_monitoring", "check_monitoring_tool",
    "check_data_retention", "check_data_retention_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
