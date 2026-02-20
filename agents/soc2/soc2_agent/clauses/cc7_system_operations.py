"""CC7 - System Operations."""

from soc2_agent.skills.monitoring_check import check_monitoring


def audit_cc7(source_path: str) -> dict:
    """Audit CC7 (System Operations).

    Covers monitoring, alerting, and incident response.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    result = check_monitoring(source_path)
    return {"findings": result.get("findings", [])}
