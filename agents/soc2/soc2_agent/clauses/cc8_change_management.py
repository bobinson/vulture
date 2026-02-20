"""CC8 - Change Management."""

from soc2_agent.skills.change_management import check_change_management


def audit_cc8(source_path: str) -> dict:
    """Audit CC8 (Change Management).

    Covers deployment practices and change control.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    result = check_change_management(source_path)
    return {"findings": result.get("findings", [])}
