"""CC6 - Logical and Physical Access Controls."""

from soc2_agent.skills.access_logging import check_access_logging
from soc2_agent.skills.encryption_check import check_encryption
from soc2_agent.skills.data_retention import check_data_retention


def audit_cc6(source_path: str) -> dict:
    """Audit CC6 (Logical and Physical Access Controls).

    Covers access logging, encryption, and data retention.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []

    for check_fn in (check_access_logging, check_encryption, check_data_retention):
        result = check_fn(source_path)
        findings.extend(result.get("findings", []))

    return {"findings": findings}
