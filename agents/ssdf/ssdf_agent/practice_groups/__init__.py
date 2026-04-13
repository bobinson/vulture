"""SSDF practice group auditors."""

from ssdf_agent.practice_groups.po_prepare import audit_po
from ssdf_agent.practice_groups.ps_protect import audit_ps
from ssdf_agent.practice_groups.pw_produce import audit_pw
from ssdf_agent.practice_groups.rv_respond import audit_rv

PRACTICE_GROUP_MAP = {
    "PO": audit_po,
    "PS": audit_ps,
    "PW": audit_pw,
    "RV": audit_rv,
}

# Normalized alias for cross-agent consistency
SKILL_MAP = PRACTICE_GROUP_MAP

__all__ = ["audit_po", "audit_ps", "audit_pw", "audit_rv", "PRACTICE_GROUP_MAP", "SKILL_MAP"]
