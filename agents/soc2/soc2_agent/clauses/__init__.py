"""SOC2 compliance clause auditors."""

from soc2_agent.clauses.cc6_logical_access import audit_cc6
from soc2_agent.clauses.cc7_system_operations import audit_cc7
from soc2_agent.clauses.cc8_change_management import audit_cc8

CLAUSE_MAP = {
    "CC6": audit_cc6,
    "CC7": audit_cc7,
    "CC8": audit_cc8,
}

__all__ = ["audit_cc6", "audit_cc7", "audit_cc8", "CLAUSE_MAP"]
