# Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
# A StrEnum NAMES outcomes in an indented class body; returning one after a failed
# check is the decision. Every identifier is invented.
# HELD-OUT-TOKENS: StrEnum
from enum import StrEnum


class Outcome(StrEnum):
    GRANTED = "granted"
    UNAUTHORIZED = "unauthorized"  # EXPECT: clean check=cwe.insufficient_logging.auth_decision
    FORBIDDEN = "forbidden"  # EXPECT: clean check=cwe.insufficient_logging.auth_decision


def admit(badge, door):
    if not badge.is_active():
        return Outcome.UNAUTHORIZED  # EXPECT: finding check=cwe.insufficient_logging.auth_decision
    return Outcome.GRANTED
