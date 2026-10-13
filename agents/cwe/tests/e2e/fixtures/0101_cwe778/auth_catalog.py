# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
# Feature 0101, CWE-778 Concept B in Python. Invented identifiers.
import enum


def guard(unauthorized):  # EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: a parameter on the declaration line
    if unauthorized:  # EXPECT: finding check=cwe.insufficient_logging.auth_decision
        return deny()
    return allow()


class Reason(enum.Enum):
    forbidden = enum.auto()  # EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: lowercase enum member


def make_flags(forbidden=False):  # EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: kwarg default on the declaration line
    return Flags(forbidden)  # EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: the flag passed on
