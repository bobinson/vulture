"""False positive suppression lists for scan skills.

Provides a simple mechanism to suppress known false-positive patterns
based on finding title, file glob, and optional line content.
"""

import re
from fnmatch import fnmatch
from pathlib import Path
from typing import NamedTuple

# Max suppressions per rule to prevent piggy-backing on broad rules.
MAX_SUPPRESSIONS_PER_RULE = 50


class SuppressionRule(NamedTuple):
    """A suppression rule: (title_pattern, file_glob, optional line_pattern)."""

    title_pattern: re.Pattern  # type: ignore[type-arg]
    file_glob: str
    line_pattern: re.Pattern | None  # type: ignore[type-arg]


def should_suppress(
    finding_title: str,
    file_path: Path,
    line: str,
    suppressions: list[SuppressionRule],
    suppression_counts: dict[int, int],
) -> bool:
    """Check if a finding should be suppressed based on suppression rules.

    Args:
        finding_title: Title of the candidate finding.
        file_path: Path to the source file.
        line: Source line that triggered the finding.
        suppressions: List of suppression rules to check.
        suppression_counts: Mutable counter dict tracking how many times
            each rule index has fired (anti-piggyback).

    Returns:
        True if the finding should be suppressed.
    """
    for idx, rule in enumerate(suppressions):
        if not rule.title_pattern.search(finding_title):
            continue
        if rule.file_glob and not fnmatch(str(file_path), rule.file_glob):
            continue
        if rule.line_pattern and not rule.line_pattern.search(line):
            continue
        count = suppression_counts.get(idx, 0)
        if count >= MAX_SUPPRESSIONS_PER_RULE:
            continue
        suppression_counts[idx] = count + 1
        return True
    return False


# --- Pre-built suppression lists for common false positives ---

# CWE info_exposure_check: test files with "password" in variable names
INFO_EXPOSURE_SUPPRESSIONS: list[SuppressionRule] = [
    SuppressionRule(
        title_pattern=re.compile(r"Sensitive data written to log", re.I),
        file_glob="*/test*",
        line_pattern=re.compile(r"test_|mock_|fake_|dummy_", re.I),
    ),
    SuppressionRule(
        title_pattern=re.compile(r"Cleartext storage", re.I),
        file_glob="*/example*",
        line_pattern=None,
    ),
    SuppressionRule(
        title_pattern=re.compile(r"Cleartext storage", re.I),
        file_glob="*/docs/*",
        line_pattern=None,
    ),
]

# CWE auth_check: test credential patterns
AUTH_CHECK_SUPPRESSIONS: list[SuppressionRule] = [
    SuppressionRule(
        title_pattern=re.compile(r"Hardcoded credentials", re.I),
        file_glob="*/test*",
        line_pattern=re.compile(r"test_|mock_|fake_|dummy_|fixture", re.I),
    ),
    SuppressionRule(
        title_pattern=re.compile(r"Hardcoded credentials", re.I),
        file_glob="",
        line_pattern=re.compile(r"(?:example|sample|demo|template)\s*[:=]", re.I),
    ),
]
