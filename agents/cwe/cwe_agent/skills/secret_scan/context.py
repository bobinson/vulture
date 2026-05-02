"""Shared false-positive reduction utilities for secret_scan sub-modules.

Centralized so each detector applies consistent test/fixture/example
exclusions. Mirrors the SAFE_CRED_PATTERNS approach in
``auth_check.py`` but extended for the secret-scan use case.
"""

from __future__ import annotations

import re
from pathlib import Path

# Lines / contexts that indicate a value is intentionally a placeholder
# rather than a real secret.
SAFE_CONTEXT = re.compile(
    r"(?:os\.(?:environ|getenv)|process\.env|System\.getenv|"
    r"Config\.|config\[|config\.get|"
    r"placeholder|example|changeme|change-me|"
    r"<your[\w\s\-]*here>|<[A-Za-z\-_]+>|"
    r"xxx+|dummy|fake|mock|stub|"
    r"TODO|FIXME|XXX_REDACTED|REDACTED|"
    r"sample|template|"
    r"YOUR_API_KEY|YOUR_SECRET|REPLACE_ME|REPLACE_THIS)",
    re.IGNORECASE,
)


def is_safe_context_line(line: str) -> bool:
    """True if the line contains a placeholder/example marker that
    suggests the value is not a real secret."""
    return bool(SAFE_CONTEXT.search(line))


# Path-component substrings that mark a file as test/fixture material.
# Findings in such paths are downgraded by one severity level.
_TEST_PATH_MARKERS = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/fixtures/",
    "/test_data/",
    "/testdata/",
    "/test-data/",
    "/__fixtures__/",
    "/spec/",
    "/specs/",
    "/example/",
    "/examples/",
    "/sample/",
    "/samples/",
)

_TEST_FILENAME_RE = re.compile(
    r"(?:^|[/\\])(?:test_|.*_test\.|.*\.test\.|test\.|.*\.spec\.|spec_)"
)


def is_test_or_fixture_path(file_path: Path | str) -> bool:
    """True if the path looks like a test, fixture, or example file."""
    s = str(file_path).replace("\\", "/")
    if any(marker in s for marker in _TEST_PATH_MARKERS):
        return True
    # Path may not have a leading slash (e.g. relative path "tests/foo.py").
    # Match the same markers anchored at start.
    if any(s.startswith(m.lstrip("/")) for m in _TEST_PATH_MARKERS):
        return True
    return bool(_TEST_FILENAME_RE.search(s))


# Severity downgrade ladder for test/fixture findings.
_DOWNGRADE: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def downgrade_severity(severity: str) -> str:
    """Drop severity by one level (critical → high → medium → low → info)."""
    return _DOWNGRADE.get(severity, severity)


def adjust_for_path(file_path: Path | str, severity: str) -> str:
    """Return ``severity`` downgraded by one level when the path looks
    like a test/fixture, otherwise return it unchanged."""
    if is_test_or_fixture_path(file_path):
        return downgrade_severity(severity)
    return severity
