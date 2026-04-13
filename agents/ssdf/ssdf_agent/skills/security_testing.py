"""PW.8 - Security testing audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe
from ssdf_agent.skills._ci_utils import gather_ci_content

_SECURITY_TEST_PATTERNS = re.compile(
    r"test.*security|test.*auth|test.*xss|test.*injection|test.*csrf|security.*test",
    re.IGNORECASE,
)

_FUZZ_PATTERNS = re.compile(
    r"fuzz_|FuzzTest|fuzzing|hypothesis|atheris|go-fuzz",
    re.IGNORECASE,
)

_COVERAGE_GATE_PATTERNS = re.compile(
    r"coverage.*threshold|cov-fail-under|coverageThreshold|minimum.?coverage|--cov",
    re.IGNORECASE,
)


def check_security_testing(source_path: str) -> dict:
    """Check for security testing practices (PW.8).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_security_tests(root):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw8.no_security_tests",
            "category": "PW-produce-well-secured-software",
            "title": "No dedicated security test files found",
            "description": "No test files focused on security testing (auth, injection, XSS) found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Add dedicated security test suites for auth, injection, and access control",
        })

    if not _find_fuzz_tests(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.pw8.no_fuzz_tests",
            "category": "PW-produce-well-secured-software",
            "title": "No fuzz testing configured",
            "description": "No fuzz testing framework (go-fuzz, hypothesis, atheris) found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Implement fuzz testing for input parsing and data processing functions",
        })

    ci_content = gather_ci_content(root)
    if not _COVERAGE_GATE_PATTERNS.search(ci_content):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.pw8.no_coverage_gate",
            "category": "PW-produce-well-secured-software",
            "title": "No test coverage enforcement in CI",
            "description": "No test coverage threshold or gate found in CI configuration",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Add coverage thresholds to CI to enforce minimum test coverage",
        })

    return {"findings": findings}


def _find_security_tests(root: Path) -> bool:
    """Check for security-focused test files."""
    # Search test directories with targeted globs instead of rglob("*")
    for pattern in ("**/test*security*", "**/security*test*", "**/test*auth*",
                    "**/test*xss*", "**/test*injection*", "**/test*csrf*"):
        for item in root.rglob(pattern):
            if item.is_file():
                return True
    return False


def _find_fuzz_tests(root: Path) -> bool:
    """Check for fuzz test files or configs."""
    # Targeted glob for fuzz_ prefixed files
    for item in root.rglob("fuzz_*"):
        if item.is_file():
            return True
    # Targeted search for __fuzz__ dirs
    for item in root.rglob("__fuzz__"):
        if item.is_dir():
            return True
    # Check for fuzz patterns in test files
    for item in root.rglob("*test*"):
        if not item.is_file():
            continue
        content = read_file_safe(item)
        if content and _FUZZ_PATTERNS.search(content):
            return True
    return False


check_security_testing_tool = function_tool(check_security_testing)
