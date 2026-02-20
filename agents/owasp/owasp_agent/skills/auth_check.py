"""Authentication vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

WEAK_AUTH_PATTERNS = [
    re.compile(r"\bmd5\(|\bMD5\(|hashlib\.md5"),
    re.compile(r"\bsha1\(|\bSHA1\(|hashlib\.sha1"),
    re.compile(r'password\s*==\s*["\']'),
    re.compile(r"(?:hardcoded|default).?password\s*=", re.IGNORECASE),
]

SKIP_LINE_PATTERNS = re.compile(r"re\.compile|PATTERN|regex|pattern.*=.*compile", re.IGNORECASE)
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")

MISSING_AUTH_PATTERNS = [
    re.compile(r"@app\.route\(.*methods.*POST", re.IGNORECASE),
    re.compile(r"@(?:app|router)\.(?:post|put|patch|delete)\(.*/api/", re.IGNORECASE),
]

AUTH_DECORATOR_PATTERNS = [
    re.compile(r"@login_required|@auth|@authenticated|@requires_auth", re.IGNORECASE),
    re.compile(r"@permission|@role_required|@jwt_required", re.IGNORECASE),
]


def check_authentication(source_path: str) -> dict:
    """Check for authentication weaknesses.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of authentication issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for authentication issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SKIP_LINE_PATTERNS.search(line):
            continue
        for pattern in WEAK_AUTH_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": "low" if is_test else "high",
                    "category": "A07-auth-failure",
                    "title": "Weak authentication mechanism",
                    "description": f"Weak auth pattern at line {line_num}",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Use bcrypt or argon2 for password hashing",
                })
                break

    _check_missing_auth(file_path, content, lines, findings, is_test=is_test)


def _check_missing_auth(
    file_path: Path, content: str, lines: list[str], findings: list[dict], *, is_test: bool
) -> None:
    """Check for sensitive endpoints missing authentication decorators."""
    if is_test:
        return
    if any(p.search(content) for p in AUTH_DECORATOR_PATTERNS):
        return
    for line_num, line in enumerate(lines, start=1):
        if any(p.search(line) for p in MISSING_AUTH_PATTERNS):
            findings.append({
                "severity": "high",
                "category": "A07-auth-failure",
                "title": "Missing authentication on sensitive endpoint",
                "description": f"Sensitive endpoint without auth at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add authentication decorator to protect this endpoint",
            })
            return


check_authentication_tool = function_tool(check_authentication)
