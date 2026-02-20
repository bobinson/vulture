"""CWE authentication vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-798: Hardcoded credentials
HARDCODED_CRED_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
    re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
    re.compile(r'(?:secret_key|secret)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:AWS_SECRET|PRIVATE_KEY)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
]

SAFE_CRED_PATTERNS = re.compile(
    r'(?:os\.(?:environ|getenv)|process\.env|Config\.|config\[|'
    r'placeholder|example|changeme|xxx|test|dummy|fake|mock|<|TODO|FIXME)',
    re.IGNORECASE,
)

# CWE-287: Improper authentication (weak hashing for passwords)
WEAK_AUTH_PATTERNS = [
    re.compile(r'(?:md5|MD5)\s*\([^)]*(?:password|passwd|pwd)', re.IGNORECASE),
    re.compile(r'(?:sha1|SHA1)\s*\([^)]*(?:password|passwd|pwd)', re.IGNORECASE),
    re.compile(r'hashlib\.(?:md5|sha1)\([^)]*(?:password|passwd)', re.IGNORECASE),
    re.compile(r'(?:password|passwd)\s*==\s*(?:request|req|params|input|body)', re.IGNORECASE),
    re.compile(r'(?:request|req|params|input|body)\S*\s*==\s*\S*(?:password|passwd)', re.IGNORECASE),
]

# CWE-306: Missing authentication on critical function
UNPROTECTED_ROUTE_PATTERNS = [
    re.compile(r'@app\.(?:route|post|put|delete|patch)\s*\([^)]*\)\s*$'),
    re.compile(r'router\.(?:post|put|delete|patch)\s*\([^)]*,\s*(?:async\s+)?(?:function|\(|handler)'),
    re.compile(r'\.(?:Post|Put|Delete|Patch)\s*\([^)]*,\s*\w+Handler'),
]

SAFE_AUTH_DECORATORS = re.compile(
    r'(?:@login_required|@auth|@require_auth|@authenticated|'
    r'@permission|@protect|middleware\.|auth_required|isAuthenticated|'
    r'@jwt_required|@token_required)',
    re.IGNORECASE,
)

# CWE-521: Weak password requirements
WEAK_PASSWORD_PATTERNS = [
    re.compile(r'(?:min.?(?:length|len))\s*(?:=|:)\s*[1-5]\b', re.IGNORECASE),
    re.compile(r'len\(\s*password\s*\)\s*(?:>=?|>)\s*[1-5]\b'),
    re.compile(r'\.length\s*(?:>=?|>)\s*[1-5]\b'),
    re.compile(r'password.*(?:min|minimum).*[1-5]\b', re.IGNORECASE),
]

SAFE_PASSWORD_VALIDATION = re.compile(
    r'(?:bcrypt|argon2|scrypt|pbkdf2|zxcvbn|password.?strength)',
    re.IGNORECASE,
)

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_authentication(source_path: str) -> dict:
    """Check for CWE authentication vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of authentication vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for authentication patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_hardcoded_creds(file_path, line, line_num, findings, is_test=is_test)
        _check_weak_auth(file_path, line, line_num, findings, is_test=is_test)
        _check_missing_auth(file_path, line, line_num, lines, findings, is_test=is_test)
        _check_weak_password(file_path, line, line_num, findings, is_test=is_test)


def _check_hardcoded_creds(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-798 hardcoded credentials."""
    if SAFE_CRED_PATTERNS.search(line):
        return
    for pattern in HARDCODED_CRED_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-798",
                "title": "Hardcoded credentials detected",
                "description": f"Possible hardcoded secret at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager",
            })
            return


def _check_weak_auth(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-287 improper authentication."""
    for pattern in WEAK_AUTH_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-287",
                "title": "Weak authentication mechanism",
                "description": f"Weak hash or direct password comparison at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use bcrypt, argon2, or scrypt for password hashing",
            })
            return


def _check_missing_auth(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], *, is_test: bool,
) -> None:
    """Check for CWE-306 missing authentication on critical functions."""
    for pattern in UNPROTECTED_ROUTE_PATTERNS:
        if not pattern.search(line):
            continue
        # Look at preceding 3 lines for auth decorators/middleware
        context_start = max(0, line_num - 4)
        preceding = "\n".join(lines[context_start:line_num - 1])
        if SAFE_AUTH_DECORATORS.search(preceding):
            return
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-306",
            "title": "Missing authentication on endpoint",
            "description": f"Route handler without auth check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add authentication middleware or decorator to protect endpoint",
        })
        return


def _check_weak_password(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-521 weak password requirements."""
    if SAFE_PASSWORD_VALIDATION.search(line):
        return
    for pattern in WEAK_PASSWORD_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "medium",
                "category": "CWE-521",
                "title": "Weak password requirements",
                "description": f"Insufficient password validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Enforce minimum 8 characters with complexity requirements",
            })
            return


check_authentication_tool = function_tool(check_authentication)
