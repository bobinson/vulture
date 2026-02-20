"""Access control vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-862: Missing authorization
ROUTE_PATTERNS = [
    re.compile(r"@app\.(?:route|get|post|put|delete|patch)\s*\("),  # Flask/FastAPI
    re.compile(r"router\.(?:GET|POST|PUT|DELETE|Handle)\w*\s*\("),  # Go
    re.compile(r"@(?:Get|Post|Put|Delete|Patch)Mapping\s*\("),  # Java Spring
    re.compile(r"app\.(?:get|post|put|delete|patch)\s*\("),  # Express.js
]
AUTHZ_PRESENT = re.compile(
    r"\b(?:requires_auth|login_required|@authenticate|@authorize|"
    r"RequireAuth|authMiddleware|IsAuthenticated|jwt_required|"
    r"@permission_required|protect|guard|@UseGuards)\b",
    re.IGNORECASE,
)

# CWE-863: Incorrect authorization via string comparison
ROLE_STRING_CMP = [
    re.compile(r'(?:role|user_role|userRole)\s*==\s*["\'](?:admin|root|superuser)["\']'),
    re.compile(r'["\'](?:admin|root|superuser)["\']\s*==\s*(?:role|user_role|userRole)'),
]

# CWE-284: IDOR patterns
IDOR_PATTERNS = [
    re.compile(r'request\.(?:args|params|query)\[?["\'](?:\w*id)["\']'),
    re.compile(r'request\.form\[?["\'](?:\w*id)["\']'),
    re.compile(r'r\.URL\.Query\(\)\.Get\(\s*"[a-z_]*id"'),
    re.compile(r'params\[[\'"]\w*id[\'"]\]'),
]
OWNERSHIP_CHECK = re.compile(
    r"\b(?:check_owner|verify_owner|is_owner|belongs_to|owned_by|current_user\.id)\b",
    re.IGNORECASE,
)

# CWE-269: Improper privilege management
PRIVILEGE_PATTERNS = [
    re.compile(r"chmod\s+777\b"),
    re.compile(r"os\.chmod\([^)]*0o?777"),
    re.compile(r'(?:run|exec).*(?:--privileged|as\s+root|USER\s+root)', re.IGNORECASE),
    re.compile(r"setuid\s*\(\s*0\s*\)"),
]

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")


def check_access_control(source_path: str) -> dict:
    """Check for access control vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of access control issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for access control issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_authz = AUTHZ_PRESENT.search(content) is not None
    has_ownership = OWNERSHIP_CHECK.search(content) is not None

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_missing_authz(file_path, line, line_num, has_authz, findings, is_test=is_test)
        _check_role_string_cmp(file_path, line, line_num, findings, is_test=is_test)
        _check_idor(file_path, line, line_num, has_ownership, findings, is_test=is_test)
        _check_privilege(file_path, line, line_num, findings, is_test=is_test)


def _check_missing_authz(
    file_path: Path,
    line: str,
    line_num: int,
    has_authz: bool,
    findings: list[dict],
    *,
    is_test: bool,
) -> None:
    """Check for missing authorization on routes (CWE-862)."""
    if has_authz:
        return
    for pattern in ROUTE_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-862",
            "title": "Route handler without authorization",
            "description": f"Endpoint at line {line_num} has no visible auth check",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add authentication/authorization middleware or decorators",
        })
        return


def _check_role_string_cmp(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for incorrect authorization via string comparison (CWE-863)."""
    for pattern in ROLE_STRING_CMP:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-863",
            "title": "Role check via string comparison",
            "description": f"Direct string comparison for role at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use a role-based access control (RBAC) system instead of string checks",
        })
        return


def _check_idor(
    file_path: Path,
    line: str,
    line_num: int,
    has_ownership: bool,
    findings: list[dict],
    *,
    is_test: bool,
) -> None:
    """Check for IDOR vulnerabilities (CWE-284)."""
    if has_ownership:
        return
    for pattern in IDOR_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-284",
            "title": "Potential IDOR vulnerability",
            "description": f"User-supplied ID used without ownership check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Verify resource ownership before granting access",
        })
        return


def _check_privilege(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for improper privilege management (CWE-269)."""
    for pattern in PRIVILEGE_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "medium" if is_test else "critical",
            "category": "CWE-269",
            "title": "Improper privilege management",
            "description": f"Excessive permissions or privilege escalation at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Apply least privilege principle; avoid running as root or using 777 permissions",
        })
        return


check_access_control_tool = function_tool(check_access_control)
