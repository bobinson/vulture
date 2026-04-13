"""Access control vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet

from cwe_agent.catalog import enrich_finding

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

# CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
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

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")

# Two-tier context: missing auth is only high with route/handler context
_ROUTE_CONTEXT = [re.compile(r"(route|handler|endpoint|controller|app\.|router\.|api)", re.I)]


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
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for access control issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""

    has_authz = AUTHZ_PRESENT.search(content) is not None
    has_ownership = OWNERSHIP_CHECK.search(content) is not None
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_missing_authz(file_path, line, line_num, has_authz, lines, content, findings)
        _check_role_string_cmp(file_path, line, line_num, lines, findings)
        _check_idor(file_path, line, line_num, has_ownership, lines, findings)
        _check_privilege(file_path, line, line_num, lines, findings)


def _check_missing_authz(
    file_path: Path,
    line: str,
    line_num: int,
    has_authz: bool,
    lines: list[str],
    content: str,
    findings: list[dict],
) -> None:
    """Check for missing authorization on routes (CWE-862)."""
    if has_authz:
        return
    for pattern in ROUTE_PATTERNS:
        if not pattern.search(line):
            continue
        # Two-tier: demote to medium if file lacks route/handler context
        severity = "high"
        if not check_context(content, _ROUTE_CONTEXT):
            severity = "medium"
        finding = {
            "severity": severity,
            "check_id": "cwe.access_control.missing_authz",
            "category": "CWE-862",
            "title": "Route handler without authorization",
            "description": f"Endpoint at line {line_num} has no visible auth check",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add authentication/authorization middleware or decorators",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "862"))
        return


def _check_role_string_cmp(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for incorrect authorization via string comparison (CWE-863)."""
    for pattern in ROLE_STRING_CMP:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.access_control.role_string_cmp",
            "category": "CWE-863",
            "title": "Role check via string comparison",
            "description": f"Direct string comparison for role at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use a role-based access control (RBAC) system instead of string checks",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "863"))
        return


def _check_idor(
    file_path: Path,
    line: str,
    line_num: int,
    has_ownership: bool,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for IDOR vulnerabilities (CWE-639)."""
    if has_ownership:
        return
    for pattern in IDOR_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.access_control.idor",
            "category": "CWE-639",
            "title": "Potential IDOR vulnerability",
            "description": f"User-supplied ID used without ownership check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Verify resource ownership before granting access",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "639"))
        return


def _check_privilege(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for improper privilege management (CWE-269)."""
    for pattern in PRIVILEGE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "critical",
            "check_id": "cwe.access_control.improper_privilege",
            "category": "CWE-269",
            "title": "Improper privilege management",
            "description": f"Excessive permissions or privilege escalation at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Apply least privilege principle; avoid running as root or using 777 permissions",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "269"))
        return


check_access_control_tool = function_tool(check_access_control)
