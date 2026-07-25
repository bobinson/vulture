"""CWE authentication vulnerability detection skill."""

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
from shared.tools.suppression import should_suppress, AUTH_CHECK_SUPPRESSIONS

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref


# CWE-798: Hardcoded credentials.
#
# Length floor raised to 8 chars for password/api_key/etc. — the prior
# 3-char minimum trapped fixture-style assignments like
#   password = "abc"
#   pwd = "test"
# producing constant noise in non-test files that happen to define
# example credentials. 8 chars matches conventional hardcoded-secret
# heuristics (most real keys/tokens far exceed 8). Trade-off: a real
# 6-char admin password slips through; the SAFE_CRED_PATTERNS line-
# context filter and downstream LLM phase pick those up.
HARDCODED_CRED_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
    re.compile(r'(?:secret_key|secret)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
    re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
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

# CWE-521: Weak password requirements.
#
# Common idioms covered:
#   1. min_length = 5      / minLength: 5
#   2. len(password) >= 6  / .length > 5
#   3. len(password) < 8   / .length < 8       (operator inverted —
#                                              the previously-missed
#                                              variant; this is the
#                                              MOST common Python form)
#   4. password.*(min|minimum).*5
#   5. Django MinLengthValidator(4) / MinimumLengthValidator(min_length=5)
WEAK_PASSWORD_PATTERNS = [
    re.compile(r'(?:min.?(?:length|len))\s*(?:=|:)\s*[1-7]\b', re.IGNORECASE),
    re.compile(r'len\(\s*password\s*\)\s*(?:>=?|>)\s*[1-7]\b'),
    re.compile(r'\.length\s*(?:>=?|>)\s*[1-7]\b'),
    re.compile(r'password.*(?:min|minimum).*[1-7]\b', re.IGNORECASE),
    # Inverted-operator form: `if len(password) < 8: reject` is a weak
    # bound — flag when bound is below 8.
    re.compile(r'len\(\s*(?:password|passwd|pwd)\s*\)\s*<\s*[1-7]\b', re.IGNORECASE),
    re.compile(r'(?:password|passwd|pwd)\.length\s*<\s*[1-7]\b', re.IGNORECASE),
    # Django validator with weak min_length kwarg
    re.compile(r'(?:Min(?:imum)?LengthValidator)\s*\(\s*(?:min_length\s*=\s*)?[1-7]\b'),
]

SAFE_PASSWORD_VALIDATION = re.compile(
    r'(?:bcrypt|argon2|scrypt|pbkdf2|zxcvbn|password.?strength)',
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

# Two-tier context: hardcoded creds are critical only with auth/connection context
_CREDENTIAL_CONTEXT = [re.compile(r"(connect|login|auth|session|database)", re.I)]


def check_authentication(source_path: str) -> dict:
    """Check for CWE authentication vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of authentication vulnerabilities.
    """
    findings: list[dict] = []
    suppression_counts: dict[int, int] = {}

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings, suppression_counts)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    """Analyze a file for authentication patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_hardcoded_creds(file_path, line, line_num, lines, content, findings, suppression_counts)
        _check_weak_auth(file_path, line, line_num, lines, findings)
        _check_missing_auth(file_path, line, line_num, lines, findings)
        _check_weak_password(file_path, line, line_num, lines, findings)


def _check_hardcoded_creds(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for CWE-798 hardcoded credentials.

    Suppresses lines whose RHS is a variable reference (`$VAR`,
    `${VAR}`, `{{ var }}`, `%(VAR)s`, etc.) — those are env / template
    indirections, not literal secrets. CI YAML files in particular are
    full of these false positives.
    """
    if SAFE_CRED_PATTERNS.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in HARDCODED_CRED_PATTERNS:
        if pattern.search(line):
            # Two-tier: demote to medium if file lacks auth/connection context
            severity = "critical"
            if not check_context(content, _CREDENTIAL_CONTEXT):
                severity = "medium"
            finding = {
                "severity": severity,
                "check_id": "cwe.auth.hardcoded_cred",
                "category": "CWE-798",
                "title": "Hardcoded credentials detected",
                "description": f"Possible hardcoded secret at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager",
                "verification_hints": ["Check if credential is used in production config", "Verify no env var override"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            if should_suppress(finding["title"], file_path, line, AUTH_CHECK_SUPPRESSIONS, suppression_counts):
                return
            findings.append(enrich_finding(finding, "798"))
            return


def _check_weak_auth(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-287 improper authentication."""
    for pattern in WEAK_AUTH_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.auth.weak_mechanism",
                "category": "CWE-287",
                "title": "Weak authentication mechanism",
                "description": f"Weak hash or direct password comparison at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use bcrypt, argon2, or scrypt for password hashing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "287"))
            return


def _check_missing_auth(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
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
        finding = {
            "severity": "high",
            "check_id": "cwe.auth.missing_auth",
            "category": "CWE-306",
            "title": "Missing authentication on endpoint",
            "description": f"Route handler without auth check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add authentication middleware or decorator to protect endpoint",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "306"))
        return


def _check_weak_password(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-521 weak password requirements."""
    if SAFE_PASSWORD_VALIDATION.search(line):
        return
    for pattern in WEAK_PASSWORD_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.auth.weak_password",
                "category": "CWE-521",
                "title": "Weak password requirements",
                "description": f"Insufficient password validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Enforce minimum 8 characters with complexity requirements",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "521"))
            return


check_authentication_tool = function_tool(check_authentication)
