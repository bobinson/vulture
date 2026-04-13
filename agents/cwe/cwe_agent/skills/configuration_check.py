"""Configuration and deployment security detection skill."""

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

# CWE-1188: Insecure Default Initialization of Resource
INSECURE_DEFAULT_PATTERNS = [
    re.compile(r'(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|"true")', re.IGNORECASE),
    re.compile(r'(?:CORS_ALLOW_ALL|allow_all_origins|AllowAllOrigins)\s*[:=]\s*(?:True|true|1)', re.IGNORECASE),
    re.compile(r'(?:verify|ssl_verify|VERIFY_SSL)\s*[:=]\s*(?:False|false|0)', re.IGNORECASE),
    re.compile(r'(?:secure|SECURE)\s*[:=]\s*(?:False|false|0)', re.IGNORECASE),
    re.compile(r'(?:ALLOWED_HOSTS|allowedHosts)\s*[:=]\s*\[\s*["\']?\*["\']?\s*\]', re.IGNORECASE),
]

SAFE_DEFAULT_PATTERNS = re.compile(
    r"(?:test|spec|_test\.|\.test\.|development|dev\.config|example|sample|template)",
    re.IGNORECASE,
)

# Per-pattern Weakness CWE IDs (CWE-16 is a Category/Obsolete, not a Weakness)
MISCONFIGURATION_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?:bind|listen|host)\s*[:=]\s*['\"]0\.0\.0\.0['\"]"),
     "668", "Service bound to all interfaces"),
    (re.compile(r'(?:TLS|tls|ssl).*(?:min|minimum).*(?:1\.0|SSLv|TLSv1[^.])', re.IGNORECASE),
     "326", "Weak TLS/SSL protocol version"),
    (re.compile(r'InsecureSkipVerify\s*:\s*true', re.IGNORECASE),
     "295", "Certificate verification disabled"),
    (re.compile(r'(?:HSTS|Strict-Transport-Security).*max-age\s*[:=]\s*(?:[0-9]{1,4})\b'),
     "319", "Weak HSTS max-age value"),
]

# CWE-732: Incorrect Permission Assignment for Critical Resource
PERMISSION_PATTERNS = [
    re.compile(r"chmod\s+(?:666|667|776|777)\b"),
    re.compile(r"os\.chmod\([^)]*0o?(?:666|667|776|777)"),
    re.compile(r"umask\s*\(\s*0\s*\)"),
    re.compile(r'(?:mode|perm)\s*[:=]\s*0o?(?:666|667|776|777)'),
    re.compile(r"os\.MkdirAll\([^)]*0o?777\)"),
]

SAFE_PERMISSION_PATTERNS = re.compile(
    r"(?:temp|tmp|cache|test|spec|example)",
    re.IGNORECASE,
)

# CWE-668: Exposure of Resource to Wrong Sphere
EXPOSURE_PATTERNS = [
    re.compile(r"(?:EXPOSE|expose)\s+(?:22|3306|5432|6379|27017)\b"),
    re.compile(r'(?:bind|host).*["\']0\.0\.0\.0["\'].*(?:3306|5432|6379|27017|9200)', re.IGNORECASE),
    re.compile(r"(?:public|PUBLIC)\s*[:=]\s*(?:True|true|1)", re.IGNORECASE),
]

# CWE-1295: Debug Features Enabled in Production
DEBUG_PROD_PATTERNS = [
    re.compile(r"(?:app|server|flask)\.(?:run|debug)\s*\([^)]*debug\s*=\s*True", re.IGNORECASE),
    re.compile(r"(?:DEBUG|debug)\s*=\s*(?:True|true|1)\s*#?\s*(?!.*(?:test|dev|local))", re.IGNORECASE),
    re.compile(r'(?:devtools|debugger|profiler)\s*[:=]\s*(?:True|true|enabled)', re.IGNORECASE),
    re.compile(r"(?:stacktrace|stack_trace|verbose_errors)\s*[:=]\s*(?:True|true|1)", re.IGNORECASE),
]

SAFE_DEBUG_PATTERNS = re.compile(
    r"(?:test|spec|development|dev\.|local|__name__.*__main__|if.*DEBUG)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

# Two-tier context: debug mode is only high with production/deploy context
_DEBUG_CONTEXT = [re.compile(r"(production|deploy|release|staging|prod|gunicorn|uwsgi)", re.I)]

# Configuration files to scan
CONFIG_EXTENSIONS = frozenset({
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".json",
})


def check_configuration(source_path: str) -> dict:
    """Check for configuration and deployment security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of configuration vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=CONFIG_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for configuration security issues."""
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
        _check_insecure_defaults(file_path, line, line_num, lines, findings)
        _check_misconfiguration(file_path, line, line_num, lines, findings)
        _check_permissions(file_path, line, line_num, lines, findings)
        _check_exposure(file_path, line, line_num, lines, findings)
        _check_debug_prod(file_path, line, line_num, lines, content, findings)


def _check_insecure_defaults(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-1188 insecure default initialization."""
    if SAFE_DEFAULT_PATTERNS.search(file_path.name):
        return
    for pattern in INSECURE_DEFAULT_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.configuration.insecure_default",
                "category": "CWE-1188",
                "title": "Insecure default configuration",
                "description": f"Insecure default value at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use secure defaults: disable debug, restrict CORS, enable SSL verification",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1188"))
            return


def _check_misconfiguration(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for configuration issues mapped to specific Weakness CWE IDs."""
    for pattern, cwe_id, title in MISCONFIGURATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.configuration.misconfiguration",
                "category": f"CWE-{cwe_id}",
                "title": title,
                "description": f"Potentially insecure configuration at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Bind to localhost, enforce TLS 1.2+, enable certificate verification",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, cwe_id))
            return


def _check_permissions(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-732 incorrect permission assignment."""
    if SAFE_PERMISSION_PATTERNS.search(file_path.name):
        return
    for pattern in PERMISSION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.configuration.overly_permissive",
                "category": "CWE-732",
                "title": "Overly permissive file permissions",
                "description": f"World-writable or overly permissive permissions at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use restrictive permissions (0644 for files, 0755 for directories)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "732"))
            return


def _check_exposure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-668 resource exposure to wrong sphere."""
    for pattern in EXPOSURE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.configuration.resource_exposure",
                "category": "CWE-668",
                "title": "Resource exposed to wrong sphere",
                "description": f"Internal service port or resource publicly exposed at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Bind internal services to localhost; use network policies to restrict access",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "668"))
            return


def _check_debug_prod(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict],
) -> None:
    """Check for CWE-1295 debug features in production."""
    if SAFE_DEBUG_PATTERNS.search(file_path.name):
        return
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_DEBUG_PATTERNS.search(context):
        return
    for pattern in DEBUG_PROD_PATTERNS:
        if pattern.search(line):
            # Two-tier: demote to medium if file lacks production/deploy context
            severity = "high"
            if not check_context(content, _DEBUG_CONTEXT):
                severity = "medium"
            finding = {
                "severity": severity,
                "check_id": "cwe.configuration.debug_enabled",
                "category": "CWE-1295",
                "title": "Debug features enabled in production",
                "description": f"Debug mode or verbose errors enabled at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Disable debug mode and verbose error output in production deployments",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1295"))
            return


check_configuration_tool = function_tool(check_configuration)
