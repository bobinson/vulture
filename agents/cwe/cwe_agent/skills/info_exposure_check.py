"""Information exposure vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_name,
    is_backup_name,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_backup_files,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet
from shared.tools.suppression import INFO_EXPOSURE_SUPPRESSIONS, should_suppress

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref

# CWE-209: Error message information disclosure
#
# The first five patterns are Python/Java/Go. That left Node entirely uncovered,
# so a TypeScript target which mounts `errorhandler()` — a package whose whole
# purpose is to return the stack trace and surrounding source to the client —
# reported nothing. The Node additions follow.
ERROR_DISCLOSURE_PATTERNS = [
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"\.printStackTrace\s*\("),  # Java
    re.compile(r"debug\.PrintStack\s*\("),  # Go
    re.compile(r"return\s+.*(?:traceback|stacktrace|stack_trace)", re.IGNORECASE),
    # Node/Express: an error VALUE echoed into the response body.
    #
    # Two exclusions carry the precision. The character class stops at a quote,
    # so `res.send('failed')` cannot match. The `(?!\s*:)` lookahead rejects the
    # token when it is an object KEY — `res.json({ error: 'Try again' })` names
    # a field "error" and returns a literal, which is the correct behaviour.
    # `res.json({ error: err.message })` still matches, on the value.
    re.compile(
        r"\.(?:send|json|end|write)\s*\(\s*[^'\"`)]*"
        r"\b((?:err|error|ex|exception)\w*)\b(?!\s*:)",
        re.IGNORECASE,
    ),
    # A `.stack` property reaching the response, in any wrapping:
    #   res.status(500).json({ stack: err.stack })
    re.compile(r"\.(?:send|json|end|write)\s*\([^)]*\.stack\b"),
]

# Middleware that returns diagnostic detail to the client by design. Reporting
# the mount site is the point: the leak is the mount, not a line inside the
# package.
LEAKY_ERROR_MIDDLEWARE = re.compile(
    r"\buse\s*\(\s*(?:\w+\.)?(?:errorhandler|errorHandler|expressErrorHandler)\s*\(",
)

# Gating the above on the environment is its documented safe usage, so a guard
# anywhere near the mount suppresses the finding.
_ENV_GUARD = re.compile(
    r"(?:NODE_ENV|app\.get\(\s*['\"]env['\"]\s*\)|process\.env\.\w*ENV\w*)"
    r"|\b(?:isDev|isDevelopment|__DEV__|devMode)\b",
    re.IGNORECASE,
)

# Server-side logging of an error is CWE-532's concern, not disclosure. Without
# this, `logger.error(err.stack)` would match the `.stack` pattern above.
_LOG_SINK = re.compile(
    r"\b(?:console|logger|log|winston|pino|bunyan)\s*\.\s*\w+\s*\(|"
    r"\b(?:log|logger)\s*\(",
    re.IGNORECASE,
)

# CWE-532: Information through log files
LOG_SENSITIVE_PATTERNS = [
    re.compile(r"(?:log(?:ger)?|print|fmt\.Print)\w*\(.*(?:password|passwd|secret|token|api_key|apikey)", re.IGNORECASE),
    re.compile(r"logging\.(?:debug|info|warning|error)\(.*(?:password|secret|token|api_key)", re.IGNORECASE),
    re.compile(r"console\.log\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
    re.compile(r"log\.(?:Info|Debug|Warn|Error)\w*\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
]

# CWE-200: Exposure of sensitive info
SENSITIVE_RESPONSE_PATTERNS = [
    re.compile(r"(?:json|JSON)\w*\(.*(?:internal_path|db_host|database_url|dsn)", re.IGNORECASE),
    re.compile(r"(?:Response|response|w\.Write)\(.*(?:stack|internal|debug_info)", re.IGNORECASE),
]

# CWE-312: Cleartext storage of sensitive info
CLEARTEXT_STORAGE_PATTERNS = [
    re.compile(r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
    re.compile(r"(?:set|put|store|save)\w*\(.*(?:password|secret|token).*,\s*[\"']", re.IGNORECASE),
]
# Exclude safe patterns: hashing, env vars, config constants
SAFE_STORAGE = re.compile(
    r"\b(?:hash|bcrypt|encrypt|sha256|os\.(?:environ|getenv)|ENV\[|config\.|PLACEHOLDER|example|changeme|xxx)\b",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")
STRING_ONLY = re.compile(r"^\s*[\"']")

# Two-tier context: cleartext storage is only high with database/persist context
_STORAGE_CONTEXT = [re.compile(r"(database|persist|store|save|write|insert|sqlite|postgres|mysql|redis)", re.IGNORECASE)]


def check_information_exposure(source_path: str) -> dict:
    """Check for information exposure vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of information exposure issues.
    """
    findings: list[dict] = []
    suppression_counts: dict[int, int] = {}

    # A shadow copy is a finding in its own right, whatever its contents
    # (feature 0068). Walked separately from the code scan: running this
    # inside the scan_code_files loop meant a backup was only reported if it
    # was also *parseable*, so package-lock.json.bak (effective name in
    # SKIP_FILES) and coupons_2013.md.bak (non-code extension) were silently
    # exempt — 1 of juice-shop's 3 backups was reported.
    for backup_path in scan_backup_files(source_path):
        _check_backup_exposure(backup_path, source_path, findings)

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings, suppression_counts)

    return {"findings": findings}


# Directories typically reachable by an unauthenticated client. A shadow copy
# here is materially worse than one buried in src/.
_SERVED_DIRS = frozenset({
    "ftp", "public", "static", "www", "wwwroot", "htdocs", "dist", "build",
    "assets", "uploads", "files", "download", "downloads", "web",
})


def _check_backup_exposure(file_path: Path, source_path: str, findings: list[dict]) -> None:
    """Report a backup/shadow copy of source or config as an exposure.

    Precise weakness is CWE-530 (Exposure of Backup File), which the OWASP 2025
    edition does not map; we therefore categorise as the mapped parent CWE-552
    (Files or Directories Accessible to External Parties -> A01) and name
    CWE-530 in the text rather than inventing a mapping.
    """
    if not is_backup_name(file_path.name):
        return
    shadowed = effective_name(file_path.name)
    try:
        rel = file_path.relative_to(source_path)
        parts = {p.lower() for p in rel.parts[:-1]}
    except ValueError:
        rel, parts = file_path, set()
    served = bool(parts & _SERVED_DIRS)

    finding = {
        "severity": "high" if served else "medium",
        "check_id": "cwe.info_exposure.backup_file",
        "category": "CWE-552",
        "title": f"Exposed backup file '{file_path.name}' (CWE-530)",
        "description": (
            f"'{rel}' is a backup/shadow copy of '{shadowed}'. Backup files "
            "commonly retain credentials, dependency pins and logic that were "
            "deliberately removed from the live file, and are served verbatim "
            "if they sit inside the deployed tree (CWE-530)."
            + (" It is located under a publicly-served directory." if served else "")
        ),
        "file_path": str(file_path),
        "line_start": 1,
        "line_end": 1,
        "recommendation": (
            "Delete the backup from the repository/deploy artefact and keep "
            "history in version control; block backup extensions at the web server."
        ),
    }
    findings.append(enrich_finding(finding, "552"))


def _analyze_file(file_path: Path, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    """Analyze a file for information exposure issues."""
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
        _check_error_disclosure(file_path, line, line_num, lines, findings)
        _check_log_sensitive(file_path, line, line_num, lines, findings, suppression_counts)
        _check_cleartext_storage(file_path, line, line_num, lines, content, findings, suppression_counts)
        _check_sensitive_response(file_path, line, line_num, lines, findings)


def _check_error_disclosure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for error message information disclosure (CWE-209)."""
    # Diagnostic middleware: the mount site IS the vulnerability, so it is
    # checked separately from the "error value in a response" patterns.
    if LEAKY_ERROR_MIDDLEWARE.search(line):
        if _has_env_guard(lines, line_num):
            return
        _add_disclosure(
            file_path, line_num, lines, findings,
            title="Diagnostic error middleware returns stack traces to clients",
            description=(
                f"Error-handling middleware mounted at line {line_num} without an "
                "environment guard. Packages of this kind return the stack trace and "
                "surrounding source of any unhandled error in the HTTP response, "
                "disclosing file paths, dependency versions and internal logic to "
                "unauthenticated callers."
            ),
            recommendation=(
                "Mount diagnostic error middleware only for development (guard on "
                "NODE_ENV / app.get('env')), and register a production handler that "
                "returns a generic message while logging detail server-side."
            ),
        )
        return

    # Server-side logging of an error is CWE-532's concern; without this a
    # `logger.error(err.stack)` line would match the `.stack` pattern.
    if _LOG_SINK.search(line):
        return

    for pattern in ERROR_DISCLOSURE_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        # An error-SHAPED name is not an error. `const errMsg = { err: 'not
        # supported' }` returned to the client discloses nothing, so when the
        # match is a bare identifier, check what it was assigned nearby.
        if m.groups() and m.group(1) and _holds_literal(lines, line_num, m.group(1)):
            return
        _add_disclosure(
            file_path, line_num, lines, findings,
            title="Error message information disclosure",
            description=f"Stack trace or error details exposed at line {line_num}",
            recommendation="Return generic error messages; log detailed errors server-side only",
        )
        return


def _holds_literal(lines: list[str], line_num: int, ident: str, radius: int = 6) -> bool:
    """True when ``ident`` is assigned a literal within ``radius`` lines above.

    Conservative on purpose: only a right-hand side that STARTS with a quote or
    an object brace counts, and an object brace only when it contains no
    identifier-valued field. Anything derived from a caught error
    (``e.message``, ``getErrorMessage(err)``) therefore still reports.
    """
    pat = re.compile(
        rf"(?:const|let|var)?\s*\b{re.escape(ident)}\b\s*=\s*(['\"`{{].*)$"
    )
    start = max(0, line_num - 1 - radius)
    for ln in lines[start:line_num - 1]:
        m = pat.search(ln)
        if not m:
            continue
        rhs = m.group(1).strip()
        if rhs[0] in "'\"`":
            return True
        # Object literal: every value must itself be a literal.
        if rhs.startswith("{"):
            values = re.findall(r":\s*([^,}]+)", rhs)
            if values and all(v.strip()[:1] in "'\"`" or v.strip().isdigit()
                              for v in values):
                return True
    return False


def _add_disclosure(
    file_path: Path, line_num: int, lines: list[str], findings: list[dict],
    title: str, description: str, recommendation: str,
) -> None:
    """Append a CWE-209 finding."""
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.error_disclosure",
        "category": "CWE-209",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "209"))


def _has_env_guard(lines: list[str], line_num: int, radius: int = 8) -> bool:
    """True when an environment check sits within `radius` lines of the mount.

    Deliberately generous: gating diagnostic middleware on the environment is
    its documented safe usage, and a false negative there costs far less than
    telling every Express project its dev-only error handler is a vulnerability.
    """
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return any(_ENV_GUARD.search(ln) for ln in lines[start:end])


def _check_log_sensitive(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for sensitive data in log output (CWE-532)."""
    for pattern in LOG_SENSITIVE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "critical",
            "check_id": "cwe.info_exposure.log_sensitive",
            "category": "CWE-532",
            "title": "Sensitive data written to log",
            "description": f"Potential password/token/secret logged at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Never log sensitive data; use redaction or masked output",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "532"))
        return


def _check_cleartext_storage(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for cleartext storage of sensitive info (CWE-312).

    Suppress lines whose RHS is a variable reference — `password=$X`,
    `--build-arg STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"` etc. are env
    indirections that the static analysis can't see resolve to a
    literal.
    """
    if SAFE_STORAGE.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in CLEARTEXT_STORAGE_PATTERNS:
        if not pattern.search(line):
            continue
        # Two-tier: demote to medium if file lacks database/persist context
        severity = "critical"
        if not check_context(content, _STORAGE_CONTEXT):
            severity = "medium"
        finding = {
            "severity": severity,
            "check_id": "cwe.info_exposure.cleartext_storage",
            "category": "CWE-312",
            "title": "Cleartext storage of sensitive information",
            "description": f"Sensitive value stored in cleartext at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use environment variables, vaults, or encryption for sensitive data",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "312"))
        return


def _check_sensitive_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for sensitive information in responses (CWE-200)."""
    for pattern in SENSITIVE_RESPONSE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.info_exposure.sensitive_response",
            "category": "CWE-200",
            "title": "Sensitive information exposure in response",
            "description": f"Internal details exposed in response at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Do not expose internal paths, database details, or debug info in responses",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "200"))
        return


check_information_exposure_tool = function_tool(check_information_exposure)
