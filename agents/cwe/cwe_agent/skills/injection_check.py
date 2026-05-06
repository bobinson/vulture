"""CWE injection vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,

    scan_code_files,
)
from shared.tools.obfuscation import check_obfuscation
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-89: SQL Injection.
#
# All four common Python string-construction antipatterns are now
# matched, plus Go's Sprintf / direct concat:
#   - f-string with placeholder            f"SELECT ... {var}"
#   - .format(...)                          "SELECT ...".format(x)
#   - %-formatting                          "SELECT ... %s" % var       (NEW)
#   - + concatenation                       query = "SELECT " + var
#   - Sprintf                               fmt.Sprintf("SELECT %s", x)
SQL_INJECTION_PATTERNS = [
    # f-strings
    re.compile(r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*\{'),
    re.compile(r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^']*\{"),
    # .format(...)
    re.compile(r"\.format\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
    re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\s.*\.format\(", re.IGNORECASE),
    # %-formatting against a SQL string. Two complementary shapes
    # because the SQL keyword can be in either operand of `%`.
    re.compile(
        r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"\']*["\']\s*%\s*[\w(]',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:query|sql|stmt)\s*=\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*%',
        re.IGNORECASE,
    ),
    # Sprintf (Go)
    re.compile(r'Sprintf\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
    # Concatenation
    re.compile(r'(?:query|sql|stmt)\s*=\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+',
               re.IGNORECASE),
    re.compile(r'(?:query|sql)\s*=\s*[f"\'"].*\+'),
]

# CWE-78: OS Command Injection
#
# Real CWE-78 = passing user input to a shell. In Python that means the
# patterns below — os.system / os.popen / subprocess.* with shell=True.
# In Go, `exec.Command(name, arg, ...)` does NOT invoke a shell; argv
# concatenation there is a different vulnerability class (CWE-88 argument
# injection or CWE-94 code injection if the binary is an interpreter).
# We retain a narrow Go pattern that flags ONLY shell-binary invocations
# explicitly: exec.Command("sh"/"bash"/"/bin/sh"/etc., "-c", ...).
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"os\.system\("),
    re.compile(r"os\.popen\("),
    re.compile(r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True"),
    re.compile(r'exec\.Command\(\s*"(?:sh|bash|zsh|/bin/(?:sh|bash|zsh))"\s*,'),
]

# Validation-guard patterns. If any of these match within the radius of
# an injection-pattern hit, the detector treats the call as guarded and
# does NOT emit a finding. Mirrors the `_has_safe_context` approach used
# by the XSS skill.
SAFE_VALIDATION_PATTERNS = re.compile(
    r"(?:"
    r"regexp\.MustCompile|"               # Go: precompiled regex
    r"\bre\.compile\s*\(|"                # Python: precompiled regex
    r"\.MatchString\s*\(|"                # Go: regexp.MatchString
    r"\.match\s*\(|"                      # Python: pattern.match()
    r"\bIsValid\w*|"                      # Go: IsValidX, IsValidPython, ...
    r"\bis_valid\w*|"                     # Python snake_case: is_valid_*
    r"\b[Vv]alidate\w+|"                  # validate_x / ValidateX
    r"\b[Ss]anitize\w+|"                  # sanitize_x / SanitizeX
    r"\bshlex\.(?:quote|split)\s*\(|"     # Python: command-escaping helpers
    r"\bshell_quote\s*\(|"                # custom shell-quote helpers
    r"\.isidentifier\s*\(|"               # Python: name.isidentifier()
    r"allowlist|allow_list|whitelist"     # allowlist-style guards
    r")",
)

# CWE-79: Cross-site Scripting (XSS)
XSS_PATTERNS = [
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"document\.write\("),
    re.compile(r"dangerouslySetInnerHTML"),
    re.compile(r"\$\(\s*['\"]#?\w+['\"]\s*\)\.html\("),
    re.compile(r"v-html\s*="),
]

# CWE-94: Code Injection
CODE_INJECTION_PATTERNS = [
    re.compile(r"(?<!\w)eval\s*\("),
    re.compile(r"(?<!\w)exec\s*\("),
    re.compile(r"new\s+Function\s*\("),
    re.compile(r"setTimeout\s*\(\s*['\"`]"),
    re.compile(r"setInterval\s*\(\s*['\"`]"),
]

# CWE-918: Server-Side Request Forgery (SSRF)
SSRF_PATTERNS = [
    re.compile(r"requests\.(?:get|post|put|delete|head|patch)\([^)]*(?:request|req|params|input|user|body|query)", re.IGNORECASE),
    re.compile(r"urllib\.request\.urlopen\([^)]*(?:request|req|params|input|user|body|query)", re.IGNORECASE),
    re.compile(r"http\.Get\([^)]*(?:request|req|params|input|user|body|query|\+)", re.IGNORECASE),
    re.compile(r"fetch\([^)]*(?:request|req|params|input|user|body|query)", re.IGNORECASE),
    re.compile(r"httpx\.(?:get|post)\([^)]*(?:request|req|params|input|user|body|query)", re.IGNORECASE),
]

SAFE_SSRF_PATTERNS = re.compile(
    r"(?:allowlist|whitelist|allowed_hosts|allowed_urls|validate_url|urlparse|ALLOWED_DOMAINS)",
    re.IGNORECASE,
)

SAFE_STATIC_CALL = re.compile(r"""(?:exec|eval)\(\s*(?:'[^']*'|"[^"]*")\s*[,)]""")
SHELL_FUNC_DEF = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")


def check_injection(source_path: str) -> dict:
    """Check for CWE injection vulnerabilities (SQL, command, XSS, code).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of injection vulnerabilities.
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
    """Analyze a file for injection patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_sql(file_path, line, line_num, lines, findings)
        _check_command(file_path, line, line_num, lines, findings)
        _check_xss(file_path, line, line_num, lines, findings)
        _check_code_injection(file_path, line, line_num, lines, findings)
        _check_ssrf(file_path, line, line_num, lines, findings)

    # Obfuscation detection across all lines
    content = read_file_safe(file_path) or ""
    obfuscation_findings = check_obfuscation(file_path, lines, content)
    findings.extend(obfuscation_findings)


def _check_sql(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-89 SQL injection."""
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.sql",
                "category": "CWE-89",
                "title": "SQL injection via string interpolation",
                "description": f"SQL query built with string formatting at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use parameterized queries or prepared statements",
                "verification_hints": ["Test with payload: ' OR 1=1--", "Check if input is reflected in SQL error"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "89"))
            return


def _has_validation_context(lines: list[str], line_num: int, radius: int = 10) -> bool:
    """Check if a validation/sanitization guard appears within `radius`
    lines of `line_num`. The window covers the function body that contains
    the suspicious call — guards like `if !isValidX(arg) { return }` or
    `if not validate_module(name): return False` immediately preceding the
    call mitigate the injection risk and should suppress the finding.
    """
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return bool(SAFE_VALIDATION_PATTERNS.search("\n".join(lines[start:end])))


def _check_command(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-78 OS command injection."""
    if SHELL_FUNC_DEF.match(line):
        return
    for pattern in COMMAND_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            if _has_validation_context(lines, line_num):
                return
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.command",
                "category": "CWE-78",
                "title": "OS command injection",
                "description": f"Unsafe command execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use subprocess with shell=False and list arguments",
                "verification_hints": ["Test with payload: ; id", "Check if command output is reflected"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "78"))
            return


def _check_xss(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-79 cross-site scripting."""
    for pattern in XSS_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.injection.xss",
                "category": "CWE-79",
                "title": "Potential cross-site scripting (XSS)",
                "description": f"Unescaped HTML output at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Sanitize user input before rendering as HTML",
                "verification_hints": ["Check if input is reflected unescaped", "Test with payload: <script>alert(1)</script>"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "79"))
            return


def _check_code_injection(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-94 code injection."""
    for pattern in CODE_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.code",
                "category": "CWE-94",
                "title": "Code injection via dynamic execution",
                "description": f"Dynamic code execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Avoid eval/exec; use safe alternatives or whitelisted operations",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "94"))
            return


def _check_ssrf(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-918 server-side request forgery."""
    # Check surrounding context for URL validation
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SSRF_PATTERNS.search(context):
        return
    for pattern in SSRF_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.injection.ssrf",
                "category": "CWE-918",
                "title": "Server-side request forgery (SSRF)",
                "description": f"User-controlled URL in server request at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate URLs against an allowlist of permitted hosts/schemes",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "918"))
            return


check_injection_tool = function_tool(check_injection)
