"""Template injection (SSTI) detection skill (CWE-1336).

Detects server-side template injection patterns that can lead to XSS
or remote code execution via dynamic template compilation with user input.
"""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# Jinja2 SSTI
JINJA2_PATTERNS = [
    re.compile(r"Template\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
    re.compile(r"from_string\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
    re.compile(r"Environment\s*\(.*\)\.from_string\s*\("),
]

# Django SSTI
DJANGO_PATTERNS = [
    re.compile(r"Template\s*\([^)]*(?:request|req\.|input|user|body|query|param)"),
    re.compile(r"Template\s*\([^)]*(?:request|req\.|input|user|body|query|param)[^)]*\)\.render\s*\("),
]

# Handlebars/Mustache unsafe
HANDLEBARS_PATTERNS = [
    re.compile(r"\{\{\{[^}]+\}\}\}"),                      # Triple-stache {{{var}}}
    re.compile(r"compile\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
]

# EJS SSTI
EJS_PATTERNS = [
    re.compile(r"ejs\.render\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
    re.compile(r"ejs\.compile\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
]

# Go template unsafe
GO_TEMPLATE_PATTERNS = [
    re.compile(r"template\.HTML\s*\([^)]*(?:request|req\.|input|r\.)", re.IGNORECASE),
    re.compile(r"template\.(?:New|Must)\s*\([^)]*\)\.Parse\s*\([^)]*(?:request|req\.|input|r\.)", re.IGNORECASE),
]

# Safe exclusions
SAFE_PATTERNS = re.compile(
    r"(?:render_template\s*\(\s*['\"]|"           # Flask render_template("file.html")
    r"get_template\s*\(\s*['\"]|"                  # loader.get_template("file.html")
    r"render\s*\(\s*request\s*,\s*['\"]|"          # Django render(request, "file.html")
    r"Template\s*\(\s*['\"][^'\"]*['\"](?:\s*\)|\s*,))",  # Template("static string")
    re.IGNORECASE,
)

COMMENT_LINE = COMMENT_INDICATORS
IMPORT_LINE = SAFE_IMPORT_LINE
SCANNER_DEF = SCANNER_DEF_LINE


def check_template_injection(source_path: str) -> dict:
    """Check for template injection (SSTI) vulnerabilities (CWE-1336).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of template injection vulnerabilities.
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
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_LINE.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF.search(line):
            continue
        if SAFE_PATTERNS.search(line):
            continue
        # Early-return chain: first match wins to avoid double-fire
        if _check_jinja2(file_path, line, line_num, findings):
            continue
        if _check_django(file_path, line, line_num, findings):
            continue
        if _check_handlebars(file_path, line, line_num, findings):
            continue
        if _check_ejs(file_path, line, line_num, findings):
            continue
        _check_go_template(file_path, line, line_num, findings)


def _check_jinja2(
    file_path: Path, line: str, line_num: int, findings: list[dict],
) -> bool:
    for pattern in JINJA2_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "critical",
                "category": "CWE-1336",
                "title": "Jinja2 SSTI via dynamic template compilation",
                "description": (
                    f"User input passed to Jinja2 Template() or from_string() "
                    f"at line {line_num}. This enables server-side template "
                    f"injection leading to XSS or RCE."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use render_template() with static template files instead "
                    "of Template(user_input). Never pass user input to "
                    "from_string() or Template()."
                ),
            })
            return True
    return False


def _check_django(
    file_path: Path, line: str, line_num: int, findings: list[dict],
) -> bool:
    for pattern in DJANGO_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "critical",
                "category": "CWE-1336",
                "title": "Django SSTI via dynamic template compilation",
                "description": (
                    f"User input passed to Django Template().render() "
                    f"at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use render() with static template files. Never pass "
                    "user input directly to Template()."
                ),
            })
            return True
    return False


def _check_handlebars(
    file_path: Path, line: str, line_num: int, findings: list[dict],
) -> bool:
    for pattern in HANDLEBARS_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "high",
                "category": "CWE-1336",
                "title": "Handlebars unsafe rendering or SSTI",
                "description": (
                    f"Triple-stache or dynamic compile with user input "
                    f"at line {line_num}. Triple-stache disables escaping."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use double-stache {{var}} instead of triple-stache "
                    "{{{var}}} to enable HTML escaping. Never pass user "
                    "input to Handlebars.compile()."
                ),
            })
            return True
    return False


def _check_ejs(
    file_path: Path, line: str, line_num: int, findings: list[dict],
) -> bool:
    for pattern in EJS_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "critical",
                "category": "CWE-1336",
                "title": "EJS SSTI via dynamic template rendering",
                "description": (
                    f"User input passed to ejs.render() or ejs.compile() "
                    f"at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use ejs.renderFile() with static template files. "
                    "Never pass user input to ejs.render() or ejs.compile()."
                ),
            })
            return True
    return False


def _check_go_template(
    file_path: Path, line: str, line_num: int, findings: list[dict],
) -> None:
    for pattern in GO_TEMPLATE_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "critical",
                "category": "CWE-1336",
                "title": "Go template injection via template.HTML()",
                "description": (
                    f"User input passed to template.HTML() or dynamic "
                    f"template.Parse() at line {line_num}. template.HTML() "
                    f"bypasses Go's auto-escaping."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use html/template with auto-escaping. Never pass user "
                    "input to template.HTML() which marks content as safe."
                ),
            })
            return


check_template_injection_tool = function_tool(check_template_injection)
