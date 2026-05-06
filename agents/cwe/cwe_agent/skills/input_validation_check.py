"""CWE input validation vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,

    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-22: Path traversal
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'os\.path\.join\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'\.\./'),
    re.compile(r'\.\.\\\\'),
    re.compile(r'open\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'Path\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'(?:readFile|readFileSync)\([^)]*(?:req|params|query)', re.IGNORECASE),
]

SAFE_PATH_PATTERNS = re.compile(
    r"(?:os\.path\.abspath|os\.path\.realpath|os\.path\.normpath|"
    r"secure_filename|sanitize|validate|whitelist|allowed_paths|"
    r"__file__|__dir__|BASE_DIR|ROOT_DIR)",
    re.IGNORECASE,
)

# CWE-20: Improper input validation.
#
# Modern web frameworks expose request-data via several access shapes.
# Bracket-only matching missed all of:
#   - dot access:        request.args.user_id
#   - property access:   request.json
#   - method get():      request.get("user_id"), request.GET.get("u")
#   - destructured kwargs: const { id } = req.body  (TS/JS — best-effort)
NO_VALIDATION_PATTERNS = [
    # bracket access (original)
    re.compile(r'(?:request|req)\.(?:body|params|query|form|args)\s*\[', re.IGNORECASE),
    re.compile(r'(?:request|req)\.(?:GET|POST)\s*\[', re.IGNORECASE),
    re.compile(r'params\[:?\w+\]'),
    # dot-attribute access on request: request.args.foo, req.body.bar
    re.compile(r'(?:request|req)\.(?:body|params|query|form|args|GET|POST)\.\w+', re.IGNORECASE),
    # request.json (Flask), request.JSON (less common)
    re.compile(r'(?:request|req)\.json\b'),
    # request.get("name") / request.GET.get("name") method form
    re.compile(r'(?:request|req)\.(?:GET|POST|args|form|body|params|query)\.get\s*\(\s*["\']', re.IGNORECASE),
    re.compile(r'(?:request|req)\.get\s*\(\s*["\']', re.IGNORECASE),
    # JS/TS destructure of req.body / req.query / req.params
    re.compile(r'(?:const|let|var)\s*\{\s*[^}]+\}\s*=\s*(?:request|req)\.(?:body|query|params)\b', re.IGNORECASE),
]

SAFE_VALIDATION_PATTERNS = re.compile(
    r"(?:validate|sanitize|clean|escape|strip|schema|serialize|"
    r"wtforms|pydantic|marshmallow|cerberus|voluptuous|joi\.|"
    r"\.is_valid|form\.cleaned_data|isinstance\()",
    re.IGNORECASE,
)

# CWE-434: Unrestricted file upload
FILE_UPLOAD_PATTERNS = [
    re.compile(r'request\.files\[', re.IGNORECASE),
    re.compile(r'(?:multer|upload|formidable)', re.IGNORECASE),
    re.compile(r'\.save\([^)]*(?:filename|file_name)', re.IGNORECASE),
    re.compile(r'MultiPartParser|multipart/form-data', re.IGNORECASE),
]

SAFE_UPLOAD_PATTERNS = re.compile(
    r"(?:allowed_extensions|content_type|file_type|mimetype|"
    r"max_size|max.?length|file.?size|content.?length|"
    r"ALLOWED_TYPES|accept=|validate|secure_filename)",
    re.IGNORECASE,
)

# CWE-611: XXE (XML External Entity)
XXE_PATTERNS = [
    re.compile(r'xml\.etree\.ElementTree\.parse\('),
    re.compile(r'etree\.parse\('),
    re.compile(r'xml\.dom\.minidom\.parse\('),
    re.compile(r'xml\.sax\.parse\('),
    re.compile(r'lxml\.etree\.parse\('),
    re.compile(r'XMLReader\(\)'),
    re.compile(r'DocumentBuilder(?:Factory)?\.new'),
    re.compile(r'SAXParser(?:Factory)?\.new'),
]

# Safe-XXE: explicit module imports (defusedxml) or attribute settings
# that DEFINITIVELY disable entity resolution. The previous regex
# matched any line containing the literal `resolve_entities = False`,
# but `resolve_entities = SAFE_FLAG` (where SAFE_FLAG is False) was
# missed. We accept either the literal-False form OR an obvious
# defusedxml import. Comments containing the words alone (e.g. "# safe:
# defusedxml") no longer trigger because they don't reach the regex
# without function-call shape.
SAFE_XXE_PATTERNS = re.compile(
    r"(?:"
    # Explicit safe library import or call
    r"\bimport\s+defusedxml\b"
    r"|\bfrom\s+defusedxml\b"
    r"|\bdefusedxml\.\w+\.parse\s*\("
    # Constructor with literal False / no_network=True
    r"|XMLParser\s*\([^)]*\bresolve_entities\s*=\s*False\b"
    r"|XMLParser\s*\([^)]*\bno_network\s*=\s*True\b"
    # Java SAX feature toggles
    r"|setFeature\s*\([^)]*disallow-doctype-decl[^)]*,\s*true\)"
    r"|setFeature\s*\([^)]*external-general-entities[^)]*,\s*false\)"
    r"|setFeature\s*\([^)]*external-parameter-entities[^)]*,\s*false\)"
    r")",
    re.IGNORECASE,
)

# CWE-352: Cross-Site Request Forgery (CSRF).
#
# Server-side decorator/route patterns AND modern client-side state-
# changing fetch/XHR shapes. SPAs that hit `fetch("/api", {method:
# "POST"})` without a CSRF token are now matched — previously only
# `<form method=POST>` markup was detected.
CSRF_PATTERNS = [
    # Server-side route decorators
    re.compile(r"@app\.route\([^)]*methods\s*=\s*\[.*(?:POST|PUT|DELETE|PATCH)", re.IGNORECASE),
    re.compile(r"router\.(?:post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"@(?:Post|Put|Delete|Patch)Mapping", re.IGNORECASE),
    # HTML form
    re.compile(r'<form[^>]*method\s*=\s*["\']?(?:post|put|delete|patch)', re.IGNORECASE),
    # Client-side fetch / axios / XHR with state-changing method
    re.compile(
        r'fetch\s*\([^)]*\bmethod\s*:\s*["\'](?:POST|PUT|DELETE|PATCH)["\']',
        re.IGNORECASE,
    ),
    re.compile(r'\baxios\.(?:post|put|delete|patch)\s*\(', re.IGNORECASE),
    re.compile(
        r'(?:XMLHttpRequest|xhr)\s*\.\s*open\s*\(\s*["\'](?:POST|PUT|DELETE|PATCH)["\']',
        re.IGNORECASE,
    ),
    # jQuery
    re.compile(r'\$\.(?:post|ajax)\s*\(', re.IGNORECASE),
]

SAFE_CSRF_PATTERNS = re.compile(
    r"(?:csrf|CSRFProtect|CsrfViewMiddleware|csrf_token|_token|X-CSRF|antiforgery|csurf|csrfmiddlewaretoken)",
    re.IGNORECASE,
)

# CWE-502: Deserialization of Untrusted Data
DESERIALIZATION_PATTERNS = [
    re.compile(r"pickle\.loads?\s*\("),
    re.compile(r"yaml\.(?:load|unsafe_load)\s*\("),
    re.compile(r"marshal\.loads?\s*\("),
    re.compile(r"shelve\.open\s*\("),
    re.compile(r"\bunserialize\s*\("),  # PHP
    re.compile(r"\.readObject\s*\("),  # Java ObjectInputStream
    re.compile(r"jsonpickle\.decode\s*\("),
]

SAFE_DESERIALIZE_PATTERNS = re.compile(
    r"(?:SafeLoader|safe_load|yaml\.safe_load|yaml\.CSafeLoader|trusted|allowed_classes)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_input_validation(source_path: str) -> dict:
    """Check for CWE input validation vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of input validation vulnerabilities.
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
    """Analyze a file for input validation patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_path_traversal(file_path, line, line_num, lines, findings)
        _check_no_validation(file_path, line, line_num, lines, findings)
        _check_file_upload(file_path, line, line_num, lines, findings)
        _check_xxe(file_path, line, line_num, lines, findings)
        _check_csrf(file_path, line, line_num, lines, findings)
        _check_deserialization(file_path, line, line_num, lines, findings)


def _check_path_traversal(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-22 path traversal."""
    if SAFE_PATH_PATTERNS.search(line):
        return
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.path_traversal",
                "category": "CWE-22",
                "title": "Potential path traversal",
                "description": f"User-controlled path input at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use os.path.realpath and validate against allowed base directory",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "22"))
            return


def _check_no_validation(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-20 improper input validation."""
    # Check surrounding context for validation
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_VALIDATION_PATTERNS.search(context):
        return
    for pattern in NO_VALIDATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.input_validation.missing_validation",
                "category": "CWE-20",
                "title": "Missing input validation",
                "description": f"User input used without validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate and sanitize all user input before processing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "20"))
            return


def _check_file_upload(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-434 unrestricted file upload."""
    # Check surrounding context for upload safeguards
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_UPLOAD_PATTERNS.search(context):
        return
    for pattern in FILE_UPLOAD_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.unrestricted_upload",
                "category": "CWE-434",
                "title": "Unrestricted file upload",
                "description": f"File upload without type/size validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate file type, extension, size, and content before saving",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "434"))
            return


def _check_xxe(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-611 XML external entity."""
    # Check surrounding context for XXE protections
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_XXE_PATTERNS.search(context):
        return
    for pattern in XXE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.xxe",
                "category": "CWE-611",
                "title": "XML external entity (XXE) vulnerability",
                "description": f"XML parsing without entity restriction at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use defusedxml or disable external entity resolution",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "611"))
            return


def _check_csrf(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-352 cross-site request forgery."""
    # Check surrounding context for CSRF protection
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_CSRF_PATTERNS.search(context):
        return
    for pattern in CSRF_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.missing_csrf",
                "category": "CWE-352",
                "title": "Missing CSRF protection",
                "description": f"State-changing endpoint without CSRF token at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add CSRF token validation (CSRFProtect, csurf, or framework middleware)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "352"))
            return


def _check_deserialization(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-502 deserialization of untrusted data."""
    if SAFE_DESERIALIZE_PATTERNS.search(line):
        return
    for pattern in DESERIALIZATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.input_validation.unsafe_deserialization",
                "category": "CWE-502",
                "title": "Deserialization of untrusted data",
                "description": f"Unsafe deserialization at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use safe loaders (yaml.safe_load), avoid pickle with untrusted data, validate before deserializing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "502"))
            return


check_input_validation_tool = function_tool(check_input_validation)
