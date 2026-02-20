"""CWE input validation vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

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

# CWE-20: Improper input validation
NO_VALIDATION_PATTERNS = [
    re.compile(r'(?:request|req)\.(?:body|params|query|form|args)\s*\[', re.IGNORECASE),
    re.compile(r'(?:request|req)\.(?:GET|POST)\s*\[', re.IGNORECASE),
    re.compile(r'params\[:?\w+\]'),
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

SAFE_XXE_PATTERNS = re.compile(
    r"(?:defusedxml|defused|resolve_entities\s*=\s*False|"
    r"no_network|XMLParser\([^)]*resolve_entities\s*=\s*False|"
    r"FEATURE_EXTERNAL_GENERAL_ENTITIES.*false|"
    r"setFeature.*disallow-doctype-decl.*true)",
    re.IGNORECASE,
)

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
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
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for input validation patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_path_traversal(file_path, line, line_num, findings, is_test=is_test)
        _check_no_validation(file_path, line, line_num, lines, findings, is_test=is_test)
        _check_file_upload(file_path, line, line_num, lines, findings, is_test=is_test)
        _check_xxe(file_path, line, line_num, lines, findings, is_test=is_test)


def _check_path_traversal(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-22 path traversal."""
    if SAFE_PATH_PATTERNS.search(line):
        return
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-22",
                "title": "Potential path traversal",
                "description": f"User-controlled path input at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use os.path.realpath and validate against allowed base directory",
            })
            return


def _check_no_validation(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], *, is_test: bool,
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
            findings.append({
                "severity": "low" if is_test else "medium",
                "category": "CWE-20",
                "title": "Missing input validation",
                "description": f"User input used without validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate and sanitize all user input before processing",
            })
            return


def _check_file_upload(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], *, is_test: bool,
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
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-434",
                "title": "Unrestricted file upload",
                "description": f"File upload without type/size validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate file type, extension, size, and content before saving",
            })
            return


def _check_xxe(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], *, is_test: bool,
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
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-611",
                "title": "XML external entity (XXE) vulnerability",
                "description": f"XML parsing without entity restriction at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use defusedxml or disable external entity resolution",
            })
            return


check_input_validation_tool = function_tool(check_input_validation)
