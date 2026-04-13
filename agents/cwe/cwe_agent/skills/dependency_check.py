"""Dependency and supply chain security detection skill."""

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
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-1104: Use of Unmaintained Third Party Components
DEPENDENCY_FILE_NAMES = frozenset({
    "requirements.txt", "Pipfile", "pyproject.toml",
    "package.json", "package-lock.json",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
})

# Patterns suggesting pinned vs unpinned dependencies
UNPINNED_PYTHON = re.compile(r"^[a-zA-Z][\w.-]*\s*$")  # No version constraint
UNPINNED_PYTHON_LOOSE = re.compile(r"^[a-zA-Z][\w.-]*\s*>=")  # Only lower bound
PINNED_VERSION = re.compile(r"==|~=|===|\block\b")

# CWE-829: Inclusion of Functionality from Untrusted Control Sphere
UNTRUSTED_SOURCE_PATTERNS = [
    re.compile(r'<script\s+src\s*=\s*["\']http:', re.IGNORECASE),
    re.compile(r'(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|python)', re.IGNORECASE),
    re.compile(r'pip\s+install\s+--index-url\s+http:', re.IGNORECASE),
    re.compile(r'go\s+get\s+.*(?:github\.com|gitlab\.com).*@latest'),
    re.compile(r'npm\s+install\s+.*(?:github:|git\+http:)', re.IGNORECASE),
]

SAFE_SCRIPT_PATTERNS = re.compile(
    r"(?:integrity\s*=|crossorigin|nonce=|SRI|subresource)",
    re.IGNORECASE,
)

# CWE-494: Download of Code Without Integrity Check
DOWNLOAD_NO_VERIFY_PATTERNS = [
    re.compile(r'(?:curl|wget)\s+.*(?:-o|-O|>)\s+\S+', re.IGNORECASE),
    re.compile(r'urllib\.request\.urlretrieve\s*\('),
    re.compile(r'requests\.get\([^)]*\)\.content'),
    re.compile(r'http\.Get\([^)]*\)'),
]

SAFE_INTEGRITY_PATTERNS = re.compile(
    r"(?:sha256|sha512|checksum|verify|gpg|signature|digest|hash)",
    re.IGNORECASE,
)

# CWE-506: Embedded Malicious Code (suspicious patterns)
SUSPICIOUS_CODE_PATTERNS = [
    re.compile(r'base64\.(?:b64decode|decodebytes)\s*\([^)]*\)\s*.*(?:exec|eval|compile)', re.IGNORECASE),
    re.compile(r"__import__\s*\(\s*['\"](?:os|subprocess|socket|http)['\"]"),
    re.compile(r'exec\s*\(\s*(?:base64|codecs|zlib)\.\w+\s*\('),
    re.compile(r"(?:socket|http\.client).*connect.*(?:exec|system|popen)", re.IGNORECASE),
]

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

ALL_EXTENSIONS = frozenset({
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".sh", ".bash",
    ".html", ".htm", ".yml", ".yaml", ".toml",
    ".txt", ".json", ".xml", ".gradle", ".lock",
})


def check_dependency_security(source_path: str) -> dict:
    """Check for dependency and supply chain security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of dependency security issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=ALL_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        if file_path.name in DEPENDENCY_FILE_NAMES:
            _analyze_dependency_file(file_path, findings)
        else:
            _analyze_code_file(file_path, findings)

    return {"findings": findings}


def _analyze_dependency_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze dependency manifest files for CWE-1104."""
    content = read_file_safe(file_path)
    if content is None:
        return

    if file_path.name == "requirements.txt":
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            if UNPINNED_PYTHON.match(stripped) or UNPINNED_PYTHON_LOOSE.match(stripped):
                finding = {
                    "severity": "medium",
                    "check_id": "cwe.dependency.unpinned_version",
                    "category": "CWE-1104",
                    "title": "Unpinned dependency version",
                    "description": f"Dependency '{stripped.split()[0]}' lacks pinned version at line {line_num}",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Pin dependencies to specific versions (use == or ~=)",
                }
                finding["code_snippet"] = extract_snippet(lines, line_num)
                findings.append(enrich_finding(finding, "1104"))


def _analyze_code_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze code files for dependency-related vulnerabilities."""
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
        _check_untrusted_source(file_path, line, line_num, lines, findings)
        _check_download_no_verify(file_path, line, line_num, lines, findings)
        _check_suspicious_code(file_path, line, line_num, lines, findings)


def _check_untrusted_source(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-829 inclusion from untrusted control sphere."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SCRIPT_PATTERNS.search(context):
        return
    for pattern in UNTRUSTED_SOURCE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.dependency.untrusted_source",
                "category": "CWE-829",
                "title": "Code from untrusted source",
                "description": f"Code loaded or executed from untrusted source at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use HTTPS, verify integrity (SRI/checksums), pin to specific versions",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "829"))
            return


def _check_download_no_verify(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-494 download without integrity check."""
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 4)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_INTEGRITY_PATTERNS.search(context):
        return
    for pattern in DOWNLOAD_NO_VERIFY_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.dependency.download_no_verify",
                "category": "CWE-494",
                "title": "Download without integrity verification",
                "description": f"Code/file downloaded without checksum verification at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Verify checksums or signatures of downloaded files before use",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "494"))
            return


def _check_suspicious_code(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-506 embedded malicious code patterns."""
    for pattern in SUSPICIOUS_CODE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.dependency.suspicious_code",
                "category": "CWE-506",
                "title": "Suspicious code pattern (potential malicious code)",
                "description": f"Obfuscated or suspicious execution pattern at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Review this code carefully; decoded-then-executed patterns are a malware indicator",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "506"))
            return


check_dependency_security_tool = function_tool(check_dependency_security)
