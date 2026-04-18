"""Dedicated skill for the CWE path-equivalence family (42, 43, 46, 48-57).

Scans source files for string literals that are passed to path-using APIs
and exhibit filename-equivalence patterns (trailing dot/slash/backslash,
wildcards, directory-traversal equivalents) catalogued as Variants under
CWE-41.

Two filters suppress false positives:
  (1) Line-level gate - literal must be inside a path-using call.
  (2) Path-shape filter - literal content must look path-ish.
Variant regexes use \\A / \\Z absolute anchors (robust to future changes).
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# (1) Line-level gate - literal must be inside one of these path-using calls.
_PATH_CALL_GATE = re.compile(
    r"\b(?:open|fopen|freopen|popen|fdopen|"
    r"read_file|write_file|readFile|writeFile|loadFile|"
    r"unlink|remove|rename|link|symlink|"
    r"stat|fstat|lstat|realpath|"
    r"File|FileReader|FileWriter|FileInputStream|FileOutputStream|"
    r"RandomAccessFile|Path|Paths)\s*\("
    r"|\bos\.path\.(?:join|normpath|abspath|realpath|exists|"
    r"isfile|isdir|getsize|basename|dirname)\s*\("
    r"|\bpathlib\.(?:Path|PurePath)\s*\("
    r"|\bfs\.(?:readFile|writeFile|unlink|stat|lstat|access|exists)\s*\("
    r"|\bFiles\.(?:read|write|delete|copy|move|exists|isDirectory)\s*\("
    r"|\bioutil\.(?:ReadFile|WriteFile)\s*\("
)

# Quoted literal - group(2) is content WITHOUT quotes.
_PATH_LITERAL = re.compile(r"""(['"])([^'"\n]{1,256})\1""")

# (2) Path-shape heuristic - content must contain at least one path signal.
_PATH_SHAPE = re.compile(
    r"[/\\]|\.\./|\.\w{1,5}(?:\s|\Z)|\.\s*\Z"
)

# Variant regexes: (cwe_id, pattern, label, severity)
_VARIANTS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("43", re.compile(r"\.{2,}\Z"),                 "multiple trailing dots",         "medium"),
    ("42", re.compile(r"(?<!\.)\.\Z"),              "trailing dot",                   "low"),
    ("46", re.compile(r"\s\Z"),                     "trailing whitespace",            "low"),
    ("49", re.compile(r"[^/]/\Z"),                  "trailing slash",                 "low"),
    ("54", re.compile(r"\\\\\Z"),                   "trailing backslash",             "medium"),
    ("52", re.compile(r"//\Z"),                     "multiple trailing slashes",      "medium"),
    ("50", re.compile(r"\A//"),                     "multiple leading slashes",       "medium"),
    ("51", re.compile(r"[^:/]//[^/]"),              "multiple internal slashes",      "medium"),
    ("55", re.compile(r"/\./"),                     "single-dot directory",           "medium"),
    ("57", re.compile(r"\.\./"),                    "directory traversal equivalence","high"),
    ("48", re.compile(r"[A-Za-z0-9]\s[A-Za-z0-9]"), "internal whitespace",            "low"),
    ("56", re.compile(r"[*?]"),                     "wildcard",                       "low"),
]


def _build_finding(
    cwe_id: str,
    label: str,
    severity: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single enriched finding dict for a path-equivalence match."""
    finding = {
        "severity": severity,
        "check_id": f"cwe.path_eq.cwe_{cwe_id}",
        "category": f"CWE-{cwe_id}",
        "title": f"Path Equivalence: {label}",
        "description": (
            f"Filename literal passed to a path-using call "
            f"exhibits {label} at line {lineno}."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Canonicalize paths (realpath/normpath) before "
            "comparison or use, and validate against an allowlist."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, cwe_id)


def _match_variants_for_literal(
    content: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Match the literal content against each variant and append one finding."""
    if not _PATH_SHAPE.search(content):
        return
    for cwe_id, pat, label, severity in _VARIANTS:
        if pat.search(content):
            findings.append(_build_finding(cwe_id, label, severity, file_path, lineno, lines))
            return  # one variant per literal


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a single line for gated path-using calls with equivalence variants."""
    if not _PATH_CALL_GATE.search(line):
        return
    for m in _PATH_LITERAL.finditer(line):
        _match_variants_for_literal(m.group(2), file_path, lineno, lines, findings)


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for path-equivalence variants."""
    if is_generated_file(file_path) or is_test_file(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, findings)


def check_path_equivalence(source_path: str) -> dict[str, Any]:
    """Scan source files for path-equivalence weaknesses (CWE-42/43/46/48-57)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_path_equivalence_tool = function_tool(check_path_equivalence)
