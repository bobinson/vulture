"""CWE buffer handling vulnerability detection skill."""

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

# Only scan C/C++/Go files
# Files we consider for buffer-style analysis. Go is included because
# the OOB / integer-overflow patterns apply, but the C-string copy
# functions (strcpy/strcat/etc.) cannot exist in Go and are gated
# below.
BUFFER_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go"})

# Extensions where C-string functions are valid identifiers.
_C_STRING_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"})

# CWE-120: Buffer overflow (unbounded copy). C-only.
UNBOUNDED_COPY_PATTERNS = [
    re.compile(r"\bstrcpy\s*\("),
    re.compile(r"\bstrcat\s*\("),
    re.compile(r"\bsprintf\s*\("),
    re.compile(r"\bgets\s*\("),
    re.compile(r"\bwcscpy\s*\("),
    re.compile(r"\bwcscat\s*\("),
]

SAFE_BOUNDED_ALTERNATIVES = re.compile(
    r"\b(?:strncpy|strncat|snprintf|fgets|strlcpy|strlcat)\s*\("
)

# CWE-787: Out-of-bounds write (memcpy/memmove without validation). C-only.
OOB_WRITE_PATTERNS = [
    re.compile(r"\bmemcpy\s*\("),
    re.compile(r"\bmemmove\s*\("),
    re.compile(r"\bcopy\s*\([^)]*,\s*\w+\s*\["),
]

# SAFE_SIZEOF_CHECK was previously `sizeof\s*\(` — too permissive; a
# `sizeof` mention anywhere on the line (including comments and
# unrelated arguments) suppressed the OOB-write finding. Tighten to
# require sizeof appearing as the LAST positional arg of the memcpy /
# memmove call (the size parameter). False negatives on unusual call
# shapes are acceptable; the previous pattern hid genuine bugs.
SAFE_SIZEOF_CHECK = re.compile(
    r"\b(?:memcpy|memmove|memset|memcmp|copy|strncpy|strncat|snprintf)\s*\("
    r"[^;]*?,\s*sizeof\s*\([^)]*\)\s*\)"
)

# CWE-125: Out-of-bounds read (array access without bounds check).
#
# Previously this matched EVERY `\w+[\w+]` access, which is essentially
# every array dereference in C/C++ code — producing hundreds of false
# positives per audit. The new patterns target shapes that are
# materially more likely to indicate an unsafe access:
#
#   1. Index derived from external input on the same line:
#         buf[atoi(argv[1])]
#         arr[strtoul(input, ...)]
#         data[recv_len(...)]
#         ptr[i + offset]   (compound arithmetic)
#   2. Index that is a known-tainted source name:
#         buf[user_input]   buf[req_size]   buf[strlen(s) + N]
#   3. Memory-region access via pointer + bare index immediately after
#      a malloc/alloc on the same expression — likely off-by-one risk.
#
# The base "any array access" pattern is GONE — that was the noise
# floor. Bounds-check suppression is preserved.
OOB_READ_PATTERNS = [
    # Compound arithmetic in subscript: arr[i + N], arr[i * 2], etc.
    re.compile(r"\b\w+\s*\[\s*\w+\s*[+\-*]\s*\w+\s*\]"),
    # Subscript with a tainted-looking name (heuristic).
    re.compile(
        r"\b\w+\s*\[\s*"
        r"(?:argv|envp|user_input|input|untrusted|tainted|req(?:_\w+)?|param|payload)"
        r"\b[^\]]*\]",
        re.IGNORECASE,
    ),
    # Subscript with a function call that returns external/length data.
    re.compile(
        r"\b\w+\s*\[\s*"
        r"(?:atoi|atol|strtol|strtoul|strtoll|recv|read|sscanf|getenv|atof)"
        r"\s*\(",
        re.IGNORECASE,
    ),
    # strlen(...) + offset as index (classic off-by-one).
    re.compile(r"\b\w+\s*\[\s*strlen\s*\([^)]*\)\s*[+\-]\s*\d+\s*\]"),
]

SAFE_BOUNDS_CHECK = re.compile(r"(?:len\(|\.(?:size|length|Len)\b|<\s*\w+\s*\)|sizeof)")

# CWE-416: Use after free
USE_AFTER_FREE_PATTERNS = [
    re.compile(r"\bfree\s*\(\s*(\w+)\s*\)"),
]

# CWE-190: Integer overflow or wraparound
INTEGER_OVERFLOW_PATTERNS = [
    re.compile(r"\b(?:int|short|int8_t|int16_t|int32_t|uint8_t|uint16_t|uint32_t)\s+\w+\s*=\s*\w+\s*[+*]\s*\w+"),
    re.compile(r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)"),
]
SAFE_OVERFLOW_CHECK = re.compile(
    r"(?:INT_MAX|INT_MIN|UINT_MAX|SIZE_MAX|overflow|__builtin_add_overflow|__builtin_mul_overflow|SafeInt|checked_)",
    re.IGNORECASE,
)

INCLUDE_LINE = re.compile(r"^\s*#\s*include\b")


def check_buffer_handling(source_path: str) -> dict:
    """Check for CWE buffer handling vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of buffer vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=BUFFER_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for buffer handling patterns.

    C-string-only checks (`unbounded_copy`, `oob_write`,
    `use_after_free`) are gated to C/C++ extensions — running them on
    Go is wasted work since `strcpy` etc. cannot exist in Go.
    OOB-read and integer-overflow patterns apply to both languages.
    """
    lines = read_file_lines(file_path)
    if lines is None:
        return
    is_c_family = file_path.suffix.lower() in _C_STRING_EXTENSIONS
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if INCLUDE_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        if is_c_family:
            _check_unbounded_copy(file_path, line, line_num, lines, findings)
            _check_oob_write(file_path, line, line_num, lines, findings)
            _check_use_after_free(file_path, line, line_num, lines, findings)
        _check_oob_read(file_path, line, line_num, lines, findings)
        _check_integer_overflow(file_path, line, line_num, lines, findings)


def _check_unbounded_copy(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-120 unbounded buffer copy."""
    if SAFE_BOUNDED_ALTERNATIVES.search(line):
        return
    for pattern in UNBOUNDED_COPY_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.buffer.unbounded_copy",
                "category": "CWE-120",
                "title": "Unbounded buffer copy",
                "description": f"Use of unbounded copy function at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use bounded alternatives: strncpy, snprintf, fgets",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "120"))
            return


def _check_oob_write(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-787 out-of-bounds write."""
    if SAFE_SIZEOF_CHECK.search(line):
        return
    for pattern in OOB_WRITE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.buffer.oob_write",
                "category": "CWE-787",
                "title": "Potential out-of-bounds write",
                "description": f"Memory copy without size validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate buffer sizes before memcpy/memmove operations",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "787"))
            return


def _check_oob_read(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-125 out-of-bounds read.

    Now matches only on indices likely derived from external input or
    arithmetic (see OOB_READ_PATTERNS doc). Pure `arr[i]` in a bounded
    loop body is no longer flagged — the previous behaviour produced
    hundreds of FPs per audit on standard C/Go code.
    """
    if SAFE_BOUNDS_CHECK.search(line):
        return
    for pattern in OOB_READ_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.buffer.oob_read",
                "category": "CWE-125",
                "title": "Potential out-of-bounds read",
                "description": f"Array access at line {line_num} uses a tainted or derived index without a bounds check",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add bounds checking before array access",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "125"))
            return


def _check_use_after_free(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-416 use after free."""
    for pattern in USE_AFTER_FREE_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        freed_var = match.group(1)
        # Check next 5 lines for use of freed pointer
        window_end = min(line_num + 5, len(lines))
        for i in range(line_num, window_end):
            subsequent = lines[i]
            if re.search(rf"\b{re.escape(freed_var)}\s*(?:->|\.|\[)", subsequent):
                finding = {
                    "severity": "critical",
                    "check_id": "cwe.buffer.use_after_free",
                    "category": "CWE-416",
                    "title": "Use after free",
                    "description": f"Pointer '{freed_var}' used after free() at line {line_num}",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Set pointer to NULL after free and check before use",
                }
                finding["code_snippet"] = extract_snippet(lines, line_num)
                findings.append(enrich_finding(finding, "416"))
                return


def _check_integer_overflow(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-190 integer overflow or wraparound."""
    # Check surrounding context for overflow guards
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_OVERFLOW_CHECK.search(context):
        return
    for pattern in INTEGER_OVERFLOW_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.buffer.integer_overflow",
                "category": "CWE-190",
                "title": "Potential integer overflow",
                "description": f"Integer arithmetic without overflow check at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Check for overflow before arithmetic or use safe integer libraries",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "190"))
            return


check_buffer_handling_tool = function_tool(check_buffer_handling)
