"""Error handling vulnerability detection skill."""

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

# CWE-252: Unchecked return value
UNCHECKED_RETURN_GO = [
    re.compile(r"^\s*_\s*,\s*_\s*=\s*\w+"),  # Go: _, _ = func()
    re.compile(r"^\s*_\s*=\s*\w+\.\w+\("),  # Go: _ = obj.Method()
]
GO_ERR_ASSIGN = re.compile(r",\s*err\s*:?=\s*\w+")
GO_ERR_CHECK = re.compile(r"if\s+err\s*!=\s*nil")

# CWE-755: Improper exception handling.
#
# Now also flags:
#   - except BaseException: catches SystemExit, KeyboardInterrupt,
#     GeneratorExit — strictly worse than `except Exception`.
#   - except (Exception, BaseException, ...) as tuples: same shape.
#   - Java catch(Throwable t) which catches Errors (StackOverflow, OOM).
BARE_EXCEPT_PATTERNS = [
    re.compile(r"^\s*except\s*:"),  # Python: bare except
    re.compile(r"^\s*except\s+Exception\s*(?:as\s+\w+\s*)?:"),  # Python: catch-all
    re.compile(r"^\s*except\s+BaseException\s*(?:as\s+\w+\s*)?:"),  # Python: catches SystemExit/KeyboardInterrupt
    # Tuple form: except (Exception,) / except (X, BaseException, ...)
    re.compile(r"^\s*except\s+\([^)]*\b(?:Exception|BaseException)\b[^)]*\)\s*(?:as\s+\w+\s*)?:"),
    re.compile(r"catch\s*\(\s*\.\.\.\s*\)"),  # C++: catch(...)
    re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)"),  # Java: catch(Exception e)
    re.compile(r"catch\s*\(\s*Throwable\s+\w+\s*\)"),  # Java: catch(Throwable t)
]

# CWE-754: Improper check for unusual conditions (I/O without error check)
IO_WITHOUT_CHECK = [
    re.compile(r"(?:open|read|write|connect|send|recv)\s*\([^)]*\)\s*$"),
]

# CWE-390: Error detection without action
EMPTY_CATCH_PATTERNS = [
    re.compile(r"except\s+\w+.*:\s*$"),  # Python: except SomeError: (check next line)
    re.compile(r"catch\s*\([^)]+\)\s*\{\s*\}"),  # Java/JS: catch(e) {}
]
PASS_OR_EMPTY = re.compile(r"^\s*(?:pass|\.\.\.)\s*$")

IMPORT_LINE = re.compile(r"^\s*(?:import|from|package)\s+")


def check_error_handling(source_path: str) -> dict:
    """Check for error handling vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of error handling issues.
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
    """Analyze a file for error handling issues."""
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
        _check_unchecked_return(file_path, line, line_num, lines, findings)
        _check_bare_except(file_path, line, line_num, lines, findings)
        _check_empty_catch(file_path, line, line_num, lines, findings)
        _check_io_without_check(file_path, line, line_num, lines, findings)


def _check_unchecked_return(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for unchecked return values (CWE-252)."""
    for pattern in UNCHECKED_RETURN_GO:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.error_handling.unchecked_return",
            "category": "CWE-252",
            "title": "Unchecked return value",
            "description": f"Return value discarded at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Check all return values, especially errors",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "252"))
        return


def _check_bare_except(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for bare or overly broad exception handlers (CWE-755)."""
    for pattern in BARE_EXCEPT_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.error_handling.bare_except",
            "category": "CWE-755",
            "title": "Overly broad exception handler",
            "description": f"Bare or catch-all exception handler at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Catch specific exception types and handle each appropriately",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "755"))
        return


def _check_empty_catch(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for empty catch/except blocks (CWE-390)."""
    # Inline empty catch: catch(e) {}
    for pattern in EMPTY_CATCH_PATTERNS:
        if not pattern.search(line):
            continue
        # For Python except, check if next line is pass
        if "except" in line and line_num < len(lines):
            next_line = lines[line_num]  # 0-indexed: line_num is already next
            if not PASS_OR_EMPTY.match(next_line):
                return
        finding = {
            "severity": "high",
            "check_id": "cwe.error_handling.empty_catch",
            "category": "CWE-390",
            "title": "Error caught but not handled",
            "description": f"Empty exception handler at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Log the error or take corrective action in catch/except blocks",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "390"))
        return


def _check_io_without_check(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for I/O operations without error checking (CWE-754)."""
    for pattern in IO_WITHOUT_CHECK:
        if not pattern.search(line):
            continue
        # Check surrounding context for error handling
        context_start = max(0, line_num - 2)
        context_end = min(len(lines), line_num + 3)
        context = "\n".join(lines[context_start:context_end])
        if re.search(r"\b(?:try|if\s+err|except|catch|\.catch)\b", context):
            return
        finding = {
            "severity": "medium",
            "check_id": "cwe.error_handling.io_no_check",
            "category": "CWE-754",
            "title": "I/O operation without error check",
            "description": f"I/O call without error handling at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Wrap I/O operations in try/except or check return values",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "754"))
        return


check_error_handling_tool = function_tool(check_error_handling)
