"""Concurrency vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-362: Race condition (shared mutable state without locks)
SHARED_STATE_PATTERNS = [
    re.compile(r"(?:threading\.Thread|Thread)\s*\(.*target\s*="),  # Python thread
    re.compile(r"go\s+\w+\s*\("),  # Go goroutine
]
LOCK_PRESENT = re.compile(
    r"\b(?:Lock|RLock|Mutex|RWMutex|sync\.Mutex|sync\.RWMutex|threading\.Lock|Semaphore)\b"
)
GLOBAL_VAR_WRITE = re.compile(r"^\s*(?:global|var)\s+\w+")

# CWE-367: TOCTOU (time-of-check time-of-use)
TOCTOU_CHECK_PATTERNS = [
    re.compile(r"os\.path\.exists\s*\("),
    re.compile(r"os\.path\.isfile\s*\("),
    re.compile(r"os\.access\s*\("),
    re.compile(r"os\.Stat\s*\("),  # Go
    re.compile(r"File\.exists\?\s*\("),  # Ruby
]
TOCTOU_USE_PATTERNS = [
    re.compile(r"\bopen\s*\("),
    re.compile(r"os\.(?:Open|Create|Remove|Rename)\s*\("),
    re.compile(r"os\.(?:remove|rename|unlink|mkdir)\s*\("),
    re.compile(r"shutil\.\w+\s*\("),
]

# CWE-833: Deadlock (nested lock acquisition)
LOCK_ACQUIRE = [
    re.compile(r"\.(?:acquire|Lock|RLock)\s*\("),
    re.compile(r"\.(?:lock|Lock)\(\)"),  # Go mutex
    re.compile(r"synchronized\s*\("),  # Java
]

# CWE-662: Improper synchronization
THREAD_NO_SYNC = [
    re.compile(r"threading\.Thread\s*\("),
    re.compile(r"go\s+func\s*\("),
]

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(?:import|from|package)\s+")


def check_concurrency(source_path: str) -> dict:
    """Check for concurrency vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of concurrency issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for concurrency issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_locks = LOCK_PRESENT.search(content) is not None
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_toctou(file_path, line, line_num, lines, findings, is_test=is_test)
        _check_thread_no_sync(file_path, line, line_num, has_locks, findings, is_test=is_test)


def _check_toctou(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
    *,
    is_test: bool,
) -> None:
    """Check for TOCTOU race conditions (CWE-367)."""
    is_check = any(p.search(line) for p in TOCTOU_CHECK_PATTERNS)
    if not is_check:
        return
    # Look for file use within next 5 lines
    window_end = min(line_num + 5, len(lines))
    window = "\n".join(lines[line_num:window_end])
    has_use = any(p.search(window) for p in TOCTOU_USE_PATTERNS)
    if not has_use:
        return
    findings.append({
        "severity": "low" if is_test else "high",
        "category": "CWE-367",
        "title": "Time-of-check time-of-use (TOCTOU) race condition",
        "description": f"File existence check at line {line_num} followed by file operation",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use atomic operations or handle errors from the operation directly",
    })


def _check_thread_no_sync(
    file_path: Path,
    line: str,
    line_num: int,
    has_locks: bool,
    findings: list[dict],
    *,
    is_test: bool,
) -> None:
    """Check for threading without synchronization (CWE-662)."""
    if has_locks:
        return
    for pattern in THREAD_NO_SYNC:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-662",
            "title": "Thread/goroutine without synchronization",
            "description": f"Concurrent execution at line {line_num} with no visible locking",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use mutexes, locks, or channels to synchronize shared state",
        })
        return


check_concurrency_tool = function_tool(check_concurrency)
