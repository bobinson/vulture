"""Blast radius assessment skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.line_context import mask_multiline, strip_strings_and_comments

ISOLATION_PATTERNS = [
    re.compile(r"bulkhead|Bulkhead|thread.?pool|semaphore", re.IGNORECASE),
    re.compile(r"rate.?limit|RateLimit|throttle", re.IGNORECASE),
    re.compile(r"namespace|isolation|partition", re.IGNORECASE),
]

# The `global` STATEMENT (Python `global x`, PHP `global $x`): the keyword first
# on its line, case-sensitive. Matched over the multi-line-masked text, so prose
# using the word -- a `# ... a global that ...` comment, a docstring line wrapped
# to begin with "global names ..." -- is not a declaration of shared state.
# ReDoS: `^` pins each attempt to a line start, so the scan is linear.
_GLOBAL_STATEMENT = re.compile(r"^[ \t]*global[ \t]+\$?[A-Za-z_]", re.MULTILINE)

SHARED_STATE_PATTERNS = [
    _GLOBAL_STATEMENT,
    re.compile(r"shared.?state|singleton", re.IGNORECASE),
    re.compile(r"\.Lock\(|sync\.Mutex|threading\.Lock"),
    re.compile(r"shared.?database|common.?cache|global.?config", re.IGNORECASE),
]

# Node.js/Next.js intentional singleton patterns (hot-reload-safe).
_NODEJS_SINGLETON = re.compile(
    r"global\.\w+\s*=\s*global\.\w+\s*\|\||declare\s+global|globalThis\.\w+",
)


def assess_blast_radius(source_path: str) -> dict:
    """Assess potential blast radius of failures in the codebase.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of blast radius issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        # Prose DESCRIBES a control; it is not an instance of one (F6).
        if is_prose_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Check a file for blast radius issues."""
    content = read_file_safe(file_path)
    shared_state_line = _unisolated_shared_state_line(content) if content else 0
    if shared_state_line:
        findings.append({
            "severity": "medium",
            "check_id": "chaos.blast_radius.missing_isolation",
            "category": "blast-radius",
            "title": "Shared state without isolation",
            "description": f"File {file_path.name} uses shared state without isolation mechanisms",
            "file_path": str(file_path),
            "line_start": shared_state_line,
            "line_end": shared_state_line,
            "recommendation": "Apply bulkhead pattern to isolate failure domains",
        })


def _unisolated_shared_state_line(content: str) -> int:
    """1-based line of the file's shared state; 0 for none, or when isolated."""
    # The raw text is a superset of the masked one: skip masking a file with no
    # candidate at all, which is most of them.
    if not any(p.search(content) for p in SHARED_STATE_PATTERNS):
        return 0
    # Split on "\n" only, so the masked text keeps the content's offsets.
    masked = mask_multiline(content.split("\n"))
    shared_state_line = _shared_state_line(content, "\n".join(masked))
    return 0 if _has_isolation(masked) else shared_state_line


def _has_isolation(masked_lines: list[str]) -> bool:
    """Whether the file's CODE uses an isolation mechanism.

    This evidence EXCUSES a finding, so it is read with comments, docstrings and
    string literals removed: a comment that mentions "namespace" isolates
    nothing, and used to hide a real ``global`` statement. A missed strip only
    keeps the old excuse.
    """
    code = "\n".join(map(strip_strings_and_comments, masked_lines))
    return any(p.search(code) for p in ISOLATION_PATTERNS)


def _shared_state_line(content: str, masked: str) -> int:
    """1-based line of the first shared-state match, by pattern order; 0 for none.

    Lines matching the Node.js/Next.js intentional singleton are skipped, and the
    line points at the actual offender, not line 1. Only the ``global`` statement
    is read from ``masked``: the other triggers keep the raw text, where a
    singleton's only signal may be its doc comment.
    """
    singleton_lines = _singleton_lines(content)
    for p in SHARED_STATE_PATTERNS:
        line_no = _first_line(p, masked if p is _GLOBAL_STATEMENT else content, singleton_lines)
        if line_no:
            return line_no
    return 0


def _singleton_lines(content: str) -> set[int]:
    """0-based lines holding a Node.js/Next.js intentional singleton."""
    return {_line_index(content, m.start()) for m in _NODEJS_SINGLETON.finditer(content)}


def _first_line(pattern: re.Pattern[str], text: str, skip: set[int]) -> int:
    """1-based line of the first match of ``pattern`` on a line not in ``skip``; 0 for none."""
    for match in pattern.finditer(text):
        line_no = _line_index(text, match.start())
        if line_no not in skip:
            return line_no + 1
    return 0


def _line_index(text: str, offset: int) -> int:
    return text.count("\n", 0, offset)


assess_blast_radius_tool = function_tool(assess_blast_radius)
