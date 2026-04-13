"""Pattern matching tool for agents."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import _walk_filtered


def search_pattern(path: str, pattern: str) -> list[dict]:
    """Search for a regex pattern across files in a directory.

    Uses ``_walk_filtered`` so that ``.git``, ``node_modules``,
    ``__pycache__``, ``vendor``, and other non-source directories
    are automatically skipped.

    Args:
        path: Directory path to search.
        pattern: Regular expression pattern.

    Returns:
        List of dicts with keys: file, line, match.
    """
    root = Path(path)
    if not root.is_dir():
        return []

    compiled = re.compile(pattern)
    results: list[dict] = []

    for file_path in _walk_filtered(root):
        _search_file(file_path, compiled, results)

    return results


def _search_file(
    file_path: Path, compiled: re.Pattern, results: list[dict]
) -> None:
    """Search a single file for pattern matches."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return

    for line_num, line in enumerate(text.splitlines(), start=1):
        match = compiled.search(line)
        if match:
            results.append({
                "file": str(file_path),
                "line": line_num,
                "match": match.group(),
            })


search_pattern_tool = function_tool(search_pattern)
