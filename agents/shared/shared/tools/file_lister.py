"""File lister tool for agents."""

from pathlib import Path

from agents import function_tool


def list_files(path: str, pattern: str = "*") -> list[str]:
    """List files in a directory matching a glob pattern (recursive).

    Args:
        path: Directory path to search.
        pattern: Glob pattern to match (e.g. '*.py'). Defaults to '*'.

    Returns:
        List of matching file paths as strings.
    """
    root = Path(path)
    if not root.is_dir():
        return []

    results: list[str] = []
    for entry in root.rglob(pattern):
        if entry.is_file():
            results.append(str(entry))
    results.sort()
    return results


list_files_tool = function_tool(list_files)
