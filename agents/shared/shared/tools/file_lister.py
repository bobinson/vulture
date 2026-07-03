"""File lister tool for agents."""

from pathlib import Path

from agents import function_tool

from shared.tools.confine import is_within_root


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


def make_list_files_tool(source_root: str):
    """Feature 0057 P1c: a source-root-CONFINED list_files tool.

    Rejects directory paths outside the audit source tree, and filters any
    listed entries (e.g. via symlinks) that resolve outside it.
    """
    root = Path(source_root).resolve()

    def list_files_confined(path: str, pattern: str = "*") -> list[str]:
        """List files under the audit source tree matching a glob pattern.

        Args:
            path: Directory to search (must be inside the audit source root).
            pattern: Glob pattern to match (e.g. '*.py'). Defaults to '*'.

        Returns:
            Matching in-tree file paths; empty if the directory is outside
            the audit source tree.
        """
        if not is_within_root(path, root):
            return []
        return [p for p in list_files(path, pattern) if is_within_root(p, root)]

    return function_tool(list_files_confined)
