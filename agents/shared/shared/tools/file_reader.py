"""File reader tool for agents."""

from pathlib import Path

from agents import function_tool

from shared.tools.confine import is_within_root


def read_file(path: str, start_line: int = 0, end_line: int = 0) -> str:
    """Read contents of a file, optionally within a line range.

    Args:
        path: Absolute path to the file.
        start_line: First line to read (1-based). 0 means start from beginning.
        end_line: Last line to read (1-based). 0 means read to end.

    Returns:
        File contents as string, or error message if file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError) as exc:
        return f"Error: {exc}"

    if start_line <= 0 and end_line <= 0:
        return "".join(lines)

    start_idx = max(start_line - 1, 0)
    end_idx = end_line if end_line > 0 else len(lines)
    return "".join(lines[start_idx:end_idx])


read_file_tool = function_tool(read_file)


def make_read_file_tool(source_root: str):
    """Feature 0057 P1c: a source-root-CONFINED read_file tool.

    The LLM-supplied ``path`` is model-controlled; a prompt-injected /
    hallucinating model could ask to read ``/etc/passwd`` or ``~/.ssh/id_rsa``
    and exfiltrate it via a finding. This wrapper rejects any path that does
    not resolve to a file under ``source_root`` (symlink-escape safe).
    """
    root = Path(source_root).resolve()

    def read_file_confined(path: str, start_line: int = 0, end_line: int = 0) -> str:
        """Read a file within the audit source tree, optionally by line range.

        Args:
            path: Path to the file (must be inside the audit source root).
            start_line: First line (1-based). 0 means from the beginning.
            end_line: Last line (1-based). 0 means to the end.

        Returns:
            File contents, or an error message if the path is outside the
            audit source tree or cannot be read.
        """
        if not is_within_root(path, root):
            return "Error: path is outside the audit source tree"
        return read_file(path, start_line, end_line)

    return function_tool(read_file_confined)
