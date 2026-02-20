"""File reader tool for agents."""

from agents import function_tool


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
