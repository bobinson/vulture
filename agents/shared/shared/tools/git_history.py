"""Git history tool for agents."""

import subprocess
from pathlib import Path

from agents import function_tool


def git_log(path: str, file: str = "") -> list[dict]:
    """Get git log for a repository, optionally filtered by file.

    Args:
        path: Path to git repository root.
        file: Optional file path to filter history.

    Returns:
        List of commit dicts with hash, author, date, message.
    """
    root = Path(path)
    if not (root / ".git").is_dir():
        return []

    cmd = [
        "git", "-C", str(root), "log",
        "--format=%H|%an|%aI|%s",
        "-n", "50",
    ]
    if file:
        cmd.extend(["--", file])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    if result.returncode != 0:
        return []

    commits: list[dict] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("|", maxsplit=3)
        if len(parts) == 4:
            commits.append({
                "hash": parts[0],
                "author": parts[1],
                "date": parts[2],
                "message": parts[3],
            })
    return commits


git_log_tool = function_tool(git_log)
