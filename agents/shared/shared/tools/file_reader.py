"""File reader tool for agents."""

from pathlib import Path

from agents import function_tool

from shared.env import env_flag
from shared.tools.confine import is_within_root

# Feature 0076 T2.5: the LEAF line-format module, never ``shared.audit_runner``.
# ``shared/tools/__init__.py`` re-exports this module, so importing the runner from
# here closes the cycle ``audit_runner -> shared.tools.* -> __init__ -> file_reader``
# and every agent fails at startup in that (real) import order (§5.0, D16).
from shared.tools.line_format import number_lines


def _line_numbers_enabled() -> bool:
    """Feature 0075's switch, read at CALL time — not a tool-specific twin.

    One switch, one policy: "the model is always shown numbered source". This
    delegates to ``shared.env.env_flag`` rather than restating the token set:
    ``audit_runner._line_numbers_enabled`` reads the SAME variable, and while
    that function cannot be imported here (it is the cycle ``line_format``
    exists to avoid), the POLICY can be shared. When default-true switches were
    each hand-rolled their token sets drifted, so ``off`` disabled some and not
    others; an operator rolling the feed back would then leave the tool numbered
    and hand one model two presentations, the 0075 §12 defect one layer down.

    ``shared.env`` imports only ``os``, so it is safe from ``shared/tools/``.
    """
    return env_flag("VULTURE_LLM_LINE_NUMBERS", True)


def _slice_bounds(start_line: int, end_line: int, count: int) -> tuple[int, int]:
    """Half-open ``[start, end)`` index window for a 1-based, 0-means-open range."""
    return max(start_line - 1, 0), (end_line if end_line > 0 else count)


def read_file(path: str, start_line: int = 0, end_line: int = 0) -> str:
    """Read contents of a file, optionally within a line range.

    Lines are returned NUMBERED (``"30: code"``), the same presentation the batched
    feed uses, because the model is asked to report ``line_start`` for what it reads
    (feature 0076 AC4). Numbers are absolute file positions, so a ranged read of
    lines 3-5 renders ``3:``, ``4:``, ``5:``. Set ``VULTURE_LLM_LINE_NUMBERS=false``
    to restore the raw bytes.

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

    start_idx, end_idx = _slice_bounds(start_line, end_line, len(lines))
    if not _line_numbers_enabled():
        return "".join(lines[start_idx:end_idx])
    # ``readlines`` keeps the terminator; handing it to the formatter would render a
    # blank line between every source line and double the tool's cost in a budgeted
    # context. Stripping it also removes the phantom trailing element a ``split``
    # would have produced.
    return number_lines([line.rstrip("\n") for line in lines], start_idx, end_idx)


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
