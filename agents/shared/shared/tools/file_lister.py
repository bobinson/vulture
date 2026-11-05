"""File lister tool for agents."""

import fnmatch
import re
from collections.abc import Callable, Iterable
from pathlib import Path

from agents import function_tool

from shared.tools.confine import admitted_files, rel_under, scan_refusal


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
    return _matching(admitted_files(root), root, pattern)


def _matching(files: Iterable[Path], base: Path, pattern: str) -> list[str]:
    """The ``files`` that ``base.rglob(pattern)`` would list, sorted.

    The listing is the audit walk's, never a raw ``rglob``: an ``rglob`` lists
    ``node_modules`` and ``.venv`` file by file, and every ignored file with
    them. The pattern keeps its ``rglob`` meaning over the path below ``base``.
    """
    matches = _rglob_matcher(pattern)
    return sorted(str(p) for p in files if matches(p.relative_to(base).parts))


# One pattern segment as the matcher holds it: ``None`` is ``**``.
_Segment = re.Pattern[str] | None


def _rglob_matcher(pattern: str) -> Callable[[tuple[str, ...]], bool]:
    """Whether a path's segments match ``rglob(pattern)``: the pattern below an
    implied leading ``**``, where ``**`` spans any number of directories and
    every other segment is an ``fnmatchcase`` pattern for exactly one name.

    A pattern ``rglob`` refuses or can only answer with directories (absolute,
    ``.``, ending in ``**``, a partial ``**``, ``..``) matches no file. It
    never raises: the pattern is model-supplied.
    """
    segments = _rglob_segments(pattern)
    if not segments:
        return lambda _parts: False
    compiled: list[_Segment] = [
        None if seg == "**" else re.compile(fnmatch.translate(seg)) for seg in ("**", *segments)
    ]
    return lambda parts: len(compiled) in _matched_states(parts, compiled)


def _rglob_segments(pattern: str) -> list[str]:
    """``pattern``'s segments as ``rglob`` reads it (empty and ``.`` segments
    dropped), or ``[]`` when it can match no file."""
    segments = [seg for seg in pattern.split("/") if seg not in ("", ".")]
    return segments if _file_pattern(pattern, segments) else []


def _file_pattern(pattern: str, segments: list[str]) -> bool:
    """Relative (``rglob`` refuses an absolute pattern), ending in a name (a
    final ``**`` lists directories only), every segment one ``rglob`` accepts."""
    ends_in_name = bool(segments) and segments[-1] != "**"
    return ends_in_name and not pattern.startswith("/") and all(map(_valid_segment, segments))


def _valid_segment(segment: str) -> bool:
    """``**`` only as a whole segment, and never ``..`` (no walked path has one)."""
    return segment != ".." and (segment == "**" or "**" not in segment)


def _matched_states(parts: tuple[str, ...], pattern: list[_Segment]) -> set[int]:
    """Run ``parts`` through the pattern as a small NFA; a state is the index
    of the next pattern segment, and ``len(pattern)`` means all matched."""
    states = _past_globstars({0}, pattern)
    for part in parts:
        states = _past_globstars(_advance(states, part, pattern), pattern)
    return states


def _advance(states: set[int], part: str, pattern: list[_Segment]) -> set[int]:
    """The states after consuming one path segment."""
    return {nxt for j in states if j < len(pattern) for nxt in _moves(pattern[j], j, part)}


def _moves(segment: _Segment, j: int, part: str) -> tuple[int, ...]:
    """``**`` consumes the segment and stays; a name pattern consumes it on a match."""
    if segment is None:
        return (j,)
    return (j + 1,) if segment.match(part) else ()


def _past_globstars(states: set[int], pattern: list[_Segment]) -> set[int]:
    """``states`` plus every state reached by letting a ``**`` match nothing."""
    closed = set(states)
    for j in states:
        while j < len(pattern) and pattern[j] is None:
            j += 1
            closed.add(j)
    return closed


list_files_tool = function_tool(list_files)


def make_list_files_tool(source_root: str):
    """Feature 0057 P1c: a source-root-CONFINED list_files tool.

    Rejects directory paths outside the audit source tree or excluded from the
    audit, and lists only what the audit walk reads: the listing is walked from
    the scan ROOT, so a model-named subdirectory keeps the root's ignore rules.
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
        if scan_refusal(path, root) or not Path(path).is_dir():
            return []
        base = Path(source_root) / rel_under(path, root)
        return _matching(admitted_files(source_root, rel_under(path, root)), base, pattern)

    return function_tool(list_files_confined)
