"""Pattern matching tool for agents."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.confine import admitted_files, rel_under, scan_refusal
from shared.tools.file_scanner import read_file_safe

# Feature 0057 P1c / finding #9: the LLM supplies the regex AND the directory.
# An adversarial / hallucinating model could send a catastrophic-backtracking
# pattern (ReDoS) against the tree, stalling the audit. Bound the work:
#   * cap the per-line length the regex sees (long lines amplify backtracking),
#   * cap the total matches returned,
#   * reject obviously-pathological pattern lengths,
#   * never let a regex error abort the tool (return [] instead).
_MAX_LINE_CHARS = 2000
_MAX_RESULTS = 500
_MAX_PATTERN_CHARS = 1000


def search_pattern(path: str, pattern: str, under: str = "") -> list[dict]:
    """Search for a regex pattern across files in a directory.

    Searches exactly the files the audit walk reads, from the cached listing
    of the walk of ``path``: ``.git``, ``node_modules``, ``__pycache__``,
    ``vendor`` and the other non-source directories are skipped, as are the
    `.vultureignore` and every `.gitignore`, and SKIP_FILES names.

    Args:
        path: Directory path to search -- the scan root whose rules apply.
        pattern: Regular expression pattern.
        under: A root-relative subdirectory to restrict the search to. The
            rules stay the root's: naming a subdirectory as ``path`` instead
            would make IT the root, and drop every ignore file above it.

    Returns:
        List of dicts with keys: file, line, match.
    """
    root = Path(path)
    if not root.is_dir():
        return []

    if not pattern or len(pattern) > _MAX_PATTERN_CHARS:
        return []
    try:
        compiled = re.compile(pattern)
    except re.error:
        return []

    results: list[dict] = []
    for file_path in admitted_files(root, under):
        _search_file(file_path, compiled, results)
        if len(results) >= _MAX_RESULTS:
            break

    return results[:_MAX_RESULTS]


def _search_file(
    file_path: Path, compiled: re.Pattern, results: list[dict]
) -> None:
    """Search a single file for pattern matches.

    Uses ``read_file_safe`` so this share the lru_cache that skill phase
    populated — no redundant disk read when the LLM tool layer fans out
    multiple search_pattern calls during analysis.
    """
    text = read_file_safe(file_path)
    if text is None:
        return

    for line_num, line in enumerate(text.splitlines(), start=1):
        # Bound the input the regex engine sees per line to limit ReDoS blast
        # radius from a tool-supplied pattern.
        if len(line) > _MAX_LINE_CHARS:
            line = line[:_MAX_LINE_CHARS]
        try:
            match = compiled.search(line)
        except re.error:
            return
        if match:
            results.append({
                "file": str(file_path),
                "line": line_num,
                "match": match.group(),
            })
            if len(results) >= _MAX_RESULTS:
                return


search_pattern_tool = function_tool(search_pattern)


def make_search_pattern_tool(source_root: str):
    """Feature 0057 P1c: a source-root-CONFINED search_pattern tool.

    Rejects directory paths outside the audit source tree or excluded from the
    audit. The search always runs from the scan ROOT, restricted to the named
    directory: the walk never follows a symlink, so no hit can resolve outside
    the root, and the root's ignore rules hold below any subdirectory.
    """
    root = Path(source_root).resolve()

    def search_pattern_confined(path: str, pattern: str) -> list[dict]:
        """Search for a regex pattern across files under the audit source tree.

        Args:
            path: Directory to search (must be inside the audit source root).
            pattern: Regular expression pattern (bounded against ReDoS).

        Returns:
            List of dicts with keys: file, line, match; empty if the directory
            is outside the audit source tree.
        """
        if scan_refusal(path, root):
            return []
        return search_pattern(source_root, pattern, under=rel_under(path, root))

    return function_tool(search_pattern_confined)
