"""Code snippet extraction and context corroboration helpers."""

import re
from collections.abc import Sequence

# Standard ports that shouldn't trigger "hardcoded port" findings.
STANDARD_PORTS = frozenset({80, 443, 8080, 8443, 3000, 3001, 5000, 8000, 8888})


def is_standard_port(port: int) -> bool:
    """Return True if port is a well-known standard development/web port."""
    return port in STANDARD_PORTS


def extract_snippet(lines: Sequence[str], line_num: int, context: int = 2) -> str:
    """Extract ±context lines around line_num, truncated to 200 chars.

    Args:
        lines: Source file split into lines.
        line_num: 1-based line number of the finding.
        context: Number of surrounding lines to include.

    Returns:
        Numbered source snippet, max 200 characters.
    """
    if not lines or line_num < 1:
        return ""
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
    return snippet[:200]


def check_context(content: str, context_patterns: list[re.Pattern]) -> bool:  # type: ignore[type-arg]
    """Return True if any context pattern matches in file content.

    Used for two-tier source rules: a line-level match is corroborated
    by file-level context to reduce false positives.

    Args:
        content: Full file content.
        context_patterns: Compiled regex patterns to check against.

    Returns:
        True if at least one pattern matches.
    """
    return any(p.search(content) for p in context_patterns)
