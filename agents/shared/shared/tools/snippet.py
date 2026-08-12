"""Code snippet extraction and context corroboration helpers."""

import re
from collections.abc import Sequence

# Standard ports that shouldn't trigger "hardcoded port" findings.
STANDARD_PORTS = frozenset({80, 443, 8080, 8443, 3000, 3001, 5000, 8000, 8888})


def is_standard_port(port: int) -> bool:
    """Return True if port is a well-known standard development/web port."""
    return port in STANDARD_PORTS


# Per-line cap in line-budget mode (max_chars=None). Matches the L5 judge's
# own render cap (_MAX_LINE_CHARS in validate/llm_judge.py): a minified
# bundle's single 50KB line must not defeat the line budget.
_LINE_BUDGET_LINE_CHARS = 400


def extract_snippet(
    lines: Sequence[str], line_num: int, context: int = 2,
    max_chars: int | None = 200,
) -> str:
    """Extract ±context lines around line_num.

    Args:
        lines: Source file split into lines.
        line_num: 1-based line number of the finding.
        context: Number of surrounding lines to include.
        max_chars: Character truncation for the whole snippet — 200 by
            default (the legacy contract every skill call site relies on).
            Pass ``None`` for LINE-budget mode (feature 0072 T5.2): the
            snippet is bounded by ``context`` and a per-line cap instead of
            a whole-snippet character cut, so a wide evidence window is not
            truncated mid-token.

    Returns:
        Numbered source snippet.
    """
    if not lines or line_num < 1:
        return ""
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    if max_chars is None:
        snippet = "\n".join(
            f"{i + 1}: {lines[i][:_LINE_BUDGET_LINE_CHARS]}"
            for i in range(start, end)
        )
    else:
        snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))[:max_chars]
    # Strip NUL at the origin: a snippet sampled from a binary the scanner
    # reached (a checked-in *.pyc, a stray blob) carries 0x00, which Postgres
    # TEXT rejects — and one such row aborts the whole findings INSERT batch
    # (feature 0072 P5; the backend strips it too as a persistence guarantee,
    # this keeps the SSE payload and the SQLite value clean as well).
    if "\x00" in snippet:
        snippet = snippet.replace("\x00", "")
    return snippet


def collect_handler_body(
    lines: Sequence[str],
    header_lineno_1based: int,
    max_body_lines: int = 5,
    search_window: int = 10,
) -> list[str]:
    """Return up to ``max_body_lines`` non-blank lines following an
    exception-handler header.

    Args:
        lines: Source file split into lines (0-indexed tuple/list).
        header_lineno_1based: 1-based line number of the ``except:`` or
            ``catch(...)`` header itself. Body collection begins at the
            NEXT line (index ``header_lineno_1based`` in 0-based terms,
            since 1-based lineno == 0-based "next line" index).
        max_body_lines: Stop after collecting this many non-blank lines.
        search_window: Scan at most this many raw lines past the header.

    Returns:
        List of raw (un-stripped) body lines, at most ``max_body_lines``.
    """
    body: list[str] = []
    start = header_lineno_1based
    end = min(start + search_window, len(lines))
    for i in range(start, end):
        if not lines[i].strip():
            continue
        body.append(lines[i])
        if len(body) >= max_body_lines:
            break
    return body


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
