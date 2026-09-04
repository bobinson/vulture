"""Code snippet extraction and context corroboration helpers."""

import re
from collections.abc import Sequence

from shared.tools.line_context import strip_strings_and_comments

# Standard ports that shouldn't trigger "hardcoded port" findings.
STANDARD_PORTS = frozenset({80, 443, 8080, 8443, 3000, 3001, 5000, 8000, 8888})


def is_standard_port(port: int) -> bool:
    """Return True if port is a well-known standard development/web port."""
    return port in STANDARD_PORTS


# Per-line cap in line-budget mode (max_chars=None). Matches the L5 judge's
# own render cap (_MAX_LINE_CHARS in validate/llm_judge.py): a minified
# bundle's single 50KB line must not defeat the line budget.
_LINE_BUDGET_LINE_CHARS = 400


# A finding that declares a RANGE must be windowed over that range. Measured:
# `prepaidLetterCheckout.action.ts` declared line_start=120, line_end=131 and
# got a 5-line window at 118-122, because only `line_num` was ever consulted.
# The `} catch { ... }` at line 129 — the evidence that REFUTED the finding —
# sat outside it, so the L5 judge answered "the catch block is not visible,
# making it impossible to confirm", returned weight 0, and a factually false
# finding shipped at critical severity.
#
# Capped so a finding claiming a whole file cannot blow the prompt budget.
_SPAN_MAX_LINES = 40
# A 200-char whole-snippet cut cannot hold a multi-line span, so a spanned
# window is given the line-budget treatment instead of being truncated
# mid-token — which would reintroduce exactly the invisible-evidence problem.
_SPAN_MIN_CHARS = 2000


def extract_snippet(
    lines: Sequence[str], line_num: int, context: int = 2,
    max_chars: int | None = 200, line_end: int | None = None,
) -> str:
    """Extract ±context lines around line_num, or the declared span.

    Args:
        lines: Source file split into lines.
        line_num: 1-based line number of the finding.
        context: Number of surrounding lines to include.
        line_end: 1-based END of a declared multi-line range. When it exceeds
            ``line_num`` the window covers the whole range plus ``context`` on
            each side, capped at ``_SPAN_MAX_LINES``. Omitted or <= line_num
            reproduces the previous symmetric behaviour byte for byte.
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
    try:
        span_end = int(line_end) if line_end is not None else 0
    except (TypeError, ValueError):
        span_end = 0
    if span_end > line_num:
        end = min(len(lines), span_end + context, start + _SPAN_MAX_LINES)
        # A character cut would truncate the span it was just widened to hold.
        if max_chars is not None:
            max_chars = max(max_chars, _SPAN_MIN_CHARS)
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


def collect_scoped_body(
    lines: Sequence[str],
    header_lineno_1based: int,
    brace_family: bool,
    max_body_lines: int = 12,
    search_window: int = 40,
) -> list[str]:
    """Return the handler body, stopping at the END OF ITS SCOPE.

    Feature 0087 §3.5. ``collect_handler_body`` takes the next N non-blank lines
    within a fixed window and tracks neither brace depth nor indentation, so a
    logging call in the NEXT FUNCTION silently excuses the current handler. That
    is a false negative — invisible by construction, which is the failure mode
    that let the original CWE-778 defect survive unnoticed. It also biases the
    aggregate "handlers that log" ratio upward, and comparability is that
    metric's whole value.

    ``collect_handler_body`` is deliberately left untouched for its other callers.

    Args:
        brace_family: True for C-family / Go / Rust (track ``{}`` depth), False
            for Python / Ruby (track the indent column).
    """
    body: list[str] = []
    start = header_lineno_1based
    if start >= len(lines):
        return body
    end = min(start + search_window, len(lines))

    if brace_family:
        # Depth relative to the header line: the header itself opens the block,
        # so the body ends when depth returns to 0.
        header = lines[start - 1] if start >= 1 else ""
        # Count braces from the HANDLER'S OWN opening brace, not from the start
        # of the line. Counting the whole line conflates the `}` that closes the
        # preceding `try` with the handler's braces, and `} catch (e) {` -- the
        # single most common form in every brace language -- nets to zero.
        # Braces are counted on code with strings and comments REMOVED. A `}`
        # inside a string literal or a comment otherwise closes the scope early
        # and truncates the body: `catch (e) { const s = "}"; logger.error(e); }`
        # lost its logging call and became a false positive.
        header = strip_strings_and_comments(header)
        open_idx = header.rfind("{")
        if open_idx == -1:
            depth = 1  # Allman style: `{` is on the following line
        else:
            tail = header[open_idx:]
            depth = tail.count("{") - tail.count("}")
            if depth <= 0:
                # Opened AND closed on the header line: `catch { }`, or a
                # one-line handler whose body sits on the header. Either way
                # there is nothing below to read, and walking on would collect
                # the NEXT handler's lines and excuse this one with its log
                # call. Callers treat an empty body as an empty handler.
                return []
        for i in range(start, end):
            cur = lines[i]
            if cur.strip():
                body.append(cur)
            code = strip_strings_and_comments(cur)
            depth += code.count("{") - code.count("}")
            if depth <= 0:
                break
            if len(body) >= max_body_lines:
                break
        return body

    # Indent family. The body is every line indented STRICTLY deeper than the
    # header; the first line at or left of the header's column closes the scope.
    header = lines[start - 1] if start >= 1 else ""
    base = len(header) - len(header.lstrip())
    for i in range(start, end):
        cur = lines[i]
        if not cur.strip():
            continue
        if (len(cur) - len(cur.lstrip())) <= base:
            break
        body.append(cur)
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
