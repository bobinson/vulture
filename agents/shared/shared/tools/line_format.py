"""The ``"30: code"`` line-number format — both directions, one authority.

**LEAF MODULE.** This file imports nothing from ``shared.*`` — not even a relative
``from . import x``, which would re-enter ``shared/tools/__init__.py``. That is the
invariant, and it is asserted on this module's own AST rather than left to
convention (feature 0076, AC32).

Why it is a leaf: the write direction lived in ``audit_runner._number_lines`` and the
read direction is needed by ``shared/tools/file_reader.py``. ``shared/tools/__init__``
re-exports ``file_reader``, so a ``file_reader -> audit_runner`` import closes the
cycle ``audit_runner -> shared.tools.* -> __init__ -> file_reader -> audit_runner``.
The failure is order-dependent — importing the tool alone still succeeds — so it is
invisible to a single-order test and breaks every agent at startup. Both sides can
depend on a leaf; neither can depend on the other.

The prefix is a contract with the model, not a presentation detail: the model is shown
``"30: code"`` and is asked to report ``line_start``, so the bytes written here and the
bytes read back must be the same bytes. ``number_lines`` is moved verbatim from
``audit_runner._number_lines`` (which stays as an alias) and ``strip_line_number`` is
its exact inverse.
"""

import re
from collections.abc import Sequence

# THE read-direction pattern. Groups: (1) leading whitespace, (2) the line number,
# (3) the original line. ``re.DOTALL`` is load-bearing: a presented "line" may itself
# contain a newline, and without it ``(.*)$`` cannot span one, the match fails
# outright, and the prefix survives into every comparison as a phantom difference.
NUMBER_RE: re.Pattern[str] = re.compile(r"^(\s*)(\d+):\s?(.*)$", re.DOTALL)


def number_lines(lines: Sequence[str], start: int = 0, end: int | None = None) -> str:
    """Render ``lines[start:end]`` with ABSOLUTE 1-based line numbers.

    The SINGLE authority for the one format the model is ever shown, ``"30: code"``.
    It existed inline in two places inside ``_extract_file_snippet`` and nowhere
    else, which is how the two prompt paths came to disagree about whether a file
    gets numbered at all (feature 0075). Numbers are absolute file positions, never
    snippet-relative: a snippet beginning at file line 200 renders ``200:``, because
    a number that restarts at 1 is worse than no number — the model's output would
    look precise and be systematically wrong by the snippet offset.

    The window is clamped, never checked: ``end`` past the last line renders what
    exists and a ``start`` past it renders nothing, because a caller's window is
    routinely derived from a model-reported line number.
    """
    if end is None:
        end = len(lines)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, min(end, len(lines))))


def strip_line_number(line: str) -> str:
    """Remove one ``"NN: "`` prefix — the exact inverse of :func:`number_lines`.

    Returns *line* UNCHANGED when it carries no prefix. That identity property is
    what makes this safe to apply unconditionally: a caller never has to know
    whether the text it holds came from a numbered render or from the raw file, and
    a caller forced to decide is one that will decide wrongly on the path nobody
    tested.

    Exactly one prefix comes off — the outermost. ``number_lines`` numbers
    unconditionally, so a source line that already reads ``"12: x"`` is presented as
    ``"1: 12: x"`` and must strip back to ``"12: x"``. The corollary is that a RAW
    line of that shape loses a real character sequence; that is the accepted trade,
    because this direction exists to undo the write direction and the write
    direction always ran.
    """
    match = NUMBER_RE.match(line)
    if match is None:
        return line
    return match.group(3)
