"""Depth-aware argument tokeniser for call-shaped detector rules.

WHY THIS EXISTS
---------------
A detector that cares about an argument POSITION reaches for a regex stand-in
like ``[^,]+`` or ``[^)]*`` to skip the arguments it does not care about. That
is a proven false-positive class, not a style preference: the stand-in stops at
the first comma *anywhere*, so a later capture group slides onto a literal that
lives inside an EARLIER argument. Measured shape::

    createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv)

against ``create\\w*iv\\(<lit>,\\s*[^,]+,\\s*(<lit>)\\)``: the IV group matches
the ``'hex'`` that belongs to the KEY expression. Since ``Buffer.from(k, 'hex')``
is how most Node code materialises a key, the dominant SAFE idiom becomes a
finding.

The fix is to tokenise the argument list on TOP-LEVEL commas only — honouring
``()``/``[]``/``{}`` nesting and single/double/backtick quotes with escapes —
and then test one named slot. Pure functions, no I/O, no shared state.
"""

import re

# Quote-aware literal matcher. Backticks are included for JS template strings;
# an escaped quote (``'it\\'s'``) stays inside its literal.
_STRING_LITERAL = re.compile(
    r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'" r"|`(?:\\.|[^`\\])*`"
)
_DEPTH_DELTA = {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}

# Optional callee in front of the argument list: `f(`, `a.b.c(`, `new Foo(`,
# or a bare `(`. Anything else (`a, f(b)`) is already a bare argument list, so
# its inner `(` must NOT be mistaken for the wrapper.
#
# The whitespace BETWEEN identifiers is mandatory (`\s+`, not `\s*`), and that is
# a ReDoS fix rather than a style choice. The previous form
# `(?:[A-Za-z_$@][\w.$]*\s*)*\(` let a run of identifier characters be split
# across iterations in exponentially many ways, because the two character classes
# overlap (both match `$`, letters and `_`) and the separator could match empty —
# the classic `(a+)+` shape. On input that never reaches `(` the engine explored
# every partition: measured 26 `$` took 1.6 s, and each further 4 characters
# multiplied that by ~3.5. Requiring real whitespace between identifiers makes the
# partition unique, so matching is linear: 2000 characters now take 0.07 ms.
_CALL_HEAD = re.compile(
    r"^\s*(?:[A-Za-z_$@][\w.$]*(?:\s+[A-Za-z_$@][\w.$]*)*\s*)?\("
)

# Python/Ruby keyword-argument prefix: `iv="..."` occupies a positional slot but
# the value is what a slot test must see. `==` is excluded so a comparison
# expression is never mistaken for a binding.
_KWARG_PREFIX = re.compile(r"^[A-Za-z_]\w*\s*=\s*(?!=)")


def mask_literals(text: str) -> str:
    """``text`` with every string literal's body blanked, length preserved.

    Offsets into the mask are offsets into the original, so a comma or bracket
    inside a literal can never be read as syntax.
    """
    return _STRING_LITERAL.sub(lambda m: '"' + "." * (len(m.group(0)) - 2) + '"', text)


def _slot_boundary(depth: int, char: str) -> bool | None:
    """True at the call's closing bracket, False at a top-level comma, else None."""
    if depth == 0:
        return True
    return False if (char == "," and depth == 1) else None


def _arg_spans(masked: str, start: int) -> list[tuple[int, int]] | None:
    """Top-level argument spans of the call whose ``(`` sits at ``start``.

    Returns None when the call does not close inside ``masked`` — a wrapped or
    truncated call is a miss, never a guess.
    """
    spans: list[tuple[int, int]] = []
    left = start + 1
    depth = 0
    for index, char in enumerate(masked[start:], start):
        depth += _DEPTH_DELTA.get(char, 0)
        boundary = _slot_boundary(depth, char)
        if boundary is None:
            continue
        spans.append((left, index))
        left = index + 1
        if boundary:
            return spans
    return None


def _bare_spans(masked: str, offset: int) -> list[tuple[int, int]]:
    """Spans of an unwrapped argument list, split on depth-zero commas."""
    spans: list[tuple[int, int]] = []
    left = 0
    depth = 0
    for index, char in enumerate(masked):
        depth += _DEPTH_DELTA.get(char, 0)
        if char == "," and depth == 0:
            spans.append((left + offset, index + offset))
            left = index + 1
    spans.append((left + offset, len(masked) + offset))
    return spans


def _slice(text: str, spans: list[tuple[int, int]]) -> list[str]:
    """Whitespace-trimmed text for each span; a no-argument call yields []."""
    slots = [text[begin:end].strip() for begin, end in spans]
    return [] if slots == [""] else slots


def split_call_args(text: str, start: int) -> list[str] | None:
    """Positional argument slots of the call whose ``(`` sits at ``start``.

    None when the call does not close within ``text``.
    """
    spans = _arg_spans(mask_literals(text), start)
    return None if spans is None else _slice(text, spans)


def call_span_end(text: str, start: int) -> int | None:
    """Index of the bracket closing the call whose ``(`` sits at ``start``.

    None when the call does not close within ``text``. Lets a caller assert
    "this call ends the expression" instead of approximating it with ``[^)]*``,
    which cannot span a nested call.
    """
    spans = _arg_spans(mask_literals(text), start)
    return None if spans is None else spans[-1][1]


def _call_paren(masked: str) -> int | None:
    """Index of the wrapping ``(``, or None when ``masked`` is a bare list."""
    match = _CALL_HEAD.match(masked)
    return None if match is None else match.end() - 1


def split_arguments(call_text: str) -> list[str]:
    """Positional argument slots of ``call_text``.

    Accepts a whole call (``f(a, b)``), a parenthesised list (``(a, b)``) or a
    bare list (``a, b``). Commas nested inside ``()``/``[]``/``{}`` or inside a
    quoted literal do not separate slots, so ``f('x', g(k, 'hex'), iv)`` yields
    three slots and the third is ``iv`` — never the ``'hex'`` of slot two.

    An unterminated call is tokenised as far as it goes rather than discarded;
    callers needing "the call must close here" should use ``split_call_args``.
    """
    masked = mask_literals(call_text)
    start = _call_paren(masked)
    if start is None:
        return _slice(call_text, _bare_spans(masked, 0))
    spans = _arg_spans(masked, start)
    if spans is None:
        spans = _bare_spans(masked[start + 1:], start + 1)
    return _slice(call_text, spans)


def strip_kwarg_prefix(arg: str) -> str:
    """``iv="00"`` -> ``"00"``; a positional argument is returned unchanged."""
    return _KWARG_PREFIX.sub("", arg, count=1)


def arg_slot(args: list[str], index: int | None) -> str | None:
    """Slot ``index`` with any keyword-argument prefix stripped, or None."""
    if index is None or index >= len(args):
        return None
    return strip_kwarg_prefix(args[index])
