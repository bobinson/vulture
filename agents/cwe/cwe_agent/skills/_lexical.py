"""Shared lexical primitives for the CWE-778, CWE-770 and CWE-209 rules (feature 0101).

WHY THIS EXISTS
---------------
Each of the three rules decides on language-neutral ROLES (an error binding, a
growable buffer, a security operation) read from identifier WORDS, from the name
a handler binds its error to, from a call's argument text and from the routine a
line belongs to. Before 0101 each rule carried a private copy of those four
primitives and the copies had diverged: three routine-header regexes, two catch
binding regexes, and two word splitters that disagreed on digits (``oauth2Token``
was ``(oauth, token)`` to one and ``(oauth2, token)`` to the other). One copy
here, so a fix lands in all three rules at once.

CONTRACT
--------
Pure functions: no I/O, no environment reads, no state beyond bounded caches.
Every input is capped at ``MAX_SCAN_CHARS`` before any pattern runs, and every
quantifier is bounded, so a 512 KB single-line file costs what a 2000-character
line costs (gated by ``tests/unit/test_0101_lexical_redos.py``).

The smaller helpers every rule reads lines through live here too, for the same
reason: ``stripped_code`` (the capped, comment- and literal-free line),
``indent_width``, ``param_name`` (one reading of a parameter, so `$e`, `...args`
and `(err)` name `e`, `args` and `err` in every rule), ``paren_lists`` and
``opening_bracket``.

WHY CWE-770 KEEPS ITS OWN ROUTINE BOUNDARY
------------------------------------------
``routine_header`` answers "does this OPENER line declare a routine?". 778 and
209 only ask it of lines already known to open a block. CWE-770 scans EVERY line
upward for the routine boundary, and on an arbitrary line the member-signature
form also accepts a bare call statement (`flush(batch)`, `walk(child, acc)`),
which would cut a binding window mid-routine. So 770 stops at its own
keyword-only scope header (`def`/`func`/`fn`/`function`/`class`/`struct`/...)
and walks past a keyword-less member signature to the next keyword line or the
look-back bound.
"""
from __future__ import annotations

import re
from functools import lru_cache

from cwe_agent.skills._args import mask_literals
from shared.tools.line_context import strip_strings_and_comments
from shared.tools.pattern_matcher import _MAX_LINE_CHARS as MAX_SCAN_CHARS

__all__ = [
    "MAX_SCAN_CHARS",
    "call_argument_text",
    "catch_binding",
    "identifier_words",
    "indent_width",
    "opening_bracket",
    "param_name",
    "paren_lists",
    "routine_header",
    "stripped_code",
]

# ---------------------------------------------------------------------------
# identifier_words
# ---------------------------------------------------------------------------
# A word is a capitalised or lower-case run, or an ACRONYM run that stops before
# the capital that starts the next word (`HTTPServer` -> HTTP, Server). Digits
# stay attached to the letters before them: `oauth2Token` -> (oauth2, token),
# `loadX509Cert` -> (load, x509, cert), `HTTP2Server` -> (http2, server). `_`,
# `-` and `$` are not word characters, so they split.
_WORD = re.compile(r"[A-Z]?[a-z0-9]{1,64}|[A-Z]{1,64}[0-9]{0,16}(?![a-z])")


@lru_cache(maxsize=4096)
def identifier_words(ident: str) -> tuple[str, ...]:
    """Lower-cased words of ``ident`` split on `_`, `-`, `$` and case boundaries."""
    return tuple(w.lower() for w in _WORD.findall(ident[:MAX_SCAN_CHARS]))


# ---------------------------------------------------------------------------
# catch_binding
# ---------------------------------------------------------------------------
# The forms, tried in order; the first that matches decides. Each pattern's
# group 1 is the bound name, except the keyword clause, whose parenthesised text
# is resolved by `_clause_binding`.
_ID = r"[A-Za-z_$][\w$]{0,63}"
_PROMISE_CATCH = re.compile(   # `.catch((e) =>`, `.catch(e =>`, `.catch((e: Error) =>`
    r"\.\s{0,4}catch\s{0,4}\(\s{0,4}\(?\s{0,4}(" + _ID + r")?\s{0,4}"
    r"(?::\s{0,4}[\w$.<>\[\]|]{1,80}\s{0,4})?\)?\s{0,4}=>"
)
_KEYWORD_CATCH = re.compile(r"(?<![\w$.])catch\s{0,8}\(([^()]{0,200})\)")
_SWIFT_LET = re.compile(r"(?<![\w$.])catch\s{1,4}(?:let|var)\s{1,4}(" + _ID + r")")
_SWIFT_IMPLICIT = re.compile(r"(?<![\w$.])catch\s{0,4}\{")
_PY_EXCEPT = re.compile(r"\bexcept\b[^:\n]{0,200}?\bas\s{1,4}([A-Za-z_]\w{0,63})")
_RUBY_RESCUE = re.compile(r"\brescue\b[^\n]{0,120}?=>\s{0,4}([A-Za-z_]\w{0,63})")
_SCALA_TYPED = re.compile(r"\bcase\s{1,4}([A-Za-z_]\w{0,63})\s{0,4}:\s{0,4}[\w$.\[\]]{1,80}\s{0,4}=>")
_SCALA_EXTRACTOR = re.compile(
    r"\bcase\s{1,4}[A-Z]\w{0,63}\s{0,4}\(\s{0,4}([A-Za-z_]\w{0,63})\s{0,4}\)\s{0,4}=>"
)
_LUA_PCALL = re.compile(
    r"\b(?:local\s{1,4})?[A-Za-z_]\w{0,63}\s{0,4},\s{0,4}([A-Za-z_]\w{0,63})\s{0,4}=\s{0,4}x?pcall\s{0,4}\("
)
_CLAUSE_ID = re.compile(_ID)
_CLAUSE_MODIFIERS = frozenset({"const", "final", "var", "val", "let", "as"})
_NAMED_FORMS: tuple[re.Pattern[str], ...] = (
    _SWIFT_LET, _PY_EXCEPT, _RUBY_RESCUE, _SCALA_TYPED, _SCALA_EXTRACTOR, _LUA_PCALL,
)
# The discard binding binds nothing; 209 must never resolve a placeholder through it.
_DISCARD = "_"


def _lone_identifier(ident: str, suffix: str) -> str | None:
    """`catch (e)` binds `e`; C# `catch (Exception)` names only a type."""
    if suffix == ".cs" or ident[:1].isupper():
        return None
    return ident


def _clause_idents(clause: str) -> list[str]:
    """Identifiers of a `catch ( ... )` clause; none for C++ `(const T&)`."""
    if clause.rstrip().endswith(("&", "*")):
        return []
    return [i for i in _CLAUSE_ID.findall(clause) if i not in _CLAUSE_MODIFIERS]


def _clause_binding(clause: str, suffix: str) -> str | None:
    """The bound name inside `catch ( ... )`, or None when the clause binds none."""
    idents = _clause_idents(clause)
    if not idents:
        return None   # `catch (...)`, `catch (const std::exception&)`
    if ":" in clause.replace("::", ""):
        return idents[0]   # TS / Kotlin `e: T`
    # Java / C# / C++ / PHP `T e`, Java `A | B e`; a lone name is `catch (e)` or a C# type
    return idents[-1] if len(idents) > 1 else _lone_identifier(idents[0], suffix)


def _named_form(code: str) -> str | None:
    for pattern in _NAMED_FORMS:
        m = pattern.search(code)
        if m:
            return m.group(1)
    return None


def _first_form(code: str, suffix: str) -> str | None:
    promise = _PROMISE_CATCH.search(code)
    if promise:
        return promise.group(1)   # None for `.catch(() => ...)`: no binding
    keyword = _KEYWORD_CATCH.search(code)
    return _clause_binding(keyword.group(1), suffix) if keyword else _named_form(code)


def _implicit_binding(code: str, suffix: str) -> str | None:
    """Swift's bare `catch {` binds `error` implicitly."""
    return "error" if suffix == ".swift" and _SWIFT_IMPLICIT.search(code) else None


def catch_binding(header: str, suffix: str = "") -> frozenset[str]:
    """The name a handler header binds the error to, as a set (empty when none).

    ``suffix`` is the file suffix (``.swift``, ``.cs``); it decides only the two
    forms the clause text alone cannot: Swift's implicit ``error`` and C#'s
    type-only ``catch (Exception)``.
    """
    code = stripped_code(header)
    name = _first_form(code, suffix) or _implicit_binding(code, suffix)
    if not name:
        return frozenset()
    name = name.lstrip("$")
    return frozenset() if name in ("", _DISCARD) else frozenset({name})


# ---------------------------------------------------------------------------
# call_argument_text
# ---------------------------------------------------------------------------
_PAREN = re.compile(r"[()]")


def _closing_paren(masked: str) -> int:
    """Index of the `)` matching ``masked[0]``, or -1 when it does not close."""
    depth = 0
    for m in _PAREN.finditer(masked):
        depth += 1 if m.group(0) == "(" else -1
        if depth == 0:
            return m.start()
    return -1


def call_argument_text(text: str, open_at: int, max_span: int = 400) -> str:
    """The text between the `(` at ``open_at`` and its matching `)`.

    Literals are masked once for the span, so a `)` inside a string is not
    syntax; the returned text is the original, unmasked. An unterminated call
    is cut at ``max_span`` characters (itself capped at ``MAX_SCAN_CHARS``).
    """
    if not 0 <= open_at < len(text) or text[open_at] != "(":
        return ""
    span = text[open_at:open_at + 1 + min(max_span, MAX_SCAN_CHARS)]
    close = _closing_paren(mask_literals(span))
    return span[1:close] if close > 0 else span[1:]


# ---------------------------------------------------------------------------
# routine_header
# ---------------------------------------------------------------------------
# A declaration is recognised only by declaration syntax: a routine
# keyword; `name = (...) =>` / `name = ident =>`; or a member signature
# `name(...) {` whose first token is not a control word. So an `if (` / `for (`
# / `switch (` opener is never mistaken for the routine.
_CONTROL_WORDS = frozenset({
    "if", "for", "while", "switch", "catch", "with", "elif", "else", "until", "unless",
    "foreach", "return", "match", "when", "do", "try",
})
_DECL_KEYWORD = re.compile(r"(?:^|[\s(])(?:def|function|func|fn|fun|sub|proc)\b")
_DECL_ARROW = re.compile(
    r"=\s{0,4}(?:async\s{1,4})?(?:\([^()]{0,300}\)|[A-Za-z_$][\w$]{0,60})\s{0,4}(?::[^=]{0,80})?=>"
)
_DECL_MEMBER = re.compile(
    r"^\s{0,80}(?:(?:public|private|protected|internal|static|async|override|final|abstract|open"
    r"|suspend|export|default|readonly|virtual)\s{1,4}){0,4}"
    r"(?:[\w$<>\[\],.?]{1,80}\s{1,4})?([A-Za-z_$][\w$]{0,60})\s{0,4}\([^;]{0,300}$"
)
_SIGNATURE_ENDS = ("{", ")", ":")


def _member_signature(code: str) -> bool:
    m = _DECL_MEMBER.match(code)
    if not m or m.group(1) in _CONTROL_WORDS:
        return False
    tail = code.rstrip()
    return code.split(None, 1)[0] not in _CONTROL_WORDS and tail.endswith(_SIGNATURE_ENDS)


@lru_cache(maxsize=16384)
def routine_header(code: str) -> bool:
    """True when ``code`` (one line) declares a routine, by declaration syntax only."""
    code = stripped_code(code)
    if _DECL_KEYWORD.search(code) or _DECL_ARROW.search(code):
        return True
    return bool(code.strip()) and _member_signature(code)


# ---------------------------------------------------------------------------
# line helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=32768)
def stripped_code(line: str) -> str:
    """``line`` capped at MAX_SCAN_CHARS, then with strings and comments stripped.

    Cached by line text: every rule reads the same lines several times (the try
    walk, the opener walk, the routine scope), and two rules read the same file.
    """
    return strip_strings_and_comments(line[:MAX_SCAN_CHARS])


def indent_width(text: str) -> int:
    """Leading whitespace characters of ``text``."""
    return len(text) - len(text.lstrip())


# A parameter's name is its LAST identifier before the first `:` or `=` (a type
# annotation or a default), with `::` path separators read as one segment break.
# Identifiers exclude `$`, so a PHP `$e` names `e`; a rest/spread `...args` names
# `args`; a parenthesised `(err)` names `err`.
_PARAM_IDENT = re.compile(r"[A-Za-z_]\w{0,63}")
_PARAM_HEAD_END = re.compile(r"[:=]")
_PAREN_LIST = re.compile(r"\(([^()]{0,300})\)")


def param_name(param: str) -> str:
    """`e`, `e: Error`, `Exception e`, `$e = null`, `...args`, `(err)` -> the bound name, or ""."""
    head = _PARAM_HEAD_END.split(param[:MAX_SCAN_CHARS].replace("::", "."), maxsplit=1)[0]
    ids = _PARAM_IDENT.findall(head)
    return ids[-1] if ids else ""


def paren_lists(code: str, limit: int = 16) -> list[str]:
    """The text of each innermost parenthesised list in ``code``, left to right (at most ``limit``)."""
    out: list[str] = []
    for m in _PAREN_LIST.finditer(code[:MAX_SCAN_CHARS]):
        if len(out) >= limit:
            break
        out.append(m.group(1))
    return out


_ANY_BRACKET = re.compile(r"[()\[\]{}]")
_BRACKET_PATTERN = {True: _PAREN, False: _ANY_BRACKET}
_DEPTH_STEP = {")": 1, "]": 1, "}": 1, "(": -1, "[": -1, "{": -1}


def opening_bracket(text: str, parens_only: bool = False) -> int:
    """Index of the bracket that opens the one ``text`` ends with, or -1.

    Counts bracket depth backwards from the end over the last MAX_SCAN_CHARS
    characters; ``parens_only`` counts `(`/`)` alone, so `[`/`{` inside the call
    neither open nor close it.
    """
    pattern = _BRACKET_PATTERN[parens_only]
    depth = 0
    for m in reversed(list(pattern.finditer(text, max(0, len(text) - MAX_SCAN_CHARS)))):
        depth += _DEPTH_STEP[m.group()]
        if depth == 0:
            return m.start()
    return -1
