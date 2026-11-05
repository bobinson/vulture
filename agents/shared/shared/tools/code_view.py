"""A column-preserving, language-aware view of a source file's CODE.

WHY THIS EXISTS
---------------
A rule whose construct is a call reported the call's NAME wherever it was
written: an eval call named in a trailing comment, and an exec-of-compile call
named in a module docstring and in a list of description strings, were CRITICAL
code-injection rows in one self-scan. A line-local strip cannot fix that: a docstring or a template
literal spans lines, and only a pass over the whole file knows whether a line
starts inside one.

``mask_non_code(text, language)`` returns ``text`` with every comment, and the
text of every string literal, replaced by spaces. Line count and columns are
kept, the quotes stay, and code a literal INTERPOLATES stays code: a template
literal's ``${...}``, a Python f-string's ``{...}`` (``{{`` is a literal brace),
a Ruby double-quoted ``#{...}``. ``CodeView`` is the lazy per-file wrapper a
rule holds: ``view.line(n)`` is line ``n`` (1-based) of that view.

SAFETY BIAS -- the inversion ``line_context`` documents: inside a DETECTOR an
over-blanked call is a dropped finding. So:

* Only a construct that CLOSES is blanked. One that does not -- a one-line
  string still open at the end of its line, anything still open at the end of
  the file, nesting deeper than ``_MAX_DEPTH`` -- is discarded together with
  everything opened inside it, and lexing resumes where it stopped. A mis-read
  lexeme (a JSX apostrophe, a regex literal holding a quote) therefore leaves
  text visible; it does not hide the code after it.
* A language without a lexer row is not masked at all: ``line(n)`` is the raw
  line. Every name ``shared.language.detect_language`` returns has an explicit
  row, so "unmasked" is a decision, never an omission.

COST: one left-to-right pass. Every body is consumed by one possessive regex
step, and a failed construct resumes at the furthest point it reached, so each
character is lexed once and the pass is linear in the file, whatever the input.
A view is built per file, on the first line a rule asks for, held by that
file's context and dropped with it: never cached across files, and confined to
the one thread scanning the file.

This is the canonical masked view. The older line-local strippers
(``line_context.strip_strings_and_comments`` / ``mask_multiline`` /
``interpolated_code``, the CWE skills' ``_args.mask_literals``) predate it and
are candidates to move onto it. For the languages the AST tier parses, the
exact answer is the tree; this lexer is the regex tier's fallback.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = ["CodeView", "mask_non_code", "masks"]

# An interpolation nested deeper than this is a mis-read (or a hostile file), so
# its construct fails instead of recursing further.
_MAX_DEPTH = 8

_NON_NEWLINE = re.compile(r"[^\n]")


class _Fail(Exception):
    """A construct that does not close; ``at`` is the furthest position its scan reached."""

    def __init__(self, at: int) -> None:
        super().__init__(at)
        self.at = at


@dataclass(frozen=True, slots=True)
class _Literal:
    """One kind of string literal: its body scanner and how it ends."""

    body: re.Pattern[str]      # consumes ordinary content possessively, stops at a special char
    close: str                 # closing delimiter
    interp: str | None = None  # opener of an interpolated field, if the literal has fields
    multiline: bool = False    # may the literal span lines (a one-line literal fails at `\n`)


def _lit(body: str, close: str, interp: str | None = None, multiline: bool = False) -> _Literal:
    return _Literal(re.compile(body), close, interp, multiline)


# One line, backslash escapes (an escaped newline continues the literal), no fields.
_DQ = _lit(r'(?:[^"\\\n]|\\[\s\S])*+', '"')
_SQ = _lit(r"(?:[^'\\\n]|\\[\s\S])*+", "'")
# The same, spanning lines (PHP).
_DQ_LINES = _lit(r'(?:[^"\\]|\\[\s\S])*+', '"', multiline=True)
_SQ_LINES = _lit(r"(?:[^'\\]|\\[\s\S])*+", "'", multiline=True)
# Python: f/t-strings open a field at `{`; `{{` is a literal brace. A backslash
# does not escape a brace there (`f"\{x}"` is a backslash, then a field).
_PY_FDQ = _lit(r'(?:[^"\\\n{]|\\[^{]|\\(?=\{)|\{\{)*+', '"', "{")
_PY_FSQ = _lit(r"(?:[^'\\\n{]|\\[^{]|\\(?=\{)|\{\{)*+", "'", "{")
_PY_TDQ = _lit(r'(?:[^"\\]|\\[\s\S]|"(?!""))*+', '"""', multiline=True)
_PY_TSQ = _lit(r"(?:[^'\\]|\\[\s\S]|'(?!''))*+", "'''", multiline=True)
_PY_FTDQ = _lit(r'(?:[^"\\{]|\\[^{]|\\(?=\{)|"(?!"")|\{\{)*+', '"""', "{", True)
_PY_FTSQ = _lit(r"(?:[^'\\{]|\\[^{]|\\(?=\{)|'(?!'')|\{\{)*+", "'''", "{", True)
# JS/TS template literal: spans lines, `${` opens a field.
_JS_TEMPLATE = _lit(r"(?:[^`\\$]|\\[\s\S]|\$(?!\{))*+", "`", "${", True)
# Ruby double quotes: `#{` opens a field.
_RB_DQ = _lit(r'(?:[^"\\\n#]|\\[\s\S]|#(?!\{))*+', '"', "#{")
# Go raw string: spans lines, no escapes at all (`\` is the last char of `C:\`).
_GO_RAW = _lit(r"[^`]*+", "`", multiline=True)

# A JS/TS regex literal's body, one line; a class `[...]` may hold an unescaped `/`.
_REGEX_BODY = re.compile(r"(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*+\])*+")
# A `/` after one of these (or at the start of a line) opens a regex literal, not
# a division. `<` is left out so the `/` of a JSX closing tag (`</p>`) is never
# read as one, and `}` so a self-closing `<Foo a={x} />` is not; a `)`, `]`,
# `}`, identifier or number before the `/` makes it a division.
_REGEX_AFTER = frozenset("\n(,=:[!&|?{;+-*%>~^")
_REGEX_KEYWORDS = frozenset({
    "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void",
    "throw", "yield", "await", "instanceof",
})
# How far back the token before a `/` is looked for: past this many blanks the
# `/` is read as starting its line.
_REGEX_LOOKBACK = 64
_WORD_BEFORE = re.compile(r"(?<![\w$])[A-Za-z]{2,10}$")


@dataclass(frozen=True, slots=True)
class _Syntax:
    """The lexemes of one language that are not code."""

    code: re.Pattern[str]      # the next comment or literal opener, in code
    nested: re.Pattern[str]    # the same plus `{` / `}`, inside an interpolated field
    literals: dict[tuple[str, bool], _Literal]   # (quote, prefix interpolates) -> literal
    regex_literals: bool = False
    # Where code starts when a file is mostly not code (PHP's `<?php` after HTML);
    # the code regex then also yields `leave` where it ends (`?>`). None: all code.
    region: re.Pattern[str] | None = None


def _syntax(
    openers: str, literals: dict[tuple[str, bool], _Literal],
    regex_literals: bool = False, region: str | None = None,
) -> _Syntax:
    return _Syntax(
        re.compile(openers),
        re.compile(openers + r"|(?P<ob>\{)|(?P<cb>\})"),
        literals,
        regex_literals,
        None if region is None else re.compile(region),
    )


# A block comment opens only where code can hold one: never right after a word
# character, `*`, `[` or `\` -- the `/*` of `/admin/*` in markup or a heredoc, or
# of `\/*` or `[/*]` in a regex, is text, and read as a comment it hid every line
# up to the next `*/`.
_C_COMMENTS = r"(?P<lc>//)|(?P<bc>(?<![\w\\*\[])/\*)"
# A quote right after an identifier character is an apostrophe in text
# (`Can't`, `it's` in JSX), never a string in code.
_QUOTE = r"(?<![\w$])[\"']"
_PYTHON = _syntax(
    r"(?P<lc>\#)|(?P<str>(?:(?<![\w])(?P<p>[rRbBuUfFtT]{1,2}))?(?P<q>\"\"\"|'''|\"|'))",
    {
        ('"', False): _DQ, ("'", False): _SQ, ('"', True): _PY_FDQ, ("'", True): _PY_FSQ,
        ('"""', False): _PY_TDQ, ("'''", False): _PY_TSQ, ('"""', True): _PY_FTDQ, ("'''", True): _PY_FTSQ,
    },
)
# A backtick after a markup `>` (JSX `<kbd>`</kbd>`) is text; after `=>` it opens a template.
_JAVASCRIPT = _syntax(
    _C_COMMENTS + r"|(?P<re>/)|(?P<str>(?P<q>(?<![^=]>)`|" + _QUOTE + "))",
    {('"', False): _DQ, ("'", False): _SQ, ("`", False): _JS_TEMPLATE},
    regex_literals=True,
)
_GO = _syntax(
    _C_COMMENTS + r"|(?P<str>(?P<q>[`\"']))",
    {('"', False): _DQ, ("'", False): _SQ, ("`", False): _GO_RAW},
)
# PHP: code only between `<?php` (or `<?=`) and `?>`; the markup around it is
# never lexed. `#[...]` is a PHP 8 attribute, not a comment. Strings span lines;
# a heredoc or nowdoc runs to its terminator line.
_PHP = _syntax(
    r"(?P<lc>//|\#(?!\[))|(?P<bc>(?<![\w\\*\[])/\*)|(?P<leave>\?>)"
    r"|(?P<hd><<<[ \t]*(?P<hq>[\"']?)(?P<hid>[A-Za-z_]\w*)(?P=hq)(?=[ \t]*\r?\n))"
    r"|(?P<str>(?P<q>" + _QUOTE + "))",
    {('"', False): _DQ_LINES, ("'", False): _SQ_LINES},
    region=r"<\?(?:php\b|=)?",
)
# Ruby: a `#` opens a comment only at a line start or after a blank, so the `#`
# of a regex (`/#/`) is not one. A backtick is a shell command, so it stays code.
_RUBY = _syntax(
    r"(?P<lc>(?<!\S)\#)|(?P<str>(?P<q>" + _QUOTE + "))",
    {('"', False): _RB_DQ, ("'", False): _SQ},
)

# One row per name `shared.language.detect_language` returns (a unit test holds
# them equal). None: no lexer, so the view of that file is its raw text -- a rule
# reads such a file exactly as it did before this module existed.
_SYNTAX: dict[str, _Syntax | None] = {
    "python": _PYTHON,
    "javascript": _JAVASCRIPT,
    "typescript": _JAVASCRIPT,
    "go": _GO,
    "php": _PHP,
    "ruby": _RUBY,
    **dict.fromkeys(
        (
            "java", "objc", "kotlin", "rust", "csharp", "c", "cpp", "swift", "scala", "shell",
            "sql", "yaml", "json", "toml", "html", "css", "markdown", "lua", "r", "dart", "perl",
            "dockerfile", "makefile", "groovy", "unknown",
        ),
        None,
    ),
}


def masks(language: str) -> bool:
    """Whether files of ``language`` get a masked view (else the view is the raw text)."""
    return _SYNTAX.get(language) is not None


def mask_non_code(text: str, language: str) -> str:
    """``text`` with comments and literal text blanked to spaces (see the module doc)."""
    syntax = _SYNTAX.get(language)
    if syntax is None:
        return text
    return _blank(text, _Lexer(text, syntax).spans())


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    """``text`` with each (ordered, disjoint) span replaced by spaces, newlines kept."""
    parts: list[str] = []
    prev = 0
    for start, end in spans:
        parts.append(text[prev:start])
        seg = text[start:end]
        parts.append(_NON_NEWLINE.sub(" ", seg) if "\n" in seg else " " * (end - start))
        prev = end
    parts.append(text[prev:])
    return "".join(parts)


_BRACE_DELTA = {"ob": 1, "cb": -1}


def _scan(body: re.Pattern[str], text: str, pos: int) -> int:
    """Where a possessive body loop (which always matches, maybe empty) stops."""
    m = body.match(text, pos)
    return pos if m is None else m.end()


class _Lexer:
    """One pass over ``text``: the spans to blank, in order.

    Each top-level construct is a transaction: its spans, and those of every
    construct nested in its fields, are kept only when it closes.
    """

    __slots__ = ("text", "syntax", "_nl_from", "_nl")

    def __init__(self, text: str, syntax: _Syntax) -> None:
        self.text = text
        self.syntax = syntax
        # The first newline at or after `_nl_from`: every field of a one-line
        # literal asks where its line ends, and on a file that is one long line
        # re-searching from each field would read the rest of the file each time.
        self._nl_from = self._nl = -1

    def spans(self) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        pos = self._enter(0)
        while (m := self.syntax.code.search(self.text, pos)) is not None:
            if m.lastgroup == "leave":
                pos = self._enter(m.end())
                continue
            pending: list[tuple[int, int]] = []
            try:
                pos = self._construct(m, pending, 0, None)
            except _Fail as fail:
                pos = max(fail.at, m.end())
                continue
            spans += pending
        return spans

    def _enter(self, pos: int) -> int:
        """Where code next starts at or after ``pos``: there, or after the next
        region opener of a language that has regions (else the end: no code)."""
        region = self.syntax.region
        if region is None:
            return pos
        m = region.search(self.text, pos)
        return len(self.text) if m is None else m.end()

    def _construct(self, m: re.Match[str], pending: list, depth: int, limit: int | None) -> int:
        """Lex the construct ``m`` opens; the position after it. Raises ``_Fail``."""
        return _HANDLERS[m.lastgroup or ""](self, m, pending, depth, limit)

    def _line_comment(self, m: re.Match[str], pending: list, _depth: int, _limit: int | None) -> int:
        """To the end of the line -- or, in a language with regions, to a `?>` before it."""
        end = self._eol(m.start(), None)
        if self.syntax.region is not None:
            leave = self.text.find("?>", m.start(), end)
            end = end if leave < 0 else leave
        pending.append((m.start(), end))
        return end

    def _heredoc(self, m: re.Match[str], pending: list, _depth: int, _limit: int | None) -> int:
        """A heredoc/nowdoc body, up to the line that holds only its identifier."""
        close = re.compile(rf"^[ \t]*{re.escape(m['hid'])}(?!\w)", re.MULTILINE).search(self.text, m.end())
        if close is None:
            raise _Fail(len(self.text))
        pending.append((m.end(), close.start()))
        return close.end()

    def _block_comment(self, m: re.Match[str], pending: list, _depth: int, _limit: int | None) -> int:
        close = self.text.find("*/", m.end())
        if close < 0:
            raise _Fail(len(self.text))
        pending.append((m.start(), close + 2))
        return close + 2

    def _regex(self, m: re.Match[str], pending: list, _depth: int, _limit: int | None) -> int:
        """A regex literal's body is text; a `/` in a division context is code."""
        if not self._regex_context(m.start()):
            return m.end()
        end = _scan(_REGEX_BODY, self.text, m.end())
        if not self.text.startswith("/", end):
            # An unclosed class `[` was scanned to the end of the line before the
            # body gave it back, so resume there: resuming at `end` re-reads it.
            raise _Fail(self._eol(end, None))
        pending.append((m.end(), end))
        return end + 1

    def _regex_context(self, at: int) -> bool:
        """Whether a `/` at ``at`` opens a regex literal, by the token before it."""
        before = self.text[max(0, at - _REGEX_LOOKBACK):at].rstrip(" \t")
        if before.endswith(("++", "--")):
            return False  # `i++ / 2`: a postfix operand, divided
        if not before or before[-1] in _REGEX_AFTER:
            return True
        word = _WORD_BEFORE.search(before)
        return word is not None and word.group() in _REGEX_KEYWORDS

    def _string(self, m: re.Match[str], pending: list, depth: int, limit: int | None) -> int:
        prefix = (m.groupdict().get("p") or "").lower()
        literal = self.syntax.literals[(m["q"], "f" in prefix or "t" in prefix)]
        return self._literal(literal, m.end(), pending, depth, limit)

    def _literal(self, literal: _Literal, pos: int, pending: list, depth: int, limit: int | None) -> int:
        """A literal whose body starts at ``pos``; the position after its close."""
        while True:
            end = _scan(literal.body, self.text, pos)
            if end > pos:
                pending.append((pos, end))
            if self.text.startswith(literal.close, end):
                return end + len(literal.close)
            pos = self._open_field(literal, end, pending, depth, limit)

    def _open_field(self, literal: _Literal, at: int, pending: list, depth: int, limit: int | None) -> int:
        """The field the literal opens at ``at``; it fails there when it opens none
        (a newline in a one-line literal, or the end of the file)."""
        if not (literal.interp and self.text.startswith(literal.interp, at)):
            raise _Fail(at)
        field_limit = limit if literal.multiline else self._eol(at, limit)
        return self._field(at + len(literal.interp), pending, depth + 1, field_limit)

    def _eol(self, at: int, limit: int | None) -> int:
        """End of the line holding ``at`` (its newline, or the end of the text), capped at ``limit``."""
        if not self._nl_from <= at <= self._nl:
            nl = self.text.find("\n", at)
            self._nl_from, self._nl = at, len(self.text) if nl < 0 else nl
        return self._nl if limit is None else min(self._nl, limit)

    def _field(self, pos: int, pending: list, depth: int, limit: int | None) -> int:
        """An interpolated field: code up to its matching `}`; the position after it.

        ``limit`` bounds the field of a one-line literal to that line.
        """
        if depth > _MAX_DEPTH:
            raise _Fail(pos)
        bound = len(self.text) if limit is None else limit
        braces = 1
        while braces:
            m = self._next_in_field(pos, bound)
            braces += _BRACE_DELTA.get(m.lastgroup or "", 0)
            pos = self._past(m, pending, depth, limit, bound)
        return pos

    def _next_in_field(self, pos: int, bound: int) -> re.Match[str]:
        m = self.syntax.nested.search(self.text, pos, bound)
        if m is None:
            raise _Fail(bound)
        return m

    def _past(self, m: re.Match[str], pending: list, depth: int, limit: int | None, bound: int) -> int:
        """The position past a brace, or past the construct ``m`` opens inside a field."""
        if m.lastgroup in _BRACE_DELTA:
            return m.end()
        pos = self._construct(m, pending, depth, limit)
        if pos > bound:
            raise _Fail(pos)
        return pos


_HANDLERS = {
    "lc": _Lexer._line_comment,
    "bc": _Lexer._block_comment,
    "hd": _Lexer._heredoc,
    "re": _Lexer._regex,
    "str": _Lexer._string,
}


class CodeView:
    """The masked view of one file, built on first use (see the module doc).

    ``line(n)`` is 1-based. Built for the file's lines exactly as a skill read
    them, so line ``n`` of the view and line ``n`` of the file share columns.
    ``memo`` holds facts a rule derives from this file's view, so they are
    computed once per file and dropped with it, never across files.
    """

    __slots__ = ("language", "memo", "_lines", "_view")

    def __init__(self, lines: Sequence[str], language: str) -> None:
        self.language = language
        self.memo: dict = {}
        self._lines = lines
        self._view: Sequence[str] | None = None

    def __len__(self) -> int:
        return len(self._lines)

    def line(self, line_num: int) -> str:
        view = self._view
        if view is None:
            view = self._view = self._build()
        return view[line_num - 1]

    def raw(self, line_num: int) -> str:
        """Line ``line_num`` of the file itself: what a blanked column held."""
        return self._lines[line_num - 1]

    def _build(self) -> Sequence[str]:
        if not masks(self.language):
            return self._lines
        return mask_non_code("\n".join(self._lines), self.language).split("\n")
