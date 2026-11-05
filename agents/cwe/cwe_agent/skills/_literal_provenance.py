"""Whether a Go ``fmt.Sprintf`` puts only constant text into the string it builds.

WHY THIS EXISTS
---------------
CWE-89 reported, at CRITICAL, a repository method that builds its SET clause
from literals and its placeholder index from a count::

    sets := "evidence_file_hash = $1, updated_at = now()"
    if ev.UpdateWindow {
        sets += fmt.Sprintf(", evidence_line_start = $%d", len(args)+1)
    }
    q := fmt.Sprintf(updateLineage, sets, len(args))

where ``updateLineage`` is the literal ``UPDATE finding_lineage SET %s WHERE
id = $%d``. Every value in that statement is a bound parameter: what ``Sprintf`` splices
in is text the function itself wrote. The row is a false positive whose shape
recurs wherever Go code assembles a dynamic column list for a parameterised
query.

THE TEST -- textual and conservative: anything it cannot prove is reported, as
before.

* The call stands alone: the whole right-hand side of an assignment, a
  ``return`` value, or the query argument of a call that executes SQL
  (``db.Query(``, ``tx.ExecContext(ctx,``). Nothing on its line adds to it (no
  ``+``, ``%``, second ``Sprintf`` or closure), and a name it is assigned to is
  never extended afterwards except by literals (``q += " LIMIT 1"``).
* The format is one literal; its verbs pair 1:1 with the arguments. An explicit
  index (``%[2]s``), a ``*`` width or precision, a spread (``args...``) or an
  escape that could spell ``%`` ends the proof.
* A verb that prints a number, a bool or hex digits (``%d``, ``%x``, ``%f``...)
  is safe whatever its argument: ``go vet``, which ``go test`` runs, rejects an
  argument of another type. ``%c`` is excluded: it prints the character an
  integer names, ``'`` included.
* Any other verb's argument is a literal, or an identifier LITERAL-BUILT in its
  function: across the whole top-level ``func`` holding the call (writes after
  the call count -- a loop carries them back), its first occurrence is its one
  definition (``x := LITS``, ``var x string``, ``var x [string] = LITS``) and
  every other write is ``x = LITS`` or ``x += LITS`` as a whole statement, where
  LITS joins literals and number-only ``fmt.Sprintf`` calls with ``+`` (and, in
  a write, ``x`` itself; in a definition ``x`` would be an outer variable). A
  ``func`` on a line where it occurs (a parameter, receiver, named result or
  closure), ``&x`` or ``&(x)``, ``x`` followed by a type (a parameter or a
  field), a multi-name or keyword-led left-hand side (``a, x :=``,
  ``for _, x :=``, ``if x :=``), or a statement continued after ``x,`` means not
  proven. Go strings are values, so these textual writes are all its writes.

Lines are read from the file's masked code view, so a raw string spanning
lines, a comment or a literal's text never looks like code. The scan is bounded:
``_ROUTINE_LOOKBACK`` lines up to the ``func`` and as many past the call to the
end of its body, each line cut at ``MAX_SCAN_CHARS`` -- a line longer than that
holding the name ends the proof rather than hiding a write. Each statement is
read once per name (a few searches, not one per occurrence), and a name's
verdict is kept on the file's view, so a function with many calls reads its
lines once per name.

This is the regex tier's stand-in for the AST origin engine's constant-argument
test (``shared.ast._origins._all_constant``); when the AST tier owns CWE-89 for
Go, the tree answers this instead.
"""
from __future__ import annotations

import re

from cwe_agent.skills._args import arg_spans
from cwe_agent.skills._lexical import _ROUTINE_LOOKBACK, MAX_SCAN_CHARS
from shared.tools.code_view import CodeView

# ── printf formats (Go, C, PHP and Python `%` share this grammar) ────────────

_VERB = re.compile(r"%([^A-Za-z%]*+)([A-Za-z%])")
# An explicit argument index or a `*` width/precision: verbs no longer pair with
# arguments in order.
_UNPAIRED = re.compile(r"%[^A-Za-z%*\[]*+[*\[]")


def printf_verbs(fmt: str) -> list[str] | None:
    """The conversion verbs of a printf format, in order; ``%%`` is text.

    None when the verbs do not take the arguments one each, in order.
    """
    if _UNPAIRED.search(fmt):
        return None
    return [verb for spec, verb in _VERB.findall(fmt) if verb != "%" or spec]


_NUMERIC_VERBS = frozenset("bdoOxXeEfFgGtU")

# ── Go ──────────────────────────────────────────────────────────────────────

_SPRINTF = re.compile(r"(?<![\w.])fmt\.Sprintf\s*\(")
# One literal: the view blanks a literal's text, so no quote is left inside it.
_ONE_LITERAL = re.compile(r'\s*(?:"[^"]*"|`[^`]*`)\s*')
# An interpreted literal's escape that spells `%` hides a verb from the parser.
_PERCENT_ESCAPE = re.compile(r"\\(?:x25|045|u0025|U00000025)")
_IDENT = re.compile(r"\s*([A-Za-z_]\w*)\s*")
_SPREAD = re.compile(r"\.\.\.\s*$")
# What on the call's line, outside it, can add text to its result.
_COMBINES = re.compile(r"[+%]|\bSprintf\b|(?<![\w.])func\b")
# What the call may stand after: an assignment, `return`, or the query argument of
# a call whose name says it runs SQL (an optional context argument first).
_STANDS_AFTER = re.compile(
    r"(?:(?<![=!<>:])=|:=|\breturn|\.\s*(?:query|exec|prepare|raw)\w*\s*\((?:\s*\w+\s*,)?)\s*$",
    re.IGNORECASE,
)
_ASSIGNED_NAME = re.compile(r"(?<![\w.,])([A-Za-z_]\w*)\s*:?=\s*$")
_TOP_FUNC = re.compile(r"func\b")              # gofmt puts top-level funcs at column 0
_FUNC_WORD = re.compile(r"(?<![\w.])func\b")
_STATEMENT = re.compile(r"[^;{}]+")
_ASSIGN = re.compile(r":=|<<=|>>=|&\^=|[-+*/%&|^]=|(?<![=!<>])=(?!=)")
_WRITE_KIND = {":=": "def", "=": "write", "+=": "write"}
_VAR = re.compile(r"\s*var\s+([A-Za-z_]\w*)\b")
_VAR_ZERO = re.compile(r"\s+string\s*")
_VAR_INIT = re.compile(r"(?:\s+string)?\s*=")
_PLUS_OR_BRACKET = re.compile(r"[+()\[\]]")


def constant_sprintf(view: CodeView, line_num: int, at: int) -> bool:
    """Whether the ``fmt.Sprintf`` call holding column ``at`` of line ``line_num``
    splices only constant text into a result nothing else extends (module doc)."""
    found = _alone_call(view, line_num, at)
    if found is None:
        return False
    start, args, verbs = found
    code = view.line(line_num)
    return all(_constant_arg(view, line_num, verb, code[a:b]) for verb, (a, b) in zip(verbs, args)) \
        and _result_stays_constant(view, line_num, code[:start])


def _alone_call(view: CodeView, line_num: int, at: int) -> tuple[int, list[tuple[int, int]], list[str]] | None:
    """(start, argument spans after the format, verbs) of the ``fmt.Sprintf`` holding
    ``at``, when it stands alone and its verbs pair with its arguments."""
    code = view.line(line_num)
    call = _call_at(code, at)
    if call is None or not _stands_alone(code, *call):
        return None
    verbs = _paired_verbs(view, line_num, call[1])
    return None if verbs is None else (call[0], call[1][1:], verbs)


def _call_at(code: str, at: int) -> tuple[int, list[tuple[int, int]]] | None:
    """(start, argument spans) of the ``fmt.Sprintf`` call on ``code`` whose span
    holds ``at``, the format first; None on a line too long to read whole."""
    if len(code) > MAX_SCAN_CHARS:
        return None
    for m in _SPRINTF.finditer(code):
        spans = arg_spans(code, m.end() - 1)
        if spans is not None and m.start() <= at <= spans[-1][1]:
            return m.start(), spans
    return None


def _stands_alone(code: str, start: int, spans: list[tuple[int, int]]) -> bool:
    """Nothing on the line adds to the call's result, and the call is a whole
    assignment, a ``return`` value or a SQL call's query argument."""
    outside = code[:start] + " " + code[spans[-1][1] + 1:]
    return _COMBINES.search(outside) is None and _STANDS_AFTER.search(code[max(0, start - 80):start]) is not None


def _paired_verbs(view: CodeView, line_num: int, spans: list[tuple[int, int]]) -> list[str] | None:
    """The verbs of the format at ``spans[0]`` when it is one literal whose verbs
    take the remaining arguments one each (no spread); else None."""
    code = view.line(line_num)
    if any(_SPREAD.search(code, a, b) for a, b in spans[1:]):
        return None
    verbs = _format_verbs(view, line_num, spans[0])
    return verbs if verbs is not None and len(verbs) == len(spans) - 1 else None


def _format_verbs(view: CodeView, line_num: int, span: tuple[int, int]) -> list[str] | None:
    """The verbs of the format at ``span`` when it is one literal, else None."""
    code = view.line(line_num)
    if _ONE_LITERAL.fullmatch(code, *span) is None:
        return None
    body = view.raw(line_num)[span[0]:span[1]].strip()
    if body.startswith('"') and _PERCENT_ESCAPE.search(body):
        return None
    return printf_verbs(body[1:-1])


def _constant_arg(view: CodeView, line_num: int, verb: str, arg: str) -> bool:
    if verb in _NUMERIC_VERBS or _ONE_LITERAL.fullmatch(arg):
        return True
    ident = _IDENT.fullmatch(arg)
    return ident is not None and _literal_built(view, line_num, ident.group(1))


def _result_stays_constant(view: CodeView, line_num: int, before: str) -> bool:
    """A name the result is assigned to is written nowhere else in its function
    except by literals (``q += " LIMIT 1"``): no taint is added after the call."""
    lhs = _ASSIGNED_NAME.search(before)
    if lhs is None:
        return True
    scope = _function_scope(view, line_num)
    kinds = None if scope is None else _kinds(view, scope, lhs.group(1), skip_line=line_num)
    return kinds is not None and "unsafe" not in kinds and "def" not in kinds


# ── literal-built identifiers ───────────────────────────────────────────────


def _literal_built(view: CodeView, line_num: int, name: str) -> bool:
    scope = _function_scope(view, line_num)
    if scope is None:
        return False
    key = ("go-literal-built", scope.start, name)
    if key not in view.memo:
        kinds = _kinds(view, scope, name)
        view.memo[key] = kinds is not None and kinds[:1] == ["def"] and _settled(kinds)
    return view.memo[key]


def _settled(kinds: list[str]) -> bool:
    return kinds.count("def") == 1 and "unsafe" not in kinds


def _function_scope(view: CodeView, line_num: int) -> range | None:
    """Lines of the top-level ``func`` holding ``line_num``, header to closing brace."""
    start = _func_start(view, line_num)
    if start is None:
        return None
    end = _body_end(view, start, min(len(view), line_num + _ROUTINE_LOOKBACK))
    return None if end is None or end < line_num else range(start, end + 1)


def _func_start(view: CodeView, line_num: int) -> int | None:
    """The nearest top-level ``func`` line at or above ``line_num``, within the lookback."""
    lowest = max(1, line_num - _ROUTINE_LOOKBACK)
    return next((n for n in range(line_num, lowest - 1, -1) if _TOP_FUNC.match(view.line(n))), None)


def _body_end(view: CodeView, start: int, last: int) -> int | None:
    """The line whose `}` closes the body opened at or after ``start``; None past ``last``."""
    depth, opened = 0, False
    for n in range(start, last + 1):
        code = view.line(n)[:MAX_SCAN_CHARS]
        depth += code.count("{") - code.count("}")
        opened = opened or "{" in code
        if opened and depth <= 0:
            return n
    return None


class _Name:
    """The patterns that find one name and the line-level shapes that make it unsafe."""

    __slots__ = ("name", "find", "address_taken")

    def __init__(self, name: str) -> None:
        word = re.escape(name)
        self.name = name
        self.find = re.compile(rf"(?<![\w.]){word}(?!\w)")
        self.address_taken = re.compile(rf"(?<!&)&[\s(]*{word}(?!\w)")    # `&x` / `&(x)`, not `&&`


# `x T`, `x *T`, `x []T`, `x ...T` after the name: a parameter, a field or a typed var.
_TYPED = re.compile(r"\s+(?:[A-Za-z_*\[(]|\.\.\.)")


def _kinds(view: CodeView, scope: range, name: str, skip_line: int | None = None) -> list[str] | None:
    """One kind per statement holding ``name`` in ``scope``, in order, stopping at
    the first ``unsafe`` or a second ``def``; None when such a line is too long."""
    target = _Name(name)
    lines = _holding_lines(view, scope, name, skip_line)
    kinds: list[str] = []
    for n in lines or ():
        kinds += _line_kinds(view, n, view.line(n), target)
        if _decided(kinds):
            return kinds
    return None if lines is None else kinds


def _holding_lines(view: CodeView, scope: range, name: str, skip_line: int | None) -> list[int] | None:
    """The lines of ``scope`` whose code holds ``name``; None when a line of the
    scope is too long to read whole (it could hide a write past the cut)."""
    if _too_long(view, scope):
        return None
    return [n for n in scope if n != skip_line and name in view.line(n)]


def _too_long(view: CodeView, scope: range) -> bool:
    return any(len(view.line(n)) > MAX_SCAN_CHARS for n in scope)


def _decided(kinds: list[str]) -> bool:
    """Nothing later can make the name literal-built."""
    return "unsafe" in kinds or kinds.count("def") > 1


def _line_kinds(view: CodeView, n: int, code: str, target: _Name) -> list[str]:
    if target.find.search(code) is None:
        return []
    if _FUNC_WORD.search(code) or target.address_taken.search(code):
        return ["unsafe"]
    return _statement_kinds(view, n, code, target)


def _statement_kinds(view: CodeView, n: int, code: str, target: _Name) -> list[str]:
    kinds = []
    for stmt in _STATEMENT.finditer(code):
        kind = _statement_kind(view, n, code, stmt.span(), target)
        if kind is not None:
            kinds.append(kind)
    return kinds


def _statement_kind(view: CodeView, n: int, code: str, span: tuple[int, int], target: _Name) -> str | None:
    """``def`` / ``write`` / ``read`` / ``unsafe`` for the name in one statement, or
    None when the statement does not hold it."""
    first = target.find.search(code, *span)
    if first is None:
        return None
    return _declared_kind(view, n, code, span, first) or _assigned_kind(view, n, code, span, first, target.name)


def _declared_kind(view: CodeView, n: int, code: str, span: tuple[int, int], first: re.Match[str]) -> str | None:
    """`var x ...` (a definition), or `x T` (a parameter or field: unsafe); else None."""
    var = _VAR.match(code, *span)
    if var is not None and var.span(1) == first.span():
        return "def" if _var_value_ok(view, n, code, first.end(), span[1]) else "unsafe"
    return "unsafe" if _TYPED.match(code, first.end(), span[1]) else None


def _assigned_kind(
    view: CodeView, n: int, code: str, span: tuple[int, int], first: re.Match[str], name: str,
) -> str:
    """The name on the left of the statement's assignment, a continued multi-name
    left-hand side (`x,` ending the statement), or a read."""
    op = _ASSIGN.search(code, *span)
    if op is not None and first.end() <= op.start():
        return _write_kind(view, n, code, span, op, name)
    return "unsafe" if op is None and code[span[0]:span[1]].rstrip().endswith(",") else "read"


def _write_kind(view: CodeView, n: int, code: str, span: tuple[int, int], op: re.Match[str], name: str) -> str:
    """The name alone on the left, LITS on the right, as the whole statement."""
    kind = _WRITE_KIND.get(op.group())
    lhs_alone = code[span[0]:op.start()].strip() == name
    self_ok = name if kind == "write" else None
    ok = kind is not None and lhs_alone and _literal_rhs(view, n, code, op.end(), span[1], self_ok)
    return kind if ok else "unsafe"


def _var_value_ok(view: CodeView, n: int, code: str, start: int, end: int) -> bool:
    """`var x string` (the empty string), or `var x [string] = LITS`."""
    if _VAR_ZERO.fullmatch(code, start, end):
        return True
    init = _VAR_INIT.match(code, start, end)
    return init is not None and _literal_rhs(view, n, code, init.end(), end, None)


def _literal_rhs(view: CodeView, n: int, code: str, start: int, end: int, self_name: str | None) -> bool:
    """Whether ``code[start:end]`` joins only literals, number-only ``fmt.Sprintf``
    calls and (in a write) the name itself with ``+`` -- the whole statement."""
    items = _plus_items(code, start, end)
    return all(_literal_item(view, n, code, a, b, self_name) for a, b in items)


def _plus_items(code: str, start: int, end: int) -> list[tuple[int, int]]:
    """Spans of ``code[start:end]`` split on `+` outside brackets."""
    items, left, depth = [], start, 0
    for m in _PLUS_OR_BRACKET.finditer(code, start, end):
        char = m.group()
        depth += (char in "([") - (char in ")]")
        if char == "+" and depth == 0:
            items.append((left, m.start()))
            left = m.end()
    items.append((left, end))
    return items


def _literal_item(view: CodeView, n: int, code: str, start: int, end: int, self_name: str | None) -> bool:
    text = code[start:end].strip()
    if _ONE_LITERAL.fullmatch(text) or (self_name is not None and text == self_name):
        return True
    return _numeric_sprintf(view, n, code, start, end)


def _numeric_sprintf(view: CodeView, n: int, code: str, start: int, end: int) -> bool:
    """``code[start:end]`` is exactly one ``fmt.Sprintf`` whose verbs all print numbers."""
    spans = _whole_call(code, start, end)
    verbs = None if spans is None else _paired_verbs(view, n, spans)
    return verbs is not None and set(verbs) <= _NUMERIC_VERBS


def _whole_call(code: str, start: int, end: int) -> list[tuple[int, int]] | None:
    """Argument spans of the ``fmt.Sprintf`` call that is all of ``code[start:end]``."""
    call = _SPRINTF.search(code, start, end)
    if call is None or code[start:call.start()].strip():
        return None
    spans = arg_spans(code, call.end() - 1)
    return None if spans is None or code[spans[-1][1] + 1:end].strip() else spans
