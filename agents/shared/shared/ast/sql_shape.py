"""SQL statement shape, read from source text (feature 0105, B5).

``sql_shape`` and ``select_from`` find a statement anywhere in a text: cwe's CWE-89 formatting
clauses ask it of a line and its neighbours. ``opens_statement`` asks whether a text opens with an
SQL statement, and ``opens_one_statement`` whether it opens with exactly one (no ``;``);
``statement_head`` gives a string literal's source as a statement would open it (prefix, opening
quotes and leading whitespace dropped), the reading the AST layer takes of a call's argument.

This module imports only ``re`` and ``bisect``: the isolated parse worker may load it (D2), so it
must not pull ``shared.tools`` or anything else of the parent's machinery into that process.
"""

from __future__ import annotations

import bisect
import re

__all__ = [
    "FROM",
    "SELECT",
    "SELECT_SPAN",
    "SQL_EDGE",
    "SQL_GAP",
    "SQL_STATEMENT",
    "STATEMENT_END",
    "opens_one_statement",
    "opens_statement",
    "select_from",
    "select_reaches_from",
    "sql_shape",
    "statement_head",
]

# SQL statement shape for the formatting clauses (f-string, `.format`, `%`, Sprintf),
# where the interpolation may BE the column list or the table (`SELECT {cols}
# FROM`, `UPDATE %s SET`). Read from source text, so a keyword may also sit next
# to a quote (`f"FROM {t}"`) or an escape (`"\nSELECT`, `*\tFROM`). SQL keywords,
# not English, widen a statement: `INSERT OR REPLACE INTO`, `INSERT IGNORE INTO`,
# an aliased `UPDATE users u SET`, a multi-table `DELETE t1 FROM t1 JOIN ...`, a
# `SELECT nextval(...)` with no FROM, a subquery `FROM(`.
SQL_EDGE = r"(?:(?<![A-Za-z0-9_$])|(?<=\\[nrt]))"
SQL_GAP = r"(?:\s|\\[nrt])"
SQL_STATEMENT = re.compile(
    SQL_EDGE + r"(?:INSERT(?:\s+(?:OR\s+\w{1,10}|IGNORE|LOW_PRIORITY|DELAYED|HIGH_PRIORITY))?"
    r"\s+INTO\s"
    r"|UPDATE\s+\S{1,60}(?:\s+(?:AS\s+)?\w{1,30})?\s+SET\s"
    r"|DELETE\s+FROM\s"
    r"|DELETE\s+\w{1,30}(?:\s*,\s*\w{1,30}){0,4}\s+FROM\s+\S{1,60}"
    r"\s+(?:JOIN|INNER|LEFT|RIGHT|CROSS|USING)\s"
    r"|SELECT\s+[\w.]{1,60}\s*\("
    r"|DROP\s+(?:TABLE|DATABASE)\s)",
    re.IGNORECASE,
)
SELECT = re.compile(SQL_EDGE + r"SELECT" + SQL_GAP, re.IGNORECASE)
FROM = re.compile(SQL_EDGE + r"FROM(?:\s|\\[nrt]|\()", re.IGNORECASE)
STATEMENT_END = re.compile(";")
# How far a FROM may follow its SELECT: a column list, not a paragraph.
SELECT_SPAN = 400


def sql_shape(text: str) -> bool:
    """SQL statement shape anywhere in ``text``."""
    return SQL_STATEMENT.search(text) is not None or select_from(text)


def select_from(text: str) -> bool:
    """A SELECT whose next FROM follows within ``SELECT_SPAN`` characters, in the
    same statement. Each SELECT is paired with the first FROM after it, so the
    test is linear however many of either the text holds."""
    froms = [m.start() for m in FROM.finditer(text)]
    ends = [m.start() for m in STATEMENT_END.finditer(text)]
    return any(
        select_reaches_from(sel.end(), froms, ends) for sel in SELECT.finditer(text)
    ) if froms else False


def select_reaches_from(at: int, froms: list[int], ends: list[int]) -> bool:
    nxt = bisect.bisect_left(froms, at)
    if nxt == len(froms) or froms[nxt] - at > SELECT_SPAN:
        return False
    end = bisect.bisect_left(ends, at)
    return end == len(ends) or ends[end] > froms[nxt]


# ── 0105: a statement at a literal's head ────────────────────────────────────

# A string prefix (`f`, `r`, `b`, `u8`, `R`) and its opening quotes.
_LEAD = re.compile(r"[A-Za-z0-9]{0,3}[\"'`]+")
# Leading whitespace, raw or escaped (`\n`, `\t`, `\r` as two characters).
_SPACE = re.compile(SQL_GAP + r"+")


def opens_statement(text: str) -> bool:
    """An SQL statement opens at offset 0 of ``text``: one of ``SQL_STATEMENT``'s branches, or
    the SELECT at offset 0 with its FROM in the same statement. A command line that carries a
    statement later (``psql -c '…'``, ``echo …``) opens none."""
    return SQL_STATEMENT.match(text) is not None or _opens_select(text)


def _opens_select(text: str) -> bool:
    """A SELECT at offset 0 whose FROM follows it (``select_reaches_from``)."""
    m = SELECT.match(text)
    return m is not None and _from_follows(text, m.end())


def _from_follows(text: str, at: int) -> bool:
    """``select_reaches_from(at)`` over the FROM and ``;`` offsets of ``text``."""
    froms = [f.start() for f in FROM.finditer(text)]
    ends = [e.start() for e in STATEMENT_END.finditer(text)]
    return select_reaches_from(at, froms, ends)


def opens_one_statement(head: str) -> bool:
    """``opens_statement`` with no ``;`` in ``head``: a chained second statement (or a chained
    command) is never one statement."""
    return opens_statement(head) and STATEMENT_END.search(head) is None


def statement_head(raw: str) -> str:
    """A literal's source as a statement would open it: its string prefix (at most three letters
    or digits) and opening quotes dropped, then leading whitespace and ``\\n`` / ``\\t`` /
    ``\\r`` escapes. A C++ raw string keeps its ``(`` delimiter, so it opens no statement."""
    lead = _LEAD.match(raw)
    rest = raw[lead.end():] if lead else raw
    space = _SPACE.match(rest)
    return rest[space.end():] if space else rest
