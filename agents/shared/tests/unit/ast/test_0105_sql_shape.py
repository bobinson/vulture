"""Feature 0105 (LLD §4.2, §5.3): ``shared.ast.sql_shape``, the SQL-shape predicate moved out of
cwe's ``injection_check`` so the flow pass can read it, and the three readers 0105 adds.

* ``opens_statement(text)``: an SQL statement opens at offset 0: one of ``SQL_STATEMENT``'s
  branches, or a SELECT whose FROM follows it in the same statement. A command line that
  carries a statement later (``psql -c '…'``, ``echo …``) opens none.
* ``opens_one_statement(head)``: ``opens_statement`` and no ``;`` in the head, so a chained
  second statement (or a chained command) is never statement text.
* ``statement_head(raw)``: a literal's source with its string prefix (at most three letters or
  digits) and opening quotes dropped, then leading whitespace and ``\\n`` / ``\\t`` / ``\\r``
  escapes. A C++ raw string keeps its ``(`` delimiter, so it opens no statement (named).
* ``sql_shape`` and ``select_from`` keep their "anywhere" semantics: a line of cwe's own
  CWE-89 units (the construct-precision ``sql_`` units), where the statement is not at offset 0.

Every name is imported in the test body: the module does not exist until P1, and a
module-level import would interrupt the whole session instead of failing these tests.
"""

from __future__ import annotations

import pytest

DELETE = "DELETE FROM t WHERE id = "

# opens_statement: each SQL_STATEMENT branch and an offset-0 SELECT … FROM open a statement.
OPENS = [
    pytest.param("INSERT INTO t VALUES (", True, id="insert"),
    pytest.param("UPDATE t SET a = ", True, id="update"),
    pytest.param(DELETE, True, id="delete"),
    pytest.param("DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id WHERE ", True, id="delete-join"),
    pytest.param("SELECT nextval(", True, id="select-call"),
    pytest.param("DROP TABLE ", True, id="drop-table"),
    pytest.param("DROP DATABASE ", True, id="drop-database"),
    pytest.param("SELECT a FROM t WHERE b = ", True, id="select-from"),
    pytest.param("psql -c 'DELETE FROM t'", False, id="psql"),
    pytest.param("echo DELETE FROM t", False, id="echo"),
    pytest.param("update-alternatives --set x", False, id="update-alternatives"),
    pytest.param("", False, id="empty"),
    pytest.param("a SELECT b FROM c", False, id="select-later"),
]

# opens_one_statement: a ``;`` in the head is a second statement or a chained command.
ONE_STATEMENT = [
    pytest.param("DELETE FROM t; DROP TABLE u", False, id="chained"),
    pytest.param(DELETE, True, id="single"),
]

# statement_head: a literal's source as the flow pass reads it -> the text a statement opens at.
# The Go raw string holds a real newline and tabs; the Go interpreted string holds the
# two-character escapes ``\n`` and ``\t``.
HEADS = [
    pytest.param('f"DELETE FROM t WHERE id = {x}"', 'DELETE FROM t WHERE id = {x}"', id="f"),
    pytest.param("`\n\t\tDELETE FROM t WHERE id = `", "DELETE FROM t WHERE id = `", id="raw-go"),
    pytest.param('"\\n\\tDELETE FROM t WHERE id = "', 'DELETE FROM t WHERE id = "', id="escaped"),
    pytest.param('R"(DELETE FROM t WHERE id = )"', '(DELETE FROM t WHERE id = )"', id="raw-cpp"),
    pytest.param('u8"DELETE FROM t WHERE id = "', 'DELETE FROM t WHERE id = "', id="u8"),
]
RAW_CPP = 'R"(DELETE FROM t WHERE id = )"'

# A line of the construct-precision unit ``sql_py_fstring_shape_no_sink`` (its marker dropped):
# a DELETE FROM after an assignment.
SHAPE_LINE = '    query = f"DELETE FROM t WHERE id = {i}"'
# A line of the unit ``sql_py_fstring_execute``: a SELECT … FROM inside a call's argument.
SELECT_LINE = "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"


@pytest.mark.parametrize(("text", "opens"), OPENS)
def test_opens_statement(text: str, opens: bool) -> None:
    from shared.ast.sql_shape import opens_statement

    assert opens_statement(text) is opens


@pytest.mark.parametrize(("head", "one"), ONE_STATEMENT)
def test_opens_one_statement(head: str, one: bool) -> None:
    from shared.ast.sql_shape import opens_one_statement

    assert opens_one_statement(head) is one


@pytest.mark.parametrize(("raw", "head"), HEADS)
def test_statement_head(raw: str, head: str) -> None:
    from shared.ast.sql_shape import statement_head

    assert statement_head(raw) == head


def test_a_raw_string_delimiter_opens_no_statement() -> None:
    """Named: a C++ raw string's ``(`` stays in the head, so it is never statement text."""
    from shared.ast.sql_shape import opens_one_statement, statement_head

    assert opens_one_statement(statement_head(RAW_CPP)) is False


def test_sql_shape_matches_anywhere() -> None:
    from shared.ast.sql_shape import opens_statement, sql_shape

    assert (sql_shape(SHAPE_LINE), opens_statement(SHAPE_LINE)) == (True, False)


def test_select_from_matches_anywhere() -> None:
    from shared.ast.sql_shape import opens_statement, select_from

    assert (select_from(SELECT_LINE), opens_statement(SELECT_LINE)) == (True, False)
