"""Which AST CWE-89 row a regex CWE-89 row covers, and the line numbering the cwe heads compare
(feature 0105, LLD §4.6).

**The cover rule: hop lines count for a hoisted statement only.**
``injection_check._statement_rows`` emits an AST CWE-89 row at
each statement sink the line loop read, unless a regex CWE-89 row covers its flow: a regex row
on a line of the sink's span always covers it; a regex row on a hop line of its flow covers it
only when the statement is hoisted, that is when the sink's own span lines carry no statement
text (a literal there whose head opens one). A statement built at the sink is decided by its
span lines alone, so a distinct request-fed sink whose flow passes an earlier regex-flagged
query keeps its row (the programs ``a1``, ``b1``, ``q1``, ``q2``, ``q4`` and ``p2``), while a
hoisted statement keeps exactly one row (the two hoisted E2E units and the hoisted-hop
programs LLD §4.6 cites). ``q5`` and ``h1``, whose regex row is on no hop line of the
sink's flow, are controls.

**A residual, pinned as built (feature 0105, LLD §3.4).** A statement sink whose own text
opens no statement at a literal's head (a comment before the verb, ``"/* app */ DELETE …"``;
``"CREATE TABLE "``, no statement branch) reads as hoisted, so a regex CWE-89 row on a hop line
covers it. In the two programs that line builds ``q`` from the request with a formatter, and
its regex row reports that same request value: the injection is reported once, at ``q``'s
line, and the sink's line has no row (the base gave it a CWE-78 row). These pins pass as
built; a change that gives the sink a row of its own changes them on purpose.

**The sink line and the argument's lines, not the whole call.** A statement sink's
span is its whole call: a callback body and later keyword arguments are inside it. Its cover
lines, and the lines its statement text is read from, are its sink line plus the lines of its
argument (``Flow.arg_span``, counted by ``"\\n"`` in the buffer the worker parsed). So a regex
CWE-89 row for another statement inside the call no longer covers the outer request-fed sink
(``inner_regex``, ``inner_query``, ``inner_hoisted``, ``inner_py``), and a literal statement in a
callback or a later argument no longer reads as built at the sink and gives a hoisted
statement a second row (``cb``, ``multi_arg``); the same two shapes over a UTF-8 buffer pin the
byte count. The rule is line-granular: another statement on the sink line or an argument line
still counts (pinned as built).

**Every flow reported at the sink.** A statement sink with several request-fed sink
arguments (under a ``system`` key, after an interpreter and flag) has one flow per argument,
and ``_by_line`` keeps one of them for the line's row. The head's answer records every flow it
reports (``AstAnswer.reported``; none for an answer built without them, which reads the kept
flow alone), and the cover test reads a sink over all its flows: its cover lines are its sink
line and every flow's argument lines, plus every flow's hops when, read once over those lines,
the statement is hoisted. So a regex CWE-89 row on the statement's line, or on its hoisted
Def, covers the sink whichever flow is kept (``anyflow/*_first``, ``sys_hoisted``: no second
row); a statement built at the sink keeps its row although another argument hops onto an
earlier regex-flagged query (``b1_multi``, a row read per flow would lose); the statement second
or a CWE-78 sink are controls. Head-level pins: both flows recorded (a hint-only one too), none
by default, each accepted flow decided once (A30).

**The sink's program argument.** A statement built in the sink's program argument
(the argument the classifier reads statement text from) may have no reported flow: its value
is shell-quoted or guarded, so its flow is declined, or it is built from a module constant and
is no candidate. Read over the reported flows' argument lines alone, such a sink read as
hoisted, so another argument's hop (``row.owner``, onto an earlier regex-flagged SELECT)
covered it (``b1_quoted``, ``b1_guarded``, ``b1_local``: no row), or, meeting no hop, it got a
second row beside the regex row on the statement's line (``guarded_fstr``, ``quoted_fstr``).
Every command flow now carries its sink's program-argument span (``Flow.program_span``), and
a sink's lines are its sink line, its program argument's lines and every reported flow's
argument lines; cells of the measured cross product (constant-built, shell-quoted, guarded;
one-line and multi-line; one sink or two on the line; JS and Python, concatenation and
template) pin the same. The one-line form and a pure literal statement are controls. With
none recorded the kept flow gives its program argument's lines too, so the kept-flow-alone pin
moves on purpose.

**One group per sink.** Two statement sinks on one line used to be read as one:
the flows of the line's other sink met the cover test, so its hop onto a regex-flagged query
covered a request-fed statement sink (``same_line``; the hoisted two-sink cells). The flows a
sink is read over are now those at its own call (``Flow.sink``); line ownership still keeps
one flow per line. The order swapped, and the two sinks on separate lines, are controls.

**A residual.** A hoisted concatenated statement (``stmt = "DELETE …'" + o + "'"``,
then ``h.system(stmt, row.owner)``) after a regex-flagged request-built SELECT reads as hoisted,
rightly, so ``row.owner``'s hop meets the SELECT's regex row, and no regex row stands on the
concatenated Def: the DELETE has no row (the base had a CWE-78 row). Pinned as built, JS and
Python, one-line and multi-line, one sink and two.

**Hoisting read once, the statement outside the program argument.** A statement built at a
store sink after an interpreter and flag (``db.exec("sh", "-c", stmt, opts)``) or second under
a ``system`` key (``db.system(opts, stmt)``) is on its own flow's argument line only, and the
other flow's Def (``opts``) shares a line with a regex-flagged request-built SELECT. Read once
for the sink the statement's line decides and the sink keeps its AST CWE-89 row
(``persink/``); read for each flow alone, ``opts``'s hop would cover it.

**Three more residuals, pinned as built (feature 0105, LLD §3.4).** Line ownership: a
multi-line statement sink whose flows are all hint-only (``file_path``) and which opens on the
line of an earlier store sink (``conn.exec(row.owner); h.system(``) has no line of its own; that
sink's ``row.owner`` hop meets the SELECT's regex row, so neither has a row (``lineown/``; the
base had a CWE-78 row; the JS form, whose statement flow is not hint-only, is the control). A
multi-line program argument that no reported flow reads and that nests another statement a
regex CWE-89 row flags (a callback's, a ``note(f"SELECT …")`` call's): its lines are the sink's,
so that row covers the sink (``nested/``; the base had a CWE-78 row). A store sink whose
statement is not at the program position and that no reported flow reads (shell-quoted after an
interpreter and flag; constant-built, second under a ``system`` key): no line it is read on
carries the statement, so it reads as hoisted and ``row.owner``'s hop covers it (``noprog/``;
the base was silent).

**The two numberings.** The skills' line loop numbers lines by ``str.splitlines()``
(it also breaks at ``\\f``, ``\\v``, ``\\x1c``-``\\x1e``, ``\\x85``, U+2028, U+2029); the AST
model by ``"\\n"`` alone (D21), and its rows keep that numbering. Every place the two meet
translates: the cover test reads each regex row's line as the model's before it meets the
flow's lines, and the head (``_ast_head.claim``, ``unread_sinks``) asks about the model's line
of the loop's line. A model line the loop splits is owned on each of its loop lines, emits its
row once, and is read when any of its loop lines is. So a form feed or a U+2028 above a sink
neither loses its row nor lets an unrelated regex row cover it, and a hoisted statement below
one is still reported once. The CWE-22 head's children (``input_validation_check``) read the
loop lines of each span line too, so a child that replaces a span still replaces it there. A
file with no such character is the control.

**A forged answer D3' admits.** D3' bounds a flow's ``arg_span`` and ``span`` by the shipped bytes
and its ``sink_line`` by the lines, not one by another, so a worker's answer may carry an argument
span over the whole buffer, or the last sink line with a whole-buffer span, and since the
program-argument cover a program-argument span over the whole buffer (admitted: the pin checks D3'
let it through). The lines read for such a sink stay inside the file, so the skill completes and the
rows of every other file stand (a raise lost every row of the skill).

RED until the round lands: the defect rows fail for the reason each names, the controls pass.
"""

from __future__ import annotations

import contextvars
import dataclasses
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills._ast_head import AstAnswer, ast_answers, claim, unread_sinks
from cwe_agent.skills.injection_check import (
    _RULE_78,
    _RULE_89,
    _regex_covered,
    _scanned,
    check_injection,
)
from cwe_agent.skills.input_validation_check import check_input_validation
from shared.ast import context
from shared.ast.flow import hint_only
from shared.tools.file_scanner import read_file_lines
from tests import _ast_heads
from tests._ast_heads import COMMAND_ID, PATH_ID
from tests._neutral import neutral_dir
from tests.unit.test_0105_ast_head import _asked

SQL_ID = "cwe.injection.sql"
ABSOLUTE_ID = "cwe.input_validation.absolute_path_traversal"
# The short name a row's check id is written with below.
SHORT = {SQL_ID: "89", COMMAND_ID: "78", PATH_ID: "22", ABSOLUTE_ID: "36"}

# The E2E units whose statement is hoisted into a variable (frozen; copied, never edited).
HOISTED_UNITS = Path(__file__).resolve().parents[1] / "e2e/fixtures/statement_relabel/pos"

# file -> source. The cover rule: programs whose statement sink follows a regex-flagged query,
# their controls and the hoisted-hop programs. The numberings: a form feed (``\f``), a vertical
# tab (``\v``) or a U+2028 the loop breaks at and the model does not, and the same files
# without one.
PROGRAMS: dict[str, str] = {
    "cover/a1.js": (
        "function wipe(req, db, store) {\n"
        "  const id = req.body.id; db.query(`SELECT * FROM t WHERE id = ${id}`);\n"
        '  store.exec("DELETE FROM t WHERE id = " + id);\n'
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "cover/b1.js": (
        "async function wipe(req, db, store) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  store.exec(\"DELETE FROM u WHERE owner = '\" + row.owner + \"'\");\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "cover/q1.js": (
        "async function show(req, res, db, store) {\n"
        "  const id = req.params.id;\n"
        "  const rows = await db.query(`SELECT * FROM t WHERE id = ${id}`);\n"
        '  await store.exec("UPDATE t SET seen = 1 WHERE id = " + rows[0].id);\n'
        "  res.json(rows);\n"
        "}\n"
        "module.exports = { show };\n"
    ),
    "cover/q2.js": (
        "async function find(req, res, db, store) {\n"
        "  const sql = `SELECT * FROM t WHERE name = '${req.query.name}'`;\n"
        "  const rows = await db.query(sql);\n"
        "  await store.exec(\"INSERT INTO audit(q) VALUES ('\" + sql + \"')\");\n"
        "  res.json(rows);\n"
        "}\n"
        "module.exports = { find };\n"
    ),
    "cover/q4.go": (
        "package main\n"
        "\n"
        "import (\n"
        '\t"database/sql"\n'
        '\t"fmt"\n'
        '\t"net/http"\n'
        ")\n"
        "\n"
        "func purge(w http.ResponseWriter, r *http.Request, db *sql.DB, store Store) {\n"
        '\tq := fmt.Sprintf("SELECT owner FROM t WHERE id = %s", r.FormValue("id"))\n'
        "\tdb.Query(q)\n"
        "\tstore.Exec(\"INSERT INTO audit(q) VALUES('\" + q + \"')\")\n"
        "}\n"
    ),
    "cover/p2.js": (
        "async function bump(req, db) {\n"
        "  const name = req.query.name;\n"
        "  const user = await db.query(`SELECT * FROM users WHERE name = '${name}'`);\n"
        '  await db.exec("UPDATE logins SET n = n + 1 WHERE uid = " + user.id);\n'
        "}\n"
        "module.exports = { bump };\n"
    ),
    "cover/q5.js": (
        "async function show(req, res, db, store) {\n"
        "  const rows = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        '  await store.exec("UPDATE t SET seen = 1 WHERE id = " + req.params.id);\n'
        "  res.json(rows);\n"
        "}\n"
        "module.exports = { show };\n"
    ),
    "cover/h1.js": (
        "async function wipe(req, db, store) {\n"
        "  const where = `id = ${req.params.id}`;\n"
        "  const rows = await db.query(`SELECT * FROM t WHERE ${where}`);\n"
        '  store.exec("DELETE FROM u WHERE " + where);\n'
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "hoisted/js_hoist.js": (
        "function f(req, store) {\n"
        "  const id = req.body.id;\n"
        "  const q = `DELETE FROM t WHERE id = ${id}`;\n"
        "  store.exec(q);\n"
        "}\n"
    ),
    "hoisted/py_hoist.py": (
        "from flask import request\n"
        "def f(store):\n"
        '    i = request.args["id"]\n'
        '    q = f"DELETE FROM t WHERE id = {i}"\n'
        "    store.exec(q)\n"
    ),
    "hoisted/js_hoist_param.js": (
        "function f(h, id) {\n"
        '  const q = "DELETE FROM t WHERE id = " + id;\n'
        "  h.exec(q);\n"
        "}\n"
    ),
    "hoisted/go_hoist.go": (
        "package m\n"
        'import "net/http"\n'
        "func f(h X, r *http.Request) {\n"
        '\tq := "DELETE FROM t WHERE id = " + r.FormValue("id")\n'
        "\th.Exec(q)\n"
        "}\n"
    ),
    "numbering/ff.py": (
        "from flask import request\n"
        "\f\n"
        "def wipe(store, cursor):\n"
        '    i = request.args["id"]\n'
        '    cursor.execute(f"SELECT * FROM a WHERE id = {i}")\n'
        '    store.exec("DELETE FROM b WHERE id = " + i)\n'
    ),
    "numbering/u2028.py": (
        "from flask import request\n"
        "# see spec section 2\n"
        "def wipe(store, cursor):\n"
        '    i = request.args["id"]\n'
        '    cursor.execute(f"SELECT * FROM a WHERE id = {i}")\n'
        '    store.exec("DELETE FROM b WHERE id = " + i)\n'
    ),
    "numbering/ff_ctl.py": (
        "from flask import request\n"
        "\n"
        "def wipe(store, cursor):\n"
        '    i = request.args["id"]\n'
        '    cursor.execute(f"SELECT * FROM a WHERE id = {i}")\n'
        '    store.exec("DELETE FROM b WHERE id = " + i)\n'
    ),
    "numbering/c3.py": (
        "from flask import request\n"
        "\f\n"
        "\f\n"
        "\n"
        "def wipe(store):\n"
        "    q = f\"DELETE FROM t WHERE id = {request.args['id']}\"\n"
        "    store.exec(q)\n"
    ),
    "numbering/pre2.py": (
        "import subprocess\n"
        "from flask import request\n"
        "\f\n"
        "def f():\n"
        '    c = request.args["c"]\n'
        "    # run it\n"
        "    subprocess.call(c, shell=True)\n"
    ),
    "numbering/pre2_ctl.py": (
        "import subprocess\n"
        "from flask import request\n"
        "\n"
        "def f():\n"
        '    c = request.args["c"]\n'
        "    # run it\n"
        "    subprocess.call(c, shell=True)\n"
    ),
    # A command sink after a comment on its own model line: the loop's first piece of the line
    # is the comment, which it never reads.
    "numbering/first_unread.js": (
        'const cp = require("child_process");\n'
        "function run(req) {\n"
        "  // run it   cp.exec(req.query.c);\n"
        "}\n"
        "module.exports = { run };\n"
    ),
    "numbering/first_unread_sql.js": (
        "function wipe(req, store) {\n"
        '  // purge   store.exec("DELETE FROM t WHERE id = " + req.body.id);\n'
        "}\n"
        "module.exports = { wipe };\n"
    ),
    # A sink on a model line the loop splits into two lines it reads.
    "numbering/split.js": (
        'const cp = require("child_process");\n'
        "function run(req) {\n"
        "  const c = req.query.c;\v  cp.exec(c);\n"
        "}\n"
        "module.exports = { run };\n"
    ),
    # A CWE-22 sink whose last span line a child (CWE-36) claims: the child's row replaces it.
    "numbering/child_ff.py": (
        "import os\n"
        "from flask import request\n"
        "\f\n"
        "def read(base):\n"
        "    return open(\n"
        '        os.path.join(base, request.args["f"].replace("../", "")))\n'
    ),
    "numbering/child_ff2.py": (
        "import os\n"
        "from flask import request\n"
        "\f\n"
        "\f\n"
        "def read(base):\n"
        "    return open(\n"
        '        os.path.join(base, request.args["f"].replace("../", "")))\n'
    ),
    "numbering/child_ctl.py": (
        "import os\n"
        "from flask import request\n"
        "\n"
        "def read(base):\n"
        "    return open(\n"
        '        os.path.join(base, request.args["f"].replace("../", "")))\n'
    ),
    # The residual: a statement sink whose text opens no statement at a literal's head, fed by
    # a request-fed ``SELECT`` on the line above.
    "residual/t5_typed.go": (
        "package m\n"
        "\n"
        "import (\n"
        '\t"database/sql"\n'
        '\t"fmt"\n'
        '\t"net/http"\n'
        ")\n"
        "\n"
        "func wipe(h *sql.DB, r *http.Request) {\n"
        '\tq := fmt.Sprintf("SELECT owner FROM t WHERE id = %s", r.FormValue("id"))\n'
        '\th.Exec("/* app */ DELETE FROM u WHERE owner IN (" + q + ")")\n'
        "}\n"
    ),
    "residual/t8_typed.go": (
        "package m\n"
        "\n"
        "import (\n"
        '\t"database/sql"\n'
        '\t"fmt"\n'
        '\t"net/http"\n'
        ")\n"
        "\n"
        "func mk(h *sql.DB, r *http.Request) {\n"
        '\tq := fmt.Sprintf("SELECT name FROM t WHERE id = %s", r.FormValue("id"))\n'
        '\th.Exec("CREATE TABLE " + q + " (id int)")\n'
        "}\n"
    ),
    # The argument-line cover: a statement sink whose call holds another statement in a callback or
    # a later argument, on lines that are neither its sink line nor its argument's.
    "argspan/inner_regex.js": (
        "function wipe(req, store, log) {\n"
        '  store.exec("DELETE FROM t WHERE id = " + req.body.id, function (err) {\n'
        "    const s = `SELECT * FROM log WHERE id = ${req.query.x}`;\n"
        "    log(s);\n"
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/inner_query.js": (
        "function wipe(req, store, db) {\n"
        '  store.exec("DELETE FROM t WHERE id = " + req.body.id, function (err) {\n'
        "    db.query(`SELECT * FROM log WHERE id = ${req.query.x}`);\n"
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/inner_hoisted.js": (
        "function wipe(req, store, db) {\n"
        '  const q = "DELETE FROM t WHERE id = " + req.body.id;\n'
        "  store.exec(q, function (err) {\n"
        "    db.query(`SELECT * FROM log WHERE id = ${req.query.x}`);\n"
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/inner_py.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store, cursor):\n"
        "    store.exec(\n"
        '        "DELETE FROM t WHERE id = " + request.args["id"],\n'
        "        note=f\"SELECT * FROM log WHERE id = {request.args['x']}\",\n"
        "    )\n"
    ),
    "argspan/cb.js": (
        "function wipe(req, db) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.params.id}`;\n"
        "  db.exec(q, function (err) {\n"
        "    if (err) return;\n"
        '    db.exec("UPDATE log SET n = n + 1 WHERE k = 1");\n'
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/multi_arg.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store):\n"
        "    q = f\"DELETE FROM t WHERE id = {request.args['id']}\"\n"
        "    store.exec(\n"
        "        q,\n"
        '        log="DELETE FROM t issued",\n'
        "    )\n"
    ),
    "argspan/inner_ctl.js": (
        "function wipe(req, store, log) {\n"
        '  store.exec("DELETE FROM t WHERE id = " + req.body.id, function (err) {\n'
        '    log("done");\n'
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/cb_ctl.js": (
        "function wipe(req, db) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.params.id}`;\n"
        "  db.exec(q, function (err) {\n"
        "    if (err) return;\n"
        "    db.exec(stmt);\n"
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/cb_store.js": (
        "function wipe(req, store) {\n"
        '  const q = "DELETE FROM t WHERE id = " + req.params.id;\n'
        "  store.exec(q, (err) => {\n"
        '    console.log("DELETE FROM t done");\n'
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/cb_store_ctl.js": (
        "function wipe(req, store) {\n"
        '  const q = "DELETE FROM t WHERE id = " + req.params.id;\n'
        "  store.exec(q, (err) => {\n"
        '    console.log("done");\n'
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/multi_arg_ctl.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store):\n"
        "    q = f\"DELETE FROM t WHERE id = {request.args['id']}\"\n"
        "    store.exec(\n"
        "        q,\n"
        '        log="issued",\n'
        "    )\n"
    ),
    # The same, with multibyte text above and inside the call: the argument's lines are counted
    # in the UTF-8 bytes the worker parsed.
    "argspan/inner_py_utf8.py": (
        "from flask import request\n"
        "# café, naïve, 日本語: multibyte text above the call\n"
        "def wipe(store, cursor):\n"
        "    store.exec(  # 日本語 ünï\n"
        '        "DELETE FROM t WHERE id = " + request.args["id"],\n'
        "        note=f\"SELECT * FROM log WHERE id = {request.args['x']}\",  # éé\n"
        "    )\n"
    ),
    "argspan/cb_utf8.js": (
        "function wipe(req, db) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.params.id}`; // café 日本語\n"
        "  db.exec(q, function (err) { // ünïçødé\n"
        "    if (err) return;\n"
        '    db.exec("UPDATE log SET n = n + 1 WHERE k = 1");\n'
        "  });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    # The line-granular residual: another statement ON the sink line or an argument line.
    "argspan/cb_sameline.js": (
        "function wipe(req, db) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.params.id}`;\n"
        '  db.exec(q, function (err) { db.exec("UPDATE log SET n = n + 1 WHERE k = 1"); });\n'
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/kw_argline.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store):\n"
        "    q = f\"DELETE FROM t WHERE id = {request.args['id']}\"\n"
        "    store.exec(\n"
        '        q, log="DELETE FROM t issued",\n'
        "    )\n"
    ),
    "argspan/inner_sameline.js": (
        "function wipe(req, store, db) {\n"
        '  store.exec("DELETE FROM t WHERE id = " + req.body.id, function (err) {'
        " db.query(`SELECT * FROM log WHERE id = ${req.query.x}`); });\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "argspan/inner_argline.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store, cursor):\n"
        "    store.exec(\n"
        '        "DELETE FROM t WHERE id = " + request.args["id"],'
        " note=f\"SELECT * FROM log WHERE id = {request.args['x']}\",\n"
        "    )\n"
    ),
    # The every-flow cover: a statement sink with two request-fed sink arguments (under a ``system``
    # key, or after an interpreter and flag), so two flows at one sink line, of which ``_by_line``
    # keeps the later. The statement first, built at the sink or hoisted into ``q``:
    "anyflow/db_sh_c.js": (
        "function wipe(req, db) {\n"
        "  db.exec(\n"
        '    "sh", "-c",\n'
        "    `DELETE FROM t WHERE id = ${req.body.id}`,\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/db_sh_c.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(db):\n"
        "    db.exec(\n"
        '        "sh", "-c",\n'
        "        f\"DELETE FROM t WHERE id = {request.args['id']}\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "anyflow/db_sys_first.js": (
        "function wipe(req, db) {\n"
        "  db.system(\n"
        "    `DELETE FROM t WHERE id = ${req.body.id}`,\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/db_sys_first.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(db):\n"
        "    db.system(\n"
        "        f\"DELETE FROM t WHERE id = {request.args['id']}\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "anyflow/sys_stmt_first.js": (
        "function wipe(req, h) {\n"
        "  h.system(\n"
        "    `DELETE FROM t WHERE id = ${req.body.id}`,\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/sys_stmt_first.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        "    h.system(\n"
        "        f\"DELETE FROM t WHERE id = {request.args['id']}\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "anyflow/sys_hoisted.js": (
        "function wipe(req, h) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.body.id}`;\n"
        "  h.system(\n"
        "    q,\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/sys_hoisted.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        "    q = f\"DELETE FROM t WHERE id = {request.args['id']}\"\n"
        "    h.system(\n"
        "        q,\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    # The statement second, or a CWE-78 sink (a process receiver): controls.
    "anyflow/db_sys_second.js": (
        "function wipe(req, db) {\n"
        "  db.system(\n"
        "    req.query.opts,\n"
        "    `DELETE FROM t WHERE id = ${req.body.id}`\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/sys_hoisted_second.js": (
        "function wipe(req, h) {\n"
        "  const q = `DELETE FROM t WHERE id = ${req.body.id}`;\n"
        "  h.system(\n"
        "    req.query.opts,\n"
        "    q\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/sys_stmt_second.js": (
        "function wipe(req, h) {\n"
        "  h.system(\n"
        "    req.query.opts,\n"
        "    `DELETE FROM t WHERE id = ${req.body.id}`\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "anyflow/sys_stmt_second.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        "    h.system(\n"
        '        request.args["opts"],\n'
        "        f\"DELETE FROM t WHERE id = {request.args['id']}\",\n"
        "    )\n"
    ),
    # A statement built at a two-flow sink whose other argument (``row.owner``) hops onto an
    # earlier request-fed query a regex CWE-89 row flags.
    "anyflow/b1_multi.js": (
        "async function f(req, db, h) {\n"
        "  const o = req.body.o;\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "anyflow/b1_multi.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h):\n"
        '    o = request.form["o"]\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    # Two flows at one sink: a hint-only one (``file_path``) beside a request-fed one; a
    # shell-quoted (declined) one beside a request-fed one.
    "anyflow/hint_and_request.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h, file_path):\n"
        "    h.system(\n"
        "        \"DELETE FROM t WHERE p = '\" + file_path + \"'\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "anyflow/quoted_and_request.py": (
        "import shlex\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        "    h.system(\n"
        '        "DELETE FROM t WHERE id = " + shlex.quote(request.args["id"]),\n'
        '        request.args["opts"],\n'
        "    )\n"
    ),
    # The program-argument cover: a statement built in the sink's program argument, which no
    # reported flow reads (a shell-quoted or guarded value, a module constant), beside another
    # argument (``row.owner``) that hops onto an earlier regex-flagged SELECT; an f-string statement
    # whose own flow is declined, beside a request-fed ``opts``. Controls: the one-line form, a pure
    # literal statement.
    "progarg/b1_quoted.py": (
        "import shlex\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h):\n"
        '    o = shlex.quote(request.form["o"])\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "progarg/b1_guarded.py": (
        "from flask import abort, request\n"
        "\n"
        "\n"
        "def f(db, h):\n"
        '    o = request.form["o"]\n'
        "    if not o.isalnum():\n"
        "        abort(400)\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "progarg/b1_local.js": (
        'const OWNER = "x";\n'
        "async function f(req, db, h) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "progarg/b1_local.py": (
        "from flask import request\n"
        "\n"
        'OWNER = "x"\n'
        "\n"
        "\n"
        "def f(db, h):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "progarg/guarded_fstr.py": (
        "from flask import abort, request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        '    i = request.args["id"]\n'
        "    if not i.isdigit():\n"
        "        abort(400)\n"
        "    h.system(\n"
        '        f"DELETE FROM t WHERE id = {i}",\n'
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "progarg/quoted_fstr.py": (
        "import shlex\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        "    h.system(\n"
        "        f\"DELETE FROM t WHERE id = {shlex.quote(request.args['id'])}\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "progarg/b1_local_ctl.js": (
        'const OWNER = "x";\n'
        "async function f(req, db, h) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\"DELETE FROM u WHERE owner = '\" + OWNER + \"'\", row.owner);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "progarg/b1_const.js": (
        "async function f(req, db, h) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = 'x'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "progarg/b1_const.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = 'x'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "progarg/b1_const_ctl.js": (
        "async function f(req, db, h) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\"DELETE FROM u WHERE owner = 'x'\", row.owner);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    # The per-sink grouping: two statement sinks on one line after a regex-flagged SELECT, one fed
    # by its result (``row.owner``), one by the request. Controls: the order swapped, the two sinks
    # on separate lines.
    "bysink/same_line.js": (
        "async function f(req, conn, db) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  conn.exec(row.owner); conn.exec(req.body.sql);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "bysink/same_line.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(conn, db):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        '    conn.exec(row.owner); conn.exec(request.form["sql"])\n'
    ),
    "bysink/same_line_swapped.js": (
        "async function f(req, conn, db) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  conn.exec(req.body.sql); conn.exec(row.owner);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "bysink/two_lines.js": (
        "async function f(req, conn, db) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  conn.exec(row.owner);\n"
        "  conn.exec(req.body.sql);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "bysink/two_lines.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(conn, db):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    conn.exec(row.owner)\n"
        '    conn.exec(request.form["sql"])\n'
    ),
    # The program-argument cover and the per-sink grouping over the measured cross product: the
    # statement constant-built, shell-quoted, guarded, a pure literal or hoisted; one-line or
    # multi-line; one sink or two on the line (``conn.exec(row.owner); h.system(…)``);
    # ``js_t``/``py_t`` the template and f-string forms.
    "cells/js/constbuilt_row_multi_one.js": (
        'const OWNER = "x";\n'
        "async function f(req, db, h, conn) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/py/constbuilt_request_multi_two.py": (
        "from flask import request\n"
        "\n"
        'OWNER = "x"\n'
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    conn.exec(row.owner); h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "cells/py/quoted_row_multi_one.py": (
        "import shlex\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = shlex.quote(request.form["o"])\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "cells/js/quoted_request_multi_two.js": (
        'const shellEscape = require("shell-escape");\n'
        "async function f(req, db, h, conn) {\n"
        "  const o = shellEscape([req.body.o]);\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  conn.exec(row.owner); h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/js/guarded_row_multi_one.js": (
        "async function f(req, db, h, conn) {\n"
        "  const o = req.body.o;\n"
        "  if (!/^[a-z0-9]+$/.test(o)) return;\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/py/guarded_row_multi_two.py": (
        "from flask import abort, request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = request.form["o"]\n'
        "    if not o.isalnum():\n"
        "        abort(400)\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    conn.exec(row.owner); h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "        row.owner,\n"
        "    )\n"
    ),
    "cells/js/hoisted_none_one_two.js": (
        "async function f(req, db, h, conn) {\n"
        "  const o = req.body.o;\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  const stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\";\n"
        "  conn.exec(row.owner); h.system(stmt);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/py/hoisted_request_one_two.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = request.form["o"]\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\"\n"
        '    conn.exec(row.owner); h.system(stmt, request.args["opts"])\n'
    ),
    "cells/js_t/const_row_multi_one.js": (
        "async function f(req, db, h, conn) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  h.system(\n"
        "    `DELETE FROM u WHERE owner = 'x'`,\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/js_t/quoted_request_multi_one.js": (
        'const shellEscape = require("shell-escape");\n'
        "async function f(req, db, h, conn) {\n"
        "  const o = shellEscape([req.body.o]);\n"
        "  h.system(\n"
        "    `DELETE FROM u WHERE owner = '${o}'`,\n"
        "    req.query.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "cells/py_t/guarded_request_multi_one.py": (
        "from flask import abort, request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = request.form["o"]\n'
        "    if not o.isalnum():\n"
        "        abort(400)\n"
        "    h.system(\n"
        "        f\"DELETE FROM u WHERE owner = '{o}'\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    "cells/py_t/constbuilt_request_multi_one.py": (
        "from flask import request\n"
        "\n"
        'OWNER = "x"\n'
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        "    h.system(\n"
        "        f\"DELETE FROM u WHERE owner = '{OWNER}'\",\n"
        '        request.args["opts"],\n'
        "    )\n"
    ),
    # The hoisted-concatenation residual: a hoisted concatenated statement beside ``row.owner``,
    # after a regex-flagged request-built SELECT; one-line and multi-line, one sink and two.
    "residual/concat_multi_one.js": (
        "async function f(req, db, h, conn) {\n"
        "  const o = req.body.o;\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  const stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\";\n"
        "  h.system(\n"
        "    stmt,\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "residual/concat_one_two.js": (
        "async function f(req, db, h, conn) {\n"
        "  const o = req.body.o;\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  const stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\";\n"
        "  conn.exec(row.owner); h.system(stmt, row.owner);\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "residual/concat_one_one.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = request.form["o"]\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\"\n"
        "    h.system(stmt, row.owner)\n"
    ),
    "residual/concat_multi_two.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def f(db, h, conn):\n"
        '    o = request.form["o"]\n'
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    stmt = \"DELETE FROM u WHERE owner = '\" + o + \"'\"\n"
        "    conn.exec(row.owner); h.system(\n"
        "        stmt,\n"
        "        row.owner,\n"
        "    )\n"
    ),
    # Hoisting read once for the sink: a statement built at a store sink outside its program
    # argument (after an interpreter and flag; second under a ``system`` key), beside ``opts``,
    # whose Def shares its line with a regex-flagged request-built SELECT.
    "persink/shc_concat.js": (
        "async function wipe(req, db) {\n"
        "  const o = req.body.o;\n"
        "  const opts = req.query.opts;"
        " const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  db.exec(\n"
        '    "sh", "-c",\n'
        "    \"DELETE FROM t WHERE owner = '\" + o + \"'\",\n"
        "    opts\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    "persink/shc_concat.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(db):\n"
        '    o = request.form["o"]\n'
        '    opts = request.args["opts"];'
        " row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    db.exec(\n"
        '        "sh", "-c",\n'
        "        \"DELETE FROM t WHERE owner = '\" + o + \"'\",\n"
        "        opts,\n"
        "    )\n"
    ),
    "persink/sys_second_concat.js": (
        "async function wipe(req, db) {\n"
        "  const o = req.body.o;\n"
        "  const opts = req.query.opts;"
        " const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  db.system(\n"
        "    opts,\n"
        "    \"DELETE FROM t WHERE owner = '\" + o + \"'\"\n"
        "  );\n"
        "}\n"
        "module.exports = { wipe };\n"
    ),
    # A residual of line ownership: a multi-line statement sink whose flows are all hint-only
    # (``file_path``), opening on the line of an earlier store sink fed by ``row.owner``. The
    # control: the JS form, whose statement flow is not hint-only.
    "lineown/py_hint_only_sink.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(db, h, conn, file_path):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    conn.exec(row.owner); h.system(\n"
        "        \"DELETE FROM t WHERE p = '\" + file_path + \"'\",\n"
        "    )\n"
    ),
    "lineown/py_hint_only_sink_two_args.py": (
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(db, h, conn, file_path):\n"
        "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
        "    conn.exec(row.owner); h.system(\n"
        "        \"DELETE FROM t WHERE p = '\" + file_path + \"'\",\n"
        "        file_path,\n"
        "    )\n"
    ),
    "lineown/js_hint_only_sink.js": (
        "async function f(req, db, h, conn, filePath) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  conn.exec(row.owner); h.system(\n"
        "    \"DELETE FROM t WHERE p = '\" + filePath + \"'\"\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    # A residual: a multi-line program argument, built from a constant (no reported flow reads
    # it), that nests another statement a regex CWE-89 row flags (a callback's, a call's).
    "nested/js_cb.js": (
        'const OWNER = "x";\n'
        "async function f(req, h, db) {\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + [OWNER].map(function (o) {\n"
        "      return db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "    }).join() + \"'\",\n"
        "    req.body.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "nested/js_cb_const.js": (
        'const OWNER = "x";\n'
        "async function f(req, h, db) {\n"
        "  h.system(\n"
        "    \"DELETE FROM u WHERE owner = '\" + [OWNER].map(function (o) {\n"
        "      return `SELECT * FROM t WHERE id = ${o}`;\n"
        "    }).join() + \"'\",\n"
        "    req.body.opts\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "nested/py_note.py": (
        "from flask import request\n"
        "\n"
        'OWNER = "x"\n'
        "\n"
        "\n"
        "def f(h):\n"
        "    h.system(\n"
        "        \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\"\n"
        '        + note(f"SELECT * FROM log WHERE k = {OWNER}"),\n'
        '        request.args["opts"],\n'
        "    )\n"
    ),
    # A residual: a store sink whose statement is not at the program position (shell-quoted
    # after an interpreter and flag; constant-built second under a ``system`` key) and that no
    # reported flow reads, beside ``row.owner`` after a regex-flagged request-built SELECT.
    "noprog/js_store_sh_c_quoted.js": (
        'const shellEscape = require("shell-escape");\n'
        "async function f(req, db) {\n"
        "  const o = shellEscape([req.body.o]);\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  db.exec(\n"
        '    "sh", "-c",\n'
        "    \"DELETE FROM u WHERE owner = '\" + o + \"'\",\n"
        "    row.owner\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
    "noprog/js_store_sys_second_local.js": (
        'const OWNER = "x";\n'
        "async function f(req, db) {\n"
        "  const row = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n"
        "  db.system(\n"
        "    row.owner,\n"
        "    \"DELETE FROM u WHERE owner = '\" + OWNER + \"'\"\n"
        "  );\n"
        "}\n"
        "module.exports = { f };\n"
    ),
}
# Each E2E hoisted unit's file, copied under ``hoisted/``.
HOISTED_COPIES = {
    "hoisted/stmt_py_hoisted_fstring.py": "stmt_py_hoisted_fstring/wipe.py",
    "hoisted/stmt_js_hoisted_template.js": "stmt_js_hoisted_template/wipe.js",
}

type Rows = list[tuple[int, str, str | None]]

# The cover rule, the defects: a statement sink after a regex-flagged query keeps its row.
COVER_DEFECTS: dict[str, Rows] = {
    "cover/a1.js": [(2, "89", "regex"), (3, "89", "ast")],
    "cover/b1.js": [(2, "89", "regex"), (3, "89", "ast")],
    "cover/q1.js": [(3, "89", "regex"), (4, "89", "ast")],
    "cover/q2.js": [(2, "89", "regex"), (4, "89", "ast")],
    "cover/q4.go": [(10, "89", "regex"), (12, "89", "ast")],
    "cover/p2.js": [(3, "89", "regex"), (4, "89", "ast")],
}
# The cover rule, the controls: unchanged, and a hoisted statement is one row.
COVER_CONTROLS: dict[str, Rows] = {
    "cover/q5.js": [(2, "89", "regex"), (3, "89", "ast")],
    "cover/h1.js": [(3, "89", "regex"), (4, "89", "ast")],
    "hoisted/stmt_py_hoisted_fstring.py": [(5, "89", "regex")],
    "hoisted/stmt_js_hoisted_template.js": [(2, "89", "regex")],
    "hoisted/js_hoist.js": [(3, "89", "regex")],
    "hoisted/py_hoist.py": [(4, "89", "regex")],
    "hoisted/js_hoist_param.js": [(3, "89", "ast")],
    "hoisted/go_hoist.go": [(5, "89", "ast")],
}
# The numberings, the defects. A regex row keeps the loop's line, an AST row the model's: in
# ``ff`` and ``u2028`` both stand at 6, the regex row on the SELECT (model line 5), the AST row
# on the DELETE.
NUMBERING_DEFECTS: dict[str, Rows] = {
    "numbering/ff.py": [(6, "89", "ast"), (6, "89", "regex")],  # the DELETE's row was lost
    "numbering/u2028.py": [(6, "89", "ast"), (6, "89", "regex")],  # the same, at U+2028
    "numbering/c3.py": [(8, "89", "regex")],  # the hoisted statement had a second row
    "numbering/pre2.py": [(7, "78", "ast")],  # the sink's loop line was never asked about
    "numbering/first_unread.js": [(3, "78", "ast")],  # read on its second loop line only
    "numbering/first_unread_sql.js": [(2, "89", "ast")],  # the same, a statement sink
}
# The numberings, the controls: no such character, and a split sink line emits one row.
NUMBERING_CONTROLS: dict[str, Rows] = {
    "numbering/ff_ctl.py": [(5, "89", "regex"), (6, "89", "ast")],
    "numbering/pre2_ctl.py": [(7, "78", "ast")],
    "numbering/split.js": [(3, "78", "ast")],
}
# The numberings in the CWE-22 head: the child's row alone, the CWE-22 row replaced.
PATH_ROWS: dict[str, Rows] = {
    "numbering/child_ff.py": [(7, "36", "regex")],  # a CWE-22 row stood beside it
    "numbering/child_ff2.py": [(9, "36", "regex")],  # the same, two form feeds above it
    "numbering/child_ctl.py": [(6, "36", "regex")],
}
# The residual, as built: the sink's text opens no statement at a literal's head (a comment
# before the ``DELETE``; ``CREATE``, no statement branch), so it reads as hoisted and the regex
# row on ``q``'s line covers it. One CWE-89 row, at line 10; none at the sink's line 11.
COVER_RESIDUALS: dict[str, Rows] = {
    "residual/t5_typed.go": [(10, "89", "regex")],
    "residual/t8_typed.go": [(10, "89", "regex")],
}
# The argument-line cover, the defects: a regex row on a line of the call that is neither the sink
# line nor the argument's covered the outer sink (four rows lost), and statement text there read as
# built at the sink (two second rows). Each now stands as the sink and argument lines give it.
ARG_SPAN_DEFECTS: dict[str, Rows] = {
    "argspan/inner_regex.js": [(2, "89", "ast"), (3, "89", "regex")],  # the DELETE's row lost
    "argspan/inner_query.js": [(2, "89", "ast"), (3, "89", "regex")],  # the same, a query
    "argspan/inner_hoisted.js": [(3, "89", "ast"), (4, "89", "regex")],  # the same, hoisted
    "argspan/inner_py.py": [(5, "89", "ast"), (7, "89", "regex")],  # the same, a keyword
    "argspan/cb.js": [(2, "89", "regex")],  # a second row: the callback's literal statement
    "argspan/multi_arg.py": [(5, "89", "regex")],  # a second row: a later keyword's statement
}
# The argument-line cover, the controls: unchanged.
ARG_SPAN_CONTROLS: dict[str, Rows] = {
    "argspan/inner_ctl.js": [(2, "89", "ast")],
    "argspan/cb_ctl.js": [(2, "89", "regex")],
    "argspan/cb_store.js": [(3, "89", "ast")],
    "argspan/cb_store_ctl.js": [(3, "89", "ast")],
    "argspan/multi_arg_ctl.py": [(5, "89", "regex")],
}
# The argument-line cover over a UTF-8 buffer: ``inner_py`` and ``cb`` with multibyte text above and
# in the call. A line counted off by the characters a byte offset spans moves both rows.
ARG_SPAN_BYTES: dict[str, Rows] = {
    "argspan/inner_py_utf8.py": [(4, "89", "ast"), (6, "89", "regex")],
    "argspan/cb_utf8.js": [(2, "89", "regex")],
}
# The cover is line-granular: another statement or a callback ON the sink line or an argument
# line still counts. Pinned as built (feature 0105, LLD §3.4): a second row where a hoisted
# statement's sink or argument line carries another literal statement; no AST row where a regex
# row for another statement stands on the sink or argument line (a CWE-89 row still stands on
# that line).
ARG_SPAN_RESIDUALS: dict[str, Rows] = {
    "argspan/cb_sameline.js": [(2, "89", "regex"), (3, "89", "ast")],
    "argspan/kw_argline.py": [(5, "89", "regex"), (6, "89", "ast")],
    "argspan/inner_sameline.js": [(2, "89", "regex")],
    "argspan/inner_argline.py": [(6, "89", "regex")],
}
# The every-flow cover, the defects: the kept flow's argument is the other one, so the regex CWE-89
# row on the statement's line (or on its hoisted Def's, a hop of the statement's flow only) did not
# cover the sink, which got a second CWE-89 row (an AST row at the sink line). Read through every
# flow reported at the sink, the regex row alone.
ANY_FLOW_DEFECTS: dict[str, Rows] = {
    "anyflow/db_sh_c.js": [(4, "89", "regex")],
    "anyflow/db_sh_c.py": [(7, "89", "regex")],
    "anyflow/db_sys_first.js": [(3, "89", "regex")],
    "anyflow/db_sys_first.py": [(6, "89", "regex")],
    "anyflow/sys_stmt_first.js": [(3, "89", "regex")],
    "anyflow/sys_stmt_first.py": [(6, "89", "regex")],
    "anyflow/sys_hoisted.js": [(2, "89", "regex")],
    "anyflow/sys_hoisted.py": [(5, "89", "regex")],
}
# The every-flow cover, the lost rows: the statement is built at the sink (its first argument), so
# the hops count for no flow at it. Read on the kept flow alone (``row.owner``, which hops onto the
# SELECT the regex row flags), or with hoisting decided per flow, the sink had no row.
ANY_FLOW_LOSSES: dict[str, Rows] = {
    "anyflow/b1_multi.js": [(3, "89", "regex"), (4, "89", "ast")],
    "anyflow/b1_multi.py": [(6, "89", "regex"), (7, "89", "ast")],
}
# The every-flow cover, the controls: unchanged.
ANY_FLOW_CONTROLS: dict[str, Rows] = {
    "anyflow/db_sys_second.js": [(4, "89", "regex")],
    "anyflow/sys_hoisted_second.js": [(2, "89", "regex"), (3, "78", "ast")],
    "anyflow/sys_stmt_second.js": [(2, "78", "ast"), (4, "89", "regex")],
    "anyflow/sys_stmt_second.py": [(5, "78", "ast"), (7, "89", "regex")],
}
# The program-argument cover, the lost rows: the statement is built in the sink's program argument,
# which no reported flow reads (its value shell-quoted, guarded, or a module constant), and the
# other argument (``row.owner``) hops onto an earlier regex-flagged SELECT. Read over the reported
# flows' argument lines alone the sink read as hoisted and that hop covered it: no row (the base had
# a CWE-78 row). Read with its program argument's lines it carries statement text, no hop counts and
# it keeps an AST CWE-89 row. The last three have a second sink on the line.
PROGRAM_ARG_LOSSES: dict[str, Rows] = {
    "progarg/b1_quoted.py": [(7, "89", "regex"), (8, "89", "ast")],
    "progarg/b1_guarded.py": [(8, "89", "regex"), (9, "89", "ast")],
    "progarg/b1_local.js": [(3, "89", "regex"), (4, "89", "ast")],
    "progarg/b1_local.py": [(7, "89", "regex"), (8, "89", "ast")],
    "cells/js/constbuilt_row_multi_one.js": [(3, "89", "regex"), (4, "89", "ast")],
    "cells/py/quoted_row_multi_one.py": [(7, "89", "regex"), (8, "89", "ast")],
    "cells/js/guarded_row_multi_one.js": [(4, "89", "regex"), (5, "89", "ast")],
    "cells/js_t/const_row_multi_one.js": [(2, "89", "regex"), (3, "89", "ast")],
    "cells/py/constbuilt_request_multi_two.py": [(7, "89", "regex"), (8, "89", "ast")],
    "cells/js/quoted_request_multi_two.js": [(4, "89", "regex"), (5, "89", "ast")],
    "cells/py/guarded_row_multi_two.py": [(8, "89", "regex"), (9, "89", "ast")],
}
# The program-argument cover, the second rows: the statement (an f-string or template) is the sink's
# program argument and no reported flow reads it (its value guarded, shell-quoted, or a constant),
# so the reported flow (``opts``) gave the sink its own lines alone: read as hoisted, meeting no
# hop, it got an AST row beside the regex row on the statement's line. The regex row alone.
PROGRAM_ARG_DUPLICATES: dict[str, Rows] = {
    "progarg/guarded_fstr.py": [(9, "89", "regex")],
    "progarg/quoted_fstr.py": [(7, "89", "regex")],
    "cells/js_t/quoted_request_multi_one.js": [(5, "89", "regex")],
    "cells/py_t/guarded_request_multi_one.py": [(9, "89", "regex")],
    "cells/py_t/constbuilt_request_multi_one.py": [(8, "89", "regex")],
}
# The program-argument cover, the controls: unchanged. The statement on the sink line
# (``b1_local_ctl``) and a pure literal statement (no statement flow: the sink's CWE-78 row stands).
PROGRAM_ARG_CONTROLS: dict[str, Rows] = {
    "progarg/b1_local_ctl.js": [(3, "89", "regex"), (4, "89", "ast")],
    "progarg/b1_const.js": [(2, "89", "regex"), (3, "78", "ast")],
    "progarg/b1_const.py": [(5, "89", "regex"), (6, "78", "ast")],
    "progarg/b1_const_ctl.js": [(2, "89", "regex"), (3, "78", "ast")],
}
# The per-sink grouping, the lost rows: two sinks on one line, the later (request-fed or hoisted)
# one's flow the line's row. Read together with the other sink's flow (``row.owner``, a hop onto the
# regex-flagged SELECT) it was hoisted and covered: no row. Read over its own sink's flows
# (``Flow.sink``) it keeps its AST CWE-89 row. The base was silent at ``same_line``'s sink.
BY_SINK_LOSSES: dict[str, Rows] = {
    "bysink/same_line.js": [(2, "89", "regex"), (3, "89", "ast")],
    "bysink/same_line.py": [(5, "89", "regex"), (6, "89", "ast")],
    "cells/js/hoisted_none_one_two.js": [(3, "89", "regex"), (5, "89", "ast")],
    "cells/py/hoisted_request_one_two.py": [(6, "89", "regex"), (8, "89", "ast")],
}
# The per-sink grouping, the controls: unchanged. The order swapped (the line's row is
# ``row.owner``'s sink, covered; the request-fed sink has no row of its own, as at the base and
# r0b), and the two sinks on separate lines.
BY_SINK_CONTROLS: dict[str, Rows] = {
    "bysink/same_line_swapped.js": [(2, "89", "regex")],
    "bysink/two_lines.js": [(2, "89", "regex"), (4, "89", "ast")],
    "bysink/two_lines.py": [(5, "89", "regex"), (7, "89", "ast")],
}
# The hoisted-concatenation residual, pinned as built: a hoisted concatenated statement
# (``stmt = "DELETE …'" + o + "'"``, then ``h.system(stmt, row.owner)``) after a regex-flagged
# request-built SELECT. The sink reads as hoisted (rightly: its program argument is the NAME
# ``stmt``), so the hops of every flow at it count, and ``row.owner``'s hop meets the SELECT's regex
# row; no regex row stands on the concatenated Def. The DELETE has no row (the base had a CWE-78 row
# at the sink).
CONCAT_RESIDUALS: dict[str, Rows] = {
    "residual/concat_multi_one.js": [(3, "89", "regex")],
    "residual/concat_one_two.js": [(3, "89", "regex")],
    "residual/concat_one_one.py": [(6, "89", "regex")],
    "residual/concat_multi_two.py": [(6, "89", "regex")],
}
# Hoisting read once for the sink: the statement is the store sink's own flow's argument, not
# its program argument; ``opts``'s Def shares a line with the regex-flagged SELECT. Read once
# for the sink the statement's line decides and no hop counts: a regex row and an AST CWE-89 row.
# Read for each flow alone, ``opts``'s hop meets the regex row and the sink has no row.
ONCE_PER_SINK: dict[str, Rows] = {
    "persink/shc_concat.js": [(3, "89", "regex"), (4, "89", "ast")],
    "persink/shc_concat.py": [(6, "89", "regex"), (7, "89", "ast")],
    "persink/sys_second_concat.js": [(3, "89", "regex"), (4, "89", "ast")],
}
# A residual of line ownership, pinned as built: the line ``conn.exec(row.owner); h.system(`` is
# the store sink's (a non-hint flow before a hint-only one), whose ``row.owner`` hop meets the
# SELECT's regex row. The DELETE has no row (the base had a CWE-78 row at the sink's line).
LINE_OWNER_RESIDUALS: dict[str, Rows] = {
    "lineown/py_hint_only_sink.py": [(5, "89", "regex")],
    "lineown/py_hint_only_sink_two_args.py": [(5, "89", "regex")],
}
# The control: the statement's flow is not hint-only, so the line is the later sink's, whose own
# lines carry the statement.
LINE_OWNER_CONTROLS: dict[str, Rows] = {
    "lineown/js_hint_only_sink.js": [(2, "89", "regex"), (3, "89", "ast")],
}
# A residual, pinned as built: the program argument's lines are the sink's, so the regex row on
# the statement nested in it covers the sink. The DELETE has no row (the base had a CWE-78 row).
NESTED_RESIDUALS: dict[str, Rows] = {
    "nested/js_cb.js": [(5, "89", "regex")],
    "nested/js_cb_const.js": [(5, "89", "regex")],
    "nested/py_note.py": [(9, "89", "regex")],
}
# A residual, pinned as built: no line the sink is read on carries the statement, so it reads as
# hoisted and ``row.owner``'s hop meets the SELECT's regex row. No row at the sink (as at the base).
NO_PROGRAM_RESIDUALS: dict[str, Rows] = {
    "noprog/js_store_sh_c_quoted.js": [(4, "89", "regex")],
    "noprog/js_store_sys_second_local.js": [(3, "89", "regex")],
}


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """Every program and hoisted unit under one neutral root (no test-path component)."""
    root = neutral_dir(request)
    for rel, text in PROGRAMS.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    for rel, unit in HOISTED_COPIES.items():
        shutil.copyfile(HOISTED_UNITS / unit, root / rel)
    return root


def _rows(root: Path, rel: str, skill: Any, checks: tuple[str, ...]) -> Rows:
    """``(line, short check id, engine)`` of each ``checks`` row ``skill`` gives ``rel``,
    sorted; the engine ``"ast"`` or ``"regex"`` (``_ast_heads.rows_at``)."""
    scan = _ast_heads.scan(skill, root)
    found = [
        (line, SHORT[check], engine)
        for check in checks
        for line, engine in _ast_heads.rows_at(scan, root, rel, check)
    ]
    return sorted(found, key=lambda row: (row[0], row[1], row[2] or ""))


def _injection_rows(root: Path, rel: str) -> Rows:
    return _rows(root, rel, check_injection, (SQL_ID, COMMAND_ID))


@pytest.mark.parametrize("rel", list(COVER_DEFECTS))
def test_a_statement_built_at_its_sink_keeps_its_row(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == COVER_DEFECTS[rel]


@pytest.mark.parametrize("rel", list(COVER_CONTROLS))
def test_cover_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == COVER_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(COVER_RESIDUALS))
def test_a_sink_whose_text_opens_no_statement_reads_as_hoisted(root: Path, rel: str) -> None:
    """Pinned as built (feature 0105, LLD §3.4): the request value ``q`` splices is reported
    once, by the regex row on ``q``'s line; the sink's line has no row, where the base had a
    CWE-78 row."""
    assert _injection_rows(root, rel) == COVER_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(ARG_SPAN_DEFECTS))
def test_a_statement_sink_is_read_on_its_sink_and_argument_lines(root: Path, rel: str) -> None:
    """The argument-line cover (feature 0105, LLD §4.6): the lines a regex CWE-89 row covers a
    statement sink on, and the lines its statement text is read from, are its sink line and its
    argument's, never its whole call (a callback body, a later keyword argument)."""
    assert _injection_rows(root, rel) == ARG_SPAN_DEFECTS[rel]


@pytest.mark.parametrize("rel", list(ARG_SPAN_CONTROLS))
def test_arg_span_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == ARG_SPAN_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(ARG_SPAN_BYTES))
def test_argument_lines_are_counted_in_the_parsed_bytes(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == ARG_SPAN_BYTES[rel]


@pytest.mark.parametrize("rel", list(ARG_SPAN_RESIDUALS))
def test_a_statement_on_the_sink_or_argument_line_still_counts(root: Path, rel: str) -> None:
    """Pinned as built (feature 0105, LLD §3.4): the cover lines are whole lines, so another
    statement or a callback written on the sink line or an argument line is read with them."""
    assert _injection_rows(root, rel) == ARG_SPAN_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(ANY_FLOW_DEFECTS))
def test_a_sink_is_covered_through_any_flow_reported_at_it(root: Path, rel: str) -> None:
    """The every-flow cover (feature 0105, LLD §4.6): a regex CWE-89 row covers a statement sink
    when it stands on a cover line of any flow reported at it, not only of the one ``_by_line``
    keeps."""
    assert _injection_rows(root, rel) == ANY_FLOW_DEFECTS[rel]


@pytest.mark.parametrize("rel", list(ANY_FLOW_LOSSES))
def test_hoisting_is_decided_once_for_the_sink(root: Path, rel: str) -> None:
    """The every-flow cover with the hoisted-only and argument-line covers (feature 0105, LLD §4.6):
    whether the statement is hoisted is read once for the sink, over its sink line and every
    reported flow's argument lines; only then do the hops of its flows count."""
    assert _injection_rows(root, rel) == ANY_FLOW_LOSSES[rel]


@pytest.mark.parametrize("rel", list(ANY_FLOW_CONTROLS))
def test_any_flow_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == ANY_FLOW_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(PROGRAM_ARG_LOSSES))
def test_a_statement_in_the_program_argument_keeps_its_row(root: Path, rel: str) -> None:
    """The program-argument cover (feature 0105, LLD §4.6): whether a statement is hoisted is read
    over the sink line, its program argument's lines (``Flow.program_span``) and every reported
    flow's argument lines, so a statement built in the program argument counts although no flow
    reads it."""
    assert _injection_rows(root, rel) == PROGRAM_ARG_LOSSES[rel]


@pytest.mark.parametrize("rel", list(PROGRAM_ARG_DUPLICATES))
def test_a_regex_row_on_the_program_argument_covers_the_sink(root: Path, rel: str) -> None:
    """The program-argument cover (feature 0105, LLD §4.6): the program argument's lines are cover
    lines, so the regex CWE-89 row on the statement's own line covers the sink, whichever flow is
    reported."""
    assert _injection_rows(root, rel) == PROGRAM_ARG_DUPLICATES[rel]


@pytest.mark.parametrize("rel", list(PROGRAM_ARG_CONTROLS))
def test_program_arg_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == PROGRAM_ARG_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(BY_SINK_LOSSES))
def test_each_sink_on_a_line_is_read_over_its_own_flows(root: Path, rel: str) -> None:
    """The per-sink grouping (feature 0105, LLD §4.6): the flows a sink is read over are those at
    its own call (``Flow.sink``), not every flow on its line, so another sink's hop on the same line
    covers nothing here."""
    assert _injection_rows(root, rel) == BY_SINK_LOSSES[rel]


@pytest.mark.parametrize("rel", list(BY_SINK_CONTROLS))
def test_by_sink_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == BY_SINK_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(CONCAT_RESIDUALS))
def test_a_hoisted_concatenation_is_covered_by_another_flows_hop(root: Path, rel: str) -> None:
    """Pinned as built (accepted as a residual; feature 0105, LLD §3.4): the DELETE
    hoisted into ``stmt`` by concatenation gets no row, because ``row.owner``'s hop meets the
    SELECT's regex row and no regex row stands on ``stmt``'s Def. Lost since P10 (the base had
    a CWE-78 row at the sink); a change that gives the sink a row changes this on purpose."""
    assert _injection_rows(root, rel) == CONCAT_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(ONCE_PER_SINK))
def test_hoisting_is_read_once_beside_the_program_argument(root: Path, rel: str) -> None:
    """Whether a statement is hoisted is read once for the sink, over its sink line, its
    program argument's lines and every reported flow's argument lines (feature 0105, LLD §4.6).
    Here the statement is no program argument (the interpreter literal ``"sh"`` is; ``opts`` is,
    under a ``system`` key), so only its own flow's argument line carries it, and the other flow,
    ``opts``, is defined on the line of a request-built SELECT a regex CWE-89 row flags. Read for
    that flow alone, with the program argument's lines, nothing carries statement text, its hop
    meets the regex row and the sink would have no row; read once for the sink it keeps its AST
    CWE-89 row."""
    assert _injection_rows(root, rel) == ONCE_PER_SINK[rel]


@pytest.mark.parametrize("rel", list(LINE_OWNER_RESIDUALS))
def test_a_hint_only_sink_on_another_sinks_line_has_no_row(root: Path, rel: str) -> None:
    """Pinned as built (a residual; feature 0105, LLD §3.4): line ownership keeps one flow per
    line, a non-hint flow before a hint-only one (0104 A1). ``h.system(`` opens on the line of
    ``conn.exec(row.owner)`` and its flows are all hint-only (``file_path``), so the line is the
    store sink's: its own lines carry no statement text, its ``row.owner`` hop meets the SELECT's
    regex row, and it is covered. The multi-line DELETE has no row of its own; the base had a
    CWE-78 row at the sink's line. A change that gives it a row changes this on purpose."""
    assert _injection_rows(root, rel) == LINE_OWNER_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(LINE_OWNER_CONTROLS))
def test_line_owner_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == LINE_OWNER_CONTROLS[rel]


@pytest.mark.parametrize("rel", list(NESTED_RESIDUALS))
def test_a_regex_row_nested_in_the_program_argument_covers_it(root: Path, rel: str) -> None:
    """Pinned as built (a residual; feature 0105, LLD §3.4): the sink's program argument is
    written over several lines, built from a constant so that no reported flow reads it, and
    nests another statement (a callback's ``SELECT``, a ``note(f"SELECT …")`` call) that a regex
    CWE-89 row flags. Its lines are the sink's, so that regex row covers the sink: the DELETE has
    no row of its own (the base had a CWE-78 row at the sink), and a CWE-89 row stands on the
    nested statement's line. A change that gives the sink a row changes this on purpose."""
    assert _injection_rows(root, rel) == NESTED_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(NO_PROGRAM_RESIDUALS))
def test_a_store_sink_with_its_statement_unread_reads_as_hoisted(root: Path, rel: str) -> None:
    """Pinned as built (a residual; feature 0105, LLD §3.4): a store sink whose statement is not
    at the program position (shell-quoted after an interpreter and flag; built from a constant,
    second under a ``system`` key) and that no reported flow reads. Neither the program
    argument's lines nor the one reported flow's (``row.owner``) carry the statement, so the
    sink reads as hoisted and ``row.owner``'s hop meets the SELECT's regex row: no row at the
    sink, as at the base. A change that gives the sink a row changes this on purpose."""
    assert _injection_rows(root, rel) == NO_PROGRAM_RESIDUALS[rel]


@pytest.mark.parametrize("rel", list(NUMBERING_DEFECTS))
def test_a_line_break_the_model_does_not_count_moves_no_row(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == NUMBERING_DEFECTS[rel]


@pytest.mark.parametrize("rel", list(NUMBERING_CONTROLS))
def test_numbering_controls(root: Path, rel: str) -> None:
    assert _injection_rows(root, rel) == NUMBERING_CONTROLS[rel]


@pytest.mark.parametrize("rel", ["numbering/ff.py", "numbering/u2028.py"])
def test_the_ast_row_quotes_the_sink_by_the_models_line(root: Path, rel: str) -> None:
    """The AST row at 6 is the DELETE's (D21), the regex row at 6 the SELECT's."""
    scan = _ast_heads.scan(check_injection, root)
    rows = _ast_heads.on(scan, root, rel, SQL_ID)
    quotes = [row.get("evidence_quote") for row in rows if "validation" in row]
    assert quotes == ['store.exec("DELETE FROM b WHERE id = " + i)']


@pytest.mark.parametrize("rel", list(PATH_ROWS))
def test_a_child_replaces_a_span_by_the_models_lines(root: Path, rel: str) -> None:
    assert _rows(root, rel, check_input_validation, (PATH_ID, ABSOLUTE_ID)) == PATH_ROWS[rel]


def _command_answer(path: Path) -> AstAnswer:
    """The head's CWE-78 answer for ``path``, asked as the skill asks it."""
    return _asked(path, (_RULE_78,)).together[0]


def test_a_split_sink_line_is_owned_on_each_loop_line_and_emits_once(tmp_path: Path) -> None:
    """``split.js``'s sink is model line 3, the loop's lines 3 and 4: ``claim`` owns both and
    appends one row, at the model's line; the loop's line 5 (the model's 4) is no span line."""
    path = tmp_path / "split.js"
    path.write_text(PROGRAMS["numbering/split.js"], encoding="utf-8")
    answer = _command_answer(path)
    rows: list[dict[str, Any]] = []
    owned = [claim(answer, _RULE_78, path, line, rows) for line in (3, 4, 5)]
    assert owned == [True, True, False]
    assert [row["line_start"] for row in rows] == [3]


def test_a_sink_line_is_read_when_any_of_its_loop_lines_is(tmp_path: Path) -> None:
    """``first_unread.js``'s sink is model line 3, whose first loop line is a comment the loop
    never reads and whose second it reads: ``unread_sinks`` leaves it out."""
    path = tmp_path / "first_unread.js"
    path.write_text(PROGRAMS["numbering/first_unread.js"], encoding="utf-8")
    answer = _command_answer(path)
    assert answer.spans and 3 in answer.spans
    assert unread_sinks(answer, read_file_lines(path) or (), _scanned) == frozenset()


# ── every flow reported at a sink (feature 0105, LLD §4.6) ───────────────────

MISSING: Any = object()


def _statement_answer(root: Path, rel: str) -> AstAnswer:
    """The head's CWE-89 answer for ``rel``, asked as the skill asks it."""
    return _asked(root / rel, (_RULE_89,)).together[0]


def _reported(answer: AstAnswer) -> Any:
    """The flows ``answer`` records beside its spans (``AstAnswer.reported``)."""
    found = getattr(answer, "reported", MISSING)
    assert found is not MISSING, "the answer records no reported flows"
    return found


def test_the_answer_records_every_flow_reported_at_a_sink(root: Path) -> None:
    """``sys_stmt_first.py``: two request-fed arguments, so two flows at sink line 5, each with
    its own argument; the line's row is one of them, the one ``_by_line`` keeps."""
    answer = _statement_answer(root, "anyflow/sys_stmt_first.py")
    reported = _reported(answer)
    assert [flow.sink_line for flow in reported] == [5, 5]
    assert len({flow.arg_span for flow in reported}) == 2
    assert answer.spans is not None and answer.spans[5] in reported


def test_a_hint_only_flow_is_recorded_beside_the_kept_one(root: Path) -> None:
    """``hint_and_request.py``: a hint-only flow (``file_path``) and a request-fed one at line 5.
    ``_by_line`` keeps the request-fed one (0104 A1); both are recorded."""
    answer = _statement_answer(root, "anyflow/hint_and_request.py")
    reported = _reported(answer)
    assert sorted((flow.sink_line, hint_only(flow.origins)) for flow in reported) == [
        (5, False), (5, True)]
    assert answer.spans is not None and not hint_only(answer.spans[5].origins)


def test_an_answer_built_without_them_records_none() -> None:
    """The default, an answer built as ``AstAnswer(spans, nl_lines)``: nothing recorded."""
    assert getattr(AstAnswer({}, ()), "reported", MISSING) == ()


def test_with_none_recorded_a_sink_reads_its_kept_flow_alone(root: Path) -> None:
    """``sys_stmt_first.py``: the regex row on the statement's line 6 covers the sink at 5 through
    the statement's flow. With none recorded the cover test reads the kept flow alone (``opts``,
    line 7), as before the every-flow cover, together with its sink's program argument (the
    statement, line 6: ``Flow.program_span``), so the row on 6 covers the sink this way too. Before
    the program-argument cover the kept flow alone covered nothing (``frozenset()``); the move is
    that rule's (feature 0105, LLD §4.6), measured on its prototype."""
    answer = _statement_answer(root, "anyflow/sys_stmt_first.py")
    _reported(answer)
    assert _regex_covered(answer, frozenset({6})) == frozenset({5})
    assert _regex_covered(answer._replace(reported=()), frozenset({6})) == frozenset({5})


def test_hoisting_is_read_over_every_flow_at_the_sink(root: Path) -> None:
    """``b1_multi.py``: the first argument (line 8) carries the statement, so the sink at 7 is
    not hoisted and no hop counts. Its other argument, ``row.owner`` (line 9), hops onto the
    SELECT at 6: read per flow, that flow alone would be hoisted and the regex row there would
    cover the sink."""
    answer = _statement_answer(root, "anyflow/b1_multi.py")
    assert _regex_covered(answer, frozenset({6})) == frozenset()


def test_a_hoisted_sink_reads_the_hops_of_every_flow_at_it(root: Path) -> None:
    """``sys_hoisted.py``: no line of the sink (6) or its arguments (7, 8) carries statement
    text, so the sink is hoisted and the hops of every flow at it count: the regex row on
    ``q``'s line 5, a hop of ``q``'s flow only, covers it; the kept flow (``opts``) passes no
    line 5."""
    answer = _statement_answer(root, "anyflow/sys_hoisted.py")
    assert _regex_covered(answer, frozenset({5})) == frozenset({6})


def test_the_program_argument_decides_whether_the_sink_is_hoisted(root: Path) -> None:
    """The program-argument cover: ``b1_quoted.py``'s statement (line 9) is the sink's program
    argument, built at the sink, and no flow reads it (its value is shell-quoted); the one reported
    flow, ``row.owner`` (line 10), hops onto the SELECT at 7. Read over that flow's lines alone the
    sink (8) read as hoisted and the regex row at 7 covered it; read with its program argument's
    line it carries statement text and no hop counts."""
    answer = _statement_answer(root, "progarg/b1_quoted.py")
    assert [flow.sink_line for flow in _reported(answer)] == [8]
    assert _regex_covered(answer, frozenset({7})) == frozenset()


def test_two_sinks_on_one_line_are_read_apart(root: Path) -> None:
    """The per-sink grouping: ``same_line.py``'s line 6 holds two statement sinks, and the line's
    row is the request-fed one's. The other sink's flow (``row.owner``) hops onto the SELECT at 5;
    read over its own call's flows (``Flow.sink``), the request-fed sink is not covered by it."""
    answer = _statement_answer(root, "bysink/same_line.py")
    reported = _reported(answer)
    assert len({flow.sink for flow in reported}) == 2
    assert _regex_covered(answer, frozenset({5})) == frozenset()


def _decided(path: Path) -> tuple[AstAnswer, int]:
    """In a new audit of ``path``'s directory: the head's CWE-89 answer, the command rules asked
    together as the skill asks them, and the declines the audit recorded."""
    context.enter(path.parent)
    answers = ast_answers(path, path.read_text(), (_RULE_78, _RULE_89))
    return answers[1], context.current().ledger.count


def test_each_accepted_flow_is_decided_once(root: Path) -> None:
    """A30 (1): the flows are recorded from the one ``decide`` pass the spans are built from. At
    ``quoted_and_request.py``'s sink (6) the shell-quoted statement flow is declined and the
    ``opts`` flow reported: ``decide`` sees each once, the decline is recorded once, and the
    reported flow alone is recorded."""
    from shared.ast import flow as flow_mod

    real, seen = flow_mod.decide, []

    def spy(flow: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(flow.sink_line)
        return real(flow, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(flow_mod, "decide", spy)
        answer, declines = contextvars.copy_context().run(
            _decided, root / "anyflow/quoted_and_request.py")
    assert (seen, declines) == ([6, 6], 1)
    assert [flow.sink_line for flow in _reported(answer)] == [6]


# ── a forged answer D3' admits (feature 0105, LLD §4.6) ──────────────────────

# A statement sink with two flows, whose lines a forged answer moves, and an unrelated file
# whose CWE-78 row a raise of the skill loses with every other row.
FORGED_APP = (
    "function wipe(req, h, db) {\n"
    '  const r = db.query("SELECT * FROM t WHERE id = " + req.query.id);\n'
    "  h.system(\n"
    "    `DELETE FROM t WHERE id = ${req.body.id}`,\n"
    "    req.query.opts\n"
    "  );\n"
    "}\n"
)
UNRELATED = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "\n"
    "def run():\n"
    "    os.system('ls ' + request.args['d'])\n"
)
type Forgery = Callable[[dict[str, Any], bytes], None]


def _whole_buffer_arg(flow: dict[str, Any], data: bytes) -> None:
    """The argument span over the whole buffer: within the bytes, starting before the sink's."""
    flow["arg_span"] = [0, len(data)]


def _last_sink_line(flow: dict[str, Any], data: bytes) -> None:
    """The sink line the buffer's last and the sink span the whole buffer."""
    flow["sink_line"] = data.count(b"\n") + 1
    flow["span"] = [0, len(data)]


ADMITTED: dict[str, Forgery] = {
    "argument over the whole buffer": _whole_buffer_arg,
    "last sink line, whole-buffer span": _last_sink_line,
}


def _forging(admit: Callable[..., Any], forge: Forgery) -> Callable[..., Any]:
    """``admit`` (the answer kind's), with ``FORGED_APP``'s command flows forged by ``forge`` in
    the worker's document before D3' reads it."""

    def forged(doc: dict[str, Any], profile: Any, grammar: str, text: str, data: bytes) -> Any:
        if text == FORGED_APP:
            for flow in doc["families"].get("command", ()):
                forge(flow, data)
        return admit(doc, profile, grammar, text, data)

    return forged


@pytest.mark.parametrize("forgery", list(ADMITTED))
def test_a_forged_answer_d3_admits_loses_no_row_of_the_skill(
    request: pytest.FixtureRequest, forgery: str
) -> None:
    """D3' admits the forgery (each value within its own bound); the skill completes over the
    tree, and the unrelated file keeps its CWE-78 row."""
    from shared.ast import cache

    root = neutral_dir(request)
    (root / "app.js").write_text(FORGED_APP, encoding="utf-8")
    (root / "other.py").write_text(UNRELATED, encoding="utf-8")
    kind = cache._ANSWER
    forged = dataclasses.replace(kind, admit=_forging(kind.admit, ADMITTED[forgery]))
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cache, "_ANSWER", forged)
        scan = _ast_heads.scan(check_injection, root)
    assert _ast_heads.rows_at(scan, root, "other.py", COMMAND_ID) == [(6, "ast")]


def _whole_buffer_program(flow: dict[str, Any], data: bytes) -> None:
    """The sink's program-argument span over the whole buffer: within the bytes,
    starting before the sink's."""
    flow["program_span"] = [0, len(data)]


def _admitting(forged: Callable[..., Any], admitted: list[bool]) -> Callable[..., Any]:
    """``forged``, noting in ``admitted`` each ``FORGED_APP`` answer D3' admits."""

    def admit(doc: dict[str, Any], profile: Any, grammar: str, text: str, data: bytes) -> Any:
        answer = forged(doc, profile, grammar, text, data)
        admitted.append(text == FORGED_APP)
        return answer

    return admit


def test_a_forged_program_span_d3_admits_loses_no_row_of_the_skill(
    request: pytest.FixtureRequest,
) -> None:
    """The program-argument cover: D3' bounds ``program_span`` by the shipped bytes alone, as
    ``arg_span``, so it admits a span over the whole buffer; the lines read for the sink stay inside
    the file (fix round r3's bound), the skill completes, and the unrelated file keeps its CWE-78
    row."""
    from shared.ast import cache

    root = neutral_dir(request)
    (root / "app.js").write_text(FORGED_APP, encoding="utf-8")
    (root / "other.py").write_text(UNRELATED, encoding="utf-8")
    kind, admitted = cache._ANSWER, []
    forged = _admitting(_forging(kind.admit, _whole_buffer_program), admitted)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cache, "_ANSWER", dataclasses.replace(kind, admit=forged))
        scan = _ast_heads.scan(check_injection, root)
    assert True in admitted, "D3' refused the forged answer"
    assert _ast_heads.rows_at(scan, root, "other.py", COMMAND_ID) == [(6, "ast")]
