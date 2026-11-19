"""Feature 0105 (LLD §5.1): the class of every command site, and the flows it keeps.

``Calls.command_class(site)`` gives each command-keyed call one class: ``process`` (a process
API, or no evidence against one), ``unproven`` (``system`` on a value with no command evidence:
WS-D), ``text`` (statement text on a value receiver with no evidence: WS-S), ``store`` (a
receiver with data-store evidence: WS-A), or None (a regex receiver: WS-C; or no command site).
Each table maps a row name to its inline program, the glued key of the one CALL the row is about,
and that call's class once every 0105 piece is in; each table has a class test of its own,
``test_<table>_class``. The programs, classes and origins are the measured prototype's; a comment
names the piece each row turns green at (P4 the classifier, P5 WS-C, P6 WS-S, P7 WS-A, P8 the
transaction words, P9 WS-D).

The flow half of a row is a test of its own, so it can hold while the class half is RED: a
``STILL_SINK`` row keeps a command flow at its call, a row whose class is None has none, and a
``store`` row of ``BASE_CLEAN``, ``LOSSES`` or ``GAPS``, like every ``unproven`` row, carries
exactly the origins ``ORIGINS`` lists (whether one of them is a real external origin decides its
rule: E4).

Beside the rows: the lexicon (B2's subset pins), the two caps (their cap + 1 is the ``CAPS``
rows), the ``value_imports`` language fact (§4.7), the answer schema and the ``command_class``
codec (§4.4), E4's table as ``consume.process_flow`` and ``statement_flow`` read it (§4.5), and
the parse worker's safety: ``shared.ast.sql_shape`` loads no ``shared.tools`` module (B5).

RED until each piece lands. Every name 0105 adds is reached inside a test body, so the module
collects at the base and each test fails on its own. Green at RED: the ``STILL_SINK`` flows, the
no-flow rows the base already leaves alone, and the origins of rows the base already reports.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

import shared.ast
from shared.ast import FileModel
from shared.ast._frames import ModelError
from shared.ast._origins import Engine
from shared.ast.kinds import Kind
from shared.ast.profile import PROFILES
from shared.testing.timing import budget
from tests.unit.ast._0104 import HINT, cases, required, sink_table
from tests.unit.ast._analysis import (
    Spec,
    candidates_of,
    consume_mod,
    external,
    flow_with,
    roles_mod,
    subject,
    unknown,
)
from tests.unit.ast._support import SHARED_ROOT

pytestmark = pytest.mark.usefixtures("real_pool")

# The classes (LLD §4.1); None is no command site.
PROCESS, UNPROVEN, TEXT, STORE = "process", "unproven", "text", "store"

GO_HTTP = 'package m\nimport "net/http"\nimport "database/sql"\nimport "fmt"\n'
SP = " " * 147  # the CAPS head rows' padding: the opener ends at byte 160 (the cap) or 161

# (program, the glued key of the one CALL the row is about, its class with every piece in)
type Row = tuple[Spec, str, str | None]


# WS-S: statement text on a value receiver with no command evidence is ``text``.
WS_S_TEXT: dict[str, Row] = {
    # green at P6
    "t_go_param": (
        ("go", GO_HTTP + 'func f(h X, x string) { h.Exec("DELETE FROM t WHERE id = " + x) }\n'),
        "exec", TEXT),
    "t_php_typed": (
        ("php", '<?php\n'
                'function f(PDO $h) { $h->exec("DELETE FROM t WHERE id = " . $_GET["id"]); }\n'),
        "exec", TEXT),
    "t_php_hoisted": (
        ("php", '<?php\n'
                'function f(PDO $h, $id) { $sql = "UPDATE t SET a = 1 WHERE id = " . $id; '
                '$h->exec($sql); }\n'),
        "exec", TEXT),
    "t_ts_typed": (
        ("ts", 'export function f(store: Database, req: any) { '
               'store.exec("DELETE FROM t WHERE id = " + req.body.id); }\n'),
        "exec", TEXT),
    "t_js_template": (
        ("js", 'function f(h, x) { h.exec(`INSERT INTO t VALUES (${x})`); }\n'),
        "exec", TEXT),
    "t_go_raw_lead": (
        ("go", GO_HTTP + 'func f(h X, x string) { h.Exec(`\n'
                         '\t\tDELETE FROM t WHERE id = ` + x) }\n'),
        "exec", TEXT),
    "t_go_escaped_lead": (
        ("go", GO_HTTP + 'func f(h X, x string) { '
                         'h.Exec("\\n\\tDELETE FROM t WHERE id = " + x) }\n'),
        "exec", TEXT),
    "t_go_select": (
        ("go", GO_HTTP + 'func f(h X, x string) { h.Exec("SELECT a FROM t WHERE b = " + x) }\n'),
        "exec", TEXT),
    "t_php_this": (
        ("php", '<?php\n'
                'class A { function f($id) { '
                '$this->h->exec("DELETE FROM t WHERE id = " . $id); } }\n'),
        "exec", TEXT),
    "t_go_update_raw_newline": (
        ("go", GO_HTTP + 'func f(h X, x string) { h.Exec(`UPDATE t\n\t\tSET a = ` + x) }\n'),
        "exec", TEXT),
    "t_py_fstring": (
        ("py", 'def f(h, x):\n    h.executescript(f"DELETE FROM t WHERE id = {x}")\n'),
        "executescript", TEXT),
}


# WS-S, WS-A: a receiver with data-store evidence is ``store``, whatever the argument.
WS_S_STORE: dict[str, Row] = {
    # green at P6
    "s_go_db_request": (
        ("go", GO_HTTP + 'func f(db X, r *http.Request) { '
                         'db.Exec("DELETE FROM t WHERE id = " + r.FormValue("id")) }\n'),
        "exec", STORE),
    "s_go_db_chain": (
        ("go", GO_HTTP + 'func f(db X, x string) { db.Exec("DELETE FROM t; " + x) }\n'),
        "exec", STORE),
    "s_go_db_create": (
        ("go", GO_HTTP + 'func f(db X, x string) { db.Exec("CREATE TABLE " + x) }\n'),
        "exec", STORE),
    "s_go_db_raw_arg": (
        ("go", GO_HTTP + 'func f(db X, r *http.Request) { db.Exec(r.FormValue("q")) }\n'),
        "exec", STORE),
    "s_php_static_db": (
        ("php", '<?php\nfunction f() { Db::exec("DELETE FROM t WHERE id = " . $_GET["id"]); }\n'),
        "exec", STORE),
    "s_js_ssh_conn": (
        ("js", 'const { Client } = require("ssh2");\n'
               'function f(req) { const conn = new Client(); conn.exec(req.query.c, '
               '() => {}); }\n'),
        "exec", STORE),
    "s_js_dbclient_statement": (
        ("js", 'function f(dbClient, req) { '
               'dbClient.exec("DELETE FROM t WHERE id = " + req.query.id); }\n'),
        "exec", STORE),
    # green at P7
    "s_go_typed_create": (
        ("go", GO_HTTP + 'func f(t *sql.Tx, x string) { t.Exec("CREATE TABLE " + x) }\n'),
        "exec", STORE),
    "s_go_typed_raw_newline": (
        ("go", GO_HTTP + 'type DB struct{}\n'
                         'func (d *DB) f(x string) { d.Exec(`UPDATE t\n'
                         '\t\tSET a = ` + x) }\n'),
        "exec", STORE),
    "s_go_typed_sprintf": (
        ("go", GO_HTTP + 'func f(t *sql.Tx, r *http.Request) { '
                         't.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", '
                         'r.FormValue("id"))) }\n'),
        "exec", STORE),
    "s_go_typed_raw_arg": (
        ("go", GO_HTTP + 'func f(t *sql.Tx, r *http.Request) { t.Exec(r.FormValue("q")) }\n'),
        "exec", STORE),
}


# A chained command, a shell, a namespace or command evidence keeps statement text ``process``.
WS_S_STAYS_PROCESS: dict[str, Row] = {
    # green at P4
    "p_js_cp_chain": (
        ("js", 'const cp = require("child_process");\n'
               'function f(x) { cp.exec("DELETE FROM t; " + x); }\n'),
        "exec", PROCESS),
    "p_js_param_chain": (
        ("js", 'function f(h, x) { h.exec("DELETE FROM t; " + x); }\n'),
        "exec", PROCESS),
    "p_js_cp_psql": (
        ("js", 'const cp = require("child_process");\n'
               'function f(x) { cp.exec("psql -c \'DELETE FROM t WHERE id = " + x + "\'"); }\n'),
        "exec", PROCESS),
    "p_js_param_psql": (
        ("js", 'function f(h, x) { h.exec("psql -c \'DELETE FROM t WHERE id = " + x + "\'"); }\n'),
        "exec", PROCESS),
    "p_php_bare": (
        ("php", '<?php\nfunction f() { exec("DELETE FROM t WHERE id = " . $_GET["id"]); }\n'),
        "exec", PROCESS),
    "p_js_mixed_defs": (
        ("js", 'function f(h, req, a) { let q = "DELETE FROM t WHERE id = " + a; if (a) { '
               'q = req.query.c; } h.exec(q); }\n'),
        "exec", PROCESS),
    "p_go_pkg_statement": (
        ("go", GO_HTTP + 'import "os/exec"\n'
                         'func f(x string) { '
                         'exec.Command("DELETE FROM t WHERE id = " + x).Run() }\n'),
        "command", PROCESS),
    "p_js_regex_head_rerun": (("js", 'function f(reRun, c) { reRun.exec(c); }\n'), "exec", PROCESS),
    "p_py_sh_run_statement": (
        ("py", 'from flask import request\n'
               'def f(sh):\n'
               '    sh.run("DELETE FROM t WHERE id = " + request.args["id"])\n'),
        "run", PROCESS),
    "p_js_ssh_exec_statement": (
        ("js", 'function f(ssh, req) { ssh.exec("DELETE FROM t WHERE id = " + req.query.id); }\n'),
        "exec", PROCESS),
    "p_js_cmd_run_statement": (
        ("js", 'function f(cmd, req) { cmd.run("UPDATE t SET a = " + req.query.a); }\n'),
        "run", PROCESS),
}


# The statement-text caps: at a cap the text is read (``text``), one past it it is not.
CAPS: dict[str, Row] = {
    # green at P4
    "p_cap_spine_9": (
        ("js", 'function f(h, a) { '
               'h.exec("DELETE FROM t WHERE id = " + a + a + a + a + a + a + a + a + a); }\n'),
        "exec", PROCESS),
    "p_cap_head_161": (
        ("js", 'function f(h, a) { h.exec("' + SP + ' DELETE FROM t WHERE id = " + a); }\n'),
        "exec", PROCESS),
    # green at P6
    "t_cap_spine_8": (
        ("js", 'function f(h, a) { '
               'h.exec("DELETE FROM t WHERE id = " + a + a + a + a + a + a + a + a); }\n'),
        "exec", TEXT),
    "t_cap_head_160": (
        ("js", 'function f(h, a) { h.exec("' + SP + 'DELETE FROM t WHERE id = " + a); }\n'),
        "exec", TEXT),
}


# WS-A: data-store evidence by the receiver's declared type.
WS_A_TYPE: dict[str, Row] = {
    # green at P7
    "a_go_type": (("go", GO_HTTP + 'func f(h *sql.DB, q string) { h.Exec(q) }\n'), "exec", STORE),
    "a_go_method": (
        ("go", GO_HTTP + 'type LedgerDb struct{}\nfunc (s *LedgerDb) f(q string) { s.Exec(q) }\n'),
        "exec", STORE),
}


# WS-A: data-store evidence by the receiver's binding.
WS_A_BIND: dict[str, Row] = {
    # green at P7
    "a_go_bind_open": (
        ("go", GO_HTTP + 'func f(q string) { h, _ := sql.Open("x", "y"); h.Exec(q) }\n'),
        "exec", STORE),
    "a_go_bind_begin": (
        ("go", GO_HTTP + 'func f(conn X, q string) { t := conn.Begin(); t.Exec(q) }\n'),
        "exec", STORE),
    "a_js_new": (
        ("js", 'function f(q) { const store = new Database("x.db"); store.exec(q); }\n'),
        "exec", STORE),
}


# WS-A: a transaction word names a data store.
WS_A_TX: dict[str, Row] = {
    # green at P8
    "a_go_tx_name": (
        ("go", GO_HTTP + 'func f(s X, q string) { tx, _ := s.Begin(); tx.Exec(q) }\n'),
        "exec", STORE),
    "a_go_tx_type": (
        ("go", GO_HTTP + 'func f(t txlib.Tx, q string) { t.Exec(q) }\n'),
        "exec", STORE),
}


# WS-C: a regex receiver is no command site, statement text or not.
WS_C: dict[str, Row] = {
    # green at P4
    "c_js_regex_statement": (
        ("js", 'function f(req) { '
               'return /^(\\w+)/.exec("SELECT a FROM t WHERE b = " + req.query.q); }\n'),
        "exec", None),
    "c_js_regex_var_statement": (
        ("js", 'function f(req, p) { const rx = new RegExp(p); '
               'return rx.exec("SELECT a FROM t WHERE b = " + req.query.q); }\n'),
        "exec", None),
    "c_ts_pattern_statement": (
        ("ts", 'class A { sqlPattern: any; f(req: any) { '
               'return this.sqlPattern.exec("DELETE FROM t WHERE id = " + req.body.id); } }\n'),
        "exec", None),
    # green at P5
    "c_ts_member": (
        ("ts", 'export function f(req: any, entry: any) { return entry.regex.exec(req.url); }\n'),
        "exec", None),
    "c_js_glued": (("js", 'function f(cfg, s) { return cfg.routeRegex.exec(s); }\n'), "exec", None),
}


# WS-D: ``system`` on a value with no command evidence is ``unproven``; statement text stays.
WS_D: dict[str, Row] = {
    # green at P6
    "d_ts_import_statement": (
        ("ts", 'import { palette } from "./palette";\n'
               'export function f(req: any) { '
               'return palette.system("DELETE FROM t WHERE id = " + req.body.id); }\n'),
        "system", TEXT),
    # green at P9
    "d_ts_import": (
        ("ts", 'import { palette } from "./palette";\n'
               'export function f(label: string) { return palette.system(label); }\n'),
        "system", UNPROVEN),
    "d_js_param": (("js", 'function f(runner, cmd) { runner.system(cmd); }\n'), "system", UNPROVEN),
    "d_js_param_request": (
        ("js", 'function f(runner, req) { runner.system(req.query.c); }\n'),
        "system", UNPROVEN),
    "d_ts_import_request": (
        ("ts", 'import { palette } from "./palette";\n'
               'export function f(req: any) { return palette.system(req.body.c); }\n'),
        "system", UNPROVEN),
    "d_cpp_argv_external": (
        ("cpp", 'int main(int argc, char** argv) { auto r = make(); return r.system(argv[1]); }\n'),
        "system", UNPROVEN),
}


# A process API keeps ``process`` and its command flow, on a namespace receiver too.
STILL_SINK: dict[str, Row] = {
    # green at P4
    "k_js_local_class": (
        ("js", 'class Runner { static system(c) { return c; } }\n'
               'function f(cmd) { Runner.system(cmd); }\n'),
        "system", PROCESS),
    "k_go_sh_c": (
        ("go", GO_HTTP + 'import "os/exec"\n'
                         'func f(r *http.Request) { exec.Command("sh", "-c", '
                         'r.FormValue("c")).Run() }\n'),
        "command", PROCESS),
    "k_go_syscall": (
        ("go", GO_HTTP + 'import "syscall"\n'
                         'func f(p string, a []string) { syscall.Exec(p, a, nil) }\n'),
        "exec", PROCESS),
    "k_go_cgo": (
        ("go", 'package m\n'
               '// #include <stdlib.h>\n'
               'import "C"\n'
               'import "net/http"\n'
               'func f(r *http.Request) { C.system(C.CString(r.FormValue("c"))) }\n'),
        "system", PROCESS),
    "k_go_pkg_noword": (
        ("go", GO_HTTP + 'import "example.com/x/util"\n'
                         'func f(r *http.Request) { util.System(r.FormValue("c")) }\n'),
        "system", PROCESS),
    "k_js_cp": (
        ("js", 'const cp = require("child_process");\n'
               'function f(req) { cp.exec(req.query.cmd); }\n'),
        "exec", PROCESS),
    "k_js_remote": (("js", 'function f(remote, cmd) { remote.exec(cmd); }\n'), "exec", PROCESS),
    "k_ts_runner": (
        ("ts", 'export function f(runner: ChildProcessRunner, cmd: string) { '
               'runner.exec(cmd); }\n'),
        "exec", PROCESS),
    "k_java_runtime": (
        ("java", 'class A { void f(String cmd) throws Exception { '
                 'Runtime r = Runtime.getRuntime(); r.exec(cmd); } }\n'),
        "exec", PROCESS),
    "k_java_type_import": (
        ("java", 'import com.acme.Palette;\n'
                 'class A { String f(String t) { return Palette.system(t); } }\n'),
        "system", PROCESS),
    "k_java_import_static": (
        ("java", 'import static com.acme.Ui.palette;\n'
                 'class A { void f(String t) { palette.system(t); } }\n'),
        "system", PROCESS),
    "k_py_popen": (
        ("py", 'import subprocess\ndef f(cmd):\n    subprocess.Popen(cmd, shell=True)\n'),
        "popen", PROCESS),
    "k_py_os": (("py", 'import os\ndef f(c):\n    os.system(c)\n'), "system", PROCESS),
    "k_py_os_as": (("py", 'import os as o\ndef f(c):\n    o.system(c)\n'), "system", PROCESS),
    "k_py_posix": (("py", 'import posix\ndef f(c):\n    posix.system(c)\n'), "system", PROCESS),
    "k_py_shell_param": (("py", 'def f(shell, c):\n    shell.system(c)\n'), "system", PROCESS),
    "k_py_from_os": (
        ("py", 'from os import system\ndef f(c):\n    system(c)\n'),
        "system", PROCESS),
    "k_php_bare": (("php", '<?php\nfunction f($cmd) { system($cmd); }\n'), "system", PROCESS),
    "k_php_static": (("php", '<?php\nfunction f($c) { Runner::system($c); }\n'), "system", PROCESS),
    "k_php_use_static": (
        ("php", '<?php\nuse App\\Runner;\nfunction f($c) { Runner::system($c); }\n'),
        "system", PROCESS),
    "k_c_system": (
        ("c", '#include <stdlib.h>\nint main(int argc, char **argv) { return system(argv[1]); }\n'),
        "system", PROCESS),
    "k_cpp_std": (
        ("cpp", '#include <cstdlib>\nint main(int c, char** v) { return std::system(v[1]); }\n'),
        "system", PROCESS),
    "k_cpp_mylib": (
        ("cpp", 'int main(int c, char** v) { return mylib::util::system(v[1]); }\n'),
        "system", PROCESS),
    "k_rs_libc": (
        ("rs", 'fn main() { let a: Vec<String> = std::env::args().collect(); unsafe { '
               'libc::system(a[1].as_ptr() as *const i8); } }\n'),
        "system", PROCESS),
    "k_rs_use_libc": (
        ("rs", 'use libc;\n'
               'fn main() { let a: Vec<String> = std::env::args().collect(); unsafe { '
               'libc::system(a[1].as_ptr() as *const i8); } }\n'),
        "system", PROCESS),
    "k_rs_command_new": (
        ("rs", 'use std::process::Command;\n'
               'fn main() { let a: Vec<String> = std::env::args().collect(); '
               'Command::new(&a[1]).spawn(); }\n'),
        "new", PROCESS),
    "k_rs_nix": (
        ("rs", 'fn main() { let a: Vec<String> = std::env::args().collect(); '
               'nix::unistd::system(&a[1]); }\n'),
        "system", PROCESS),
    "k_rs_type_assoc": (
        ("rs", 'struct Sh;\n'
               'impl Sh {\n'
               '    fn ls(d: &str) { let c = format!("ls {}", d); Sh::system(&c); }\n'
               '}\n'),
        "system", PROCESS),
}


# E2, E3: process evidence outranks a data store; a regex on one path only is no regex.
E_BASE: dict[str, Row] = {
    # green at P4
    "e_procdb": (("js", 'function f(procDb, q) { procDb.exec(q); }\n'), "exec", PROCESS),
    "e_mixed_regex": (
        ("js", 'function f(p, other, c) { let rx = new RegExp(p); if (c) { rx = other; } '
               'return rx.exec(c); }\n'),
        "exec", PROCESS),
}


# No sink at the base; ``store`` from P6, its flow reported by no rule.
BASE_CLEAN: dict[str, Row] = {
    # green at P6
    "b_go_call_receiver": (
        ("go", GO_HTTP + 'func f(conn X, q string) { conn.Begin().Exec(q) }\n'),
        "exec", STORE),
}


# The named losses (L6, L-A, L7, L-hint) and their external twins, which are kept.
LOSSES: dict[str, Row] = {
    # green at P5
    "l6_js_head_pattern": (
        ("js", 'function f(runPattern, cmd) { runPattern.exec(cmd); }\n'),
        "exec", None),
    "l6_go_re_receiver": (
        ("go", 'package m\n'
               'import "net/http"\n'
               'type RemoteExec struct{ host string }\n'
               'func (re *RemoteExec) Exec(c string) error { return nil }\n'
               'func (re *RemoteExec) Handle(w http.ResponseWriter, r *http.Request) { '
               're.Exec(r.FormValue("cmd")) }\n'),
        "exec", None),
    "l6_js_re_new": (
        ("js", 'function f(req) { const re = new RemoteExec(req.host); re.exec(req.query.c); }\n'),
        "exec", None),
    # green at P7
    "l1_go_dbjob_param": (
        ("go", GO_HTTP + 'type DBJob struct{}\nfunc f(job *DBJob, cmd string) { job.Exec(cmd) }\n'),
        "exec", STORE),
    "l2_go_bound_runner": (
        ("go", GO_HTTP + 'func f(db X, cmd string) { r := db.NewRunner(); r.Exec(cmd) }\n'),
        "exec", STORE),
    "l1_go_dbjob_request": (
        ("go", GO_HTTP + 'type DBJob struct{}\n'
                         'func f(job *DBJob, r *http.Request) { job.Exec(r.FormValue("c")) }\n'),
        "exec", STORE),
    "l2_py_ssh_channel": (
        ("py", 'from flask import request\n'
               'def f(conn):\n'
               '    chan = conn.open_session()\n'
               '    chan.exec_command(request.args["c"])\n'),
        "execcommand", STORE),
    "lhint_js_store_argv": (
        ("js", 'function f() { const store = new Database("x.db"); '
               'store.exec("DELETE FROM t WHERE id = " + process.argv[2]); }\n'),
        "exec", STORE),
    # green at P8
    "l4_js_txn": (("js", 'function f(txn, cmd) { txn.exec(cmd); }\n'), "exec", STORE),
    "l1_go_taskexec_request": (
        ("go", 'package m\n'
               'import "net/http"\n'
               'type TaskExec struct{}\n'
               'func (tx *TaskExec) Handle(w http.ResponseWriter, r *http.Request) { '
               'tx.Exec(r.FormValue("cmd")) }\n'),
        "exec", STORE),
    # green at P9
    "l7_js_system": (
        ("js", 'function f(runner, cmd) { runner.system(cmd); }\n'),
        "system", UNPROVEN),
    "d_ts_ns_import_param": (
        ("ts", 'import * as runner from "./runner";\n'
               'export function f(cmd: string) { runner.system(cmd); }\n'),
        "system", UNPROVEN),
    "d_js_require_param": (
        ("js", 'const runner = require("./runner");\nfunction f(cmd) { runner.system(cmd); }\n'),
        "system", UNPROVEN),
    "d_py_from_module_param": (
        ("py", 'from tools import runner\n\ndef f(cmd):\n    runner.system(cmd)\n'),
        "system", UNPROVEN),
    "l7_js_argv": (
        ("js", 'function f(runner) { runner.system(process.argv[2]); }\n'),
        "system", UNPROVEN),
    "l7_py_module_alias": (
        ("py", 'import os\nosm = os\ndef f(cmd):\n    osm.system(cmd)\n'),
        "system", UNPROVEN),
    "l7_py_dunder_import": (
        ("py", 'osm = __import__("os")\ndef f(cmd):\n    osm.system(cmd)\n'),
        "system", UNPROVEN),
    "l7_py_importlib": (
        ("py", 'import importlib\n'
               'osm = importlib.import_module("os")\n'
               'def f(cmd):\n'
               '    osm.system(cmd)\n'),
        "system", UNPROVEN),
    "l7_py_ctypes": (
        ("py", 'import ctypes\nlibc = ctypes.CDLL(None)\ndef f(cmd):\n    libc.system(cmd)\n'),
        "system", UNPROVEN),
    "l7_rs_self_type": (
        ("rs", 'struct Sh;\n'
               'impl Sh {\n'
               '    fn ls(d: &str) { let c = format!("ls {}", d); Self::system(&c); }\n'
               '}\n'),
        "system", UNPROVEN),
}


# M1: statement text to a process API on a value with no command evidence.
MISLABELS: dict[str, Row] = {
    # green at P6
    "m1_js_inline_require": (
        ("js", 'function f(req) { '
               'require("child_process").exec("DELETE FROM t WHERE id = " + req.query.id); }\n'),
        "exec", TEXT),
    "m1_py_inline_dunder": (
        ("py", 'def f(x):\n    __import__("os").system("DELETE FROM t WHERE id = " + x)\n'),
        "system", TEXT),
    "m1_js_later_semicolon": (
        ("js", 'function f(h, x) { h.exec("UPDATE t SET a = " + x + "; rm -rf /tmp/y"); }\n'),
        "exec", TEXT),
}


# The named gaps: false positives kept under CWE-78, and named CWE-89 shapes (N2, N3).
GAPS: dict[str, Row] = {
    # green at P4
    "g_js_client_statement": (
        ("js", 'function f(client, req) { '
               'client.exec("DELETE FROM t WHERE id = " + req.query.id); }\n'),
        "exec", PROCESS),
    "g_ts_untyped": (
        ("ts", 'export function wipe(store: any, q: string) { store.exec(q); }\n'),
        "exec", PROCESS),
    "g_go_index": (
        ("go", GO_HTTP + 'func f(txs []X, q string) { txs[0].Exec(q) }\n'),
        "exec", PROCESS),
    "g_go_iface": (
        ("go", GO_HTTP + 'type Execer interface{ Exec(q string) }\n'
                         'func f(e Execer, q string) { e.Exec(q) }\n'),
        "exec", PROCESS),
    "g_go_field": (
        ("go", GO_HTTP + 'type S struct{ store X }\nfunc (s *S) f(q string) { s.store.Exec(q) }\n'),
        "exec", PROCESS),
    "g_php_param_query": (
        ("php", '<?php\nfunction f(PDO $h, $query) { $h->exec($query); }\n'),
        "exec", PROCESS),
    "g_go_sprintf_value": (
        ("go", GO_HTTP + 'func f(h X, x string) { '
                         'h.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", x)) }\n'),
        "exec", PROCESS),
    "g_go_create_value": (
        ("go", GO_HTTP + 'func f(h X, x string) { h.Exec("CREATE TABLE " + x) }\n'),
        "exec", PROCESS),
    # green at P6
    "g_php_quote": (
        ("php", '<?php\n'
                'function f() { $db = new PDO("x"); '
                '$db->exec("DELETE FROM t WHERE id = " . $db->quote($_GET["id"])); }\n'),
        "exec", STORE),
    "g_py_shell_quote_store": (
        ("py", 'import shlex\n'
               'from flask import request\n'
               'def f(db):\n'
               '    db.executescript("DELETE FROM t WHERE id = " + '
               'shlex.quote(request.args["id"]))\n'),
        "executescript", STORE),
    # green at P8
    "s_go_loop_constants": (
        ("go", GO_HTTP + 'type st struct{ query string; args []any }\n'
                         'func f(d X, r *http.Request) {\n'
                         '\ttx, _ := d.Begin()\n'
                         '\tfor _, s := range []st{{"DELETE FROM a WHERE k = $1", '
                         '[]any{r.FormValue("k")}}} {\n'
                         '\t\ttx.Exec(s.query, s.args...)\n'
                         '\t}\n'
                         '}\n'),
        "exec", STORE),
}


# E5: nothing fires on an undecided fact; 16 Defs is the boundary (``unproven``).
E5: dict[str, Row] = {
    # green at P4
    "e5_text_17_defs": (
        ("js", 'function f(h, a, c) { let q = "DELETE FROM t WHERE id = " + a; if (c == 1) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 2) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 3) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 4) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 5) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 6) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 7) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 8) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 9) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 10) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 11) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 12) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 13) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 14) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 15) { '
               'q = "DELETE FROM t WHERE id = " + a; } if (c == 16) { '
               'q = "DELETE FROM t WHERE id = " + a; } h.exec(q); }\n'),
        "exec", PROCESS),
    "e5_system_17_defs": (
        ("js", 'function f(c, cmd) { let r = mk(); if (c == 1) { r = mk(); } if (c == 2) { '
               'r = mk(); } if (c == 3) { r = mk(); } if (c == 4) { r = mk(); } if (c == 5) { '
               'r = mk(); } if (c == 6) { r = mk(); } if (c == 7) { r = mk(); } if (c == 8) { '
               'r = mk(); } if (c == 9) { r = mk(); } if (c == 10) { r = mk(); } if (c == 11) { '
               'r = mk(); } if (c == 12) { r = mk(); } if (c == 13) { r = mk(); } if (c == 14) { '
               'r = mk(); } if (c == 15) { r = mk(); } if (c == 16) { r = mk(); } '
               'r.system(cmd); }\n'),
        "system", PROCESS),
    "e5_valueless_def": (
        ("js", 'function f(h, a, c) { let q; if (c) { q = "DELETE FROM t WHERE id = " + a; } '
               'h.exec(q); }\n'),
        "exec", PROCESS),
    "e5_valueless_receiver": (
        ("js", 'function f(c, cmd) { let r; if (c) { r = mk(); } r.system(cmd); }\n'),
        "system", PROCESS),
    "e5_valueless_receiver_text": (
        ("js", 'function f(c, x) { let h; if (c) { h = mk(); } '
               'h.exec("DELETE FROM t WHERE id = " + x); }\n'),
        "exec", PROCESS),
    # green at P9
    "e5_system_16_defs": (
        ("js", 'function f(c, cmd) { let r = mk(); if (c == 1) { r = mk(); } if (c == 2) { '
               'r = mk(); } if (c == 3) { r = mk(); } if (c == 4) { r = mk(); } if (c == 5) { '
               'r = mk(); } if (c == 6) { r = mk(); } if (c == 7) { r = mk(); } if (c == 8) { '
               'r = mk(); } if (c == 9) { r = mk(); } if (c == 10) { r = mk(); } if (c == 11) { '
               'r = mk(); } if (c == 12) { r = mk(); } if (c == 13) { r = mk(); } if (c == 14) { '
               'r = mk(); } if (c == 15) { r = mk(); } r.system(cmd); }\n'),
        "system", UNPROVEN),
}


# The origins of the command flow at each store row of BASE_CLEAN, LOSSES and GAPS
# and at every unproven row, spelled ``<class initial>:<role>`` and sorted.
ORIGINS: dict[str, tuple[str, ...]] = {
    "d_ts_import": ("u:param",),
    "d_js_param": ("u:param",),
    "d_js_param_request": ("e:request",),
    "d_ts_import_request": ("e:request",),
    "d_cpp_argv_external": ("e:argv", "u:argv"),
    "b_go_call_receiver": ("u:param",),
    "l1_go_dbjob_param": ("u:param",),
    "l2_go_bound_runner": ("u:param",),
    "l4_js_txn": ("u:param",),
    "l1_go_dbjob_request": ("e:request",),
    "l2_py_ssh_channel": ("e:request",),
    "l7_js_system": ("u:param",),
    "d_ts_ns_import_param": ("u:param",),
    "d_js_require_param": ("u:param",),
    "d_py_from_module_param": ("u:param",),
    "l7_js_argv": ("u:argv", "u:unresolved"),
    "l7_py_module_alias": ("u:param",),
    "l7_py_dunder_import": ("u:param",),
    "l7_py_importlib": ("u:param",),
    "l7_py_ctypes": ("u:param",),
    "l7_rs_self_type": ("u:param",),
    "l1_go_taskexec_request": ("e:request",),
    "lhint_js_store_argv": ("u:argv", "u:unresolved"),
    "g_php_quote": ("e:request",),
    "g_py_shell_quote_store": ("e:request",),
    "s_go_loop_constants": ("e:request",),
    "e5_system_16_defs": ("u:param",),
}

TABLES: dict[str, dict[str, Row]] = {
    "WS_S_TEXT": WS_S_TEXT,
    "WS_S_STORE": WS_S_STORE,
    "WS_S_STAYS_PROCESS": WS_S_STAYS_PROCESS,
    "CAPS": CAPS,
    "WS_A_TYPE": WS_A_TYPE,
    "WS_A_BIND": WS_A_BIND,
    "WS_A_TX": WS_A_TX,
    "WS_C": WS_C,
    "WS_D": WS_D,
    "STILL_SINK": STILL_SINK,
    "E_BASE": E_BASE,
    "BASE_CLEAN": BASE_CLEAN,
    "LOSSES": LOSSES,
    "MISLABELS": MISLABELS,
    "GAPS": GAPS,
    "E5": E5,
}
ROWS: dict[str, Row] = {name: row for table in TABLES.values() for name, row in table.items()}


def _of_class(tables: Iterable[dict[str, Row]], cls: str | None) -> list[str]:
    """The names of the rows of ``tables`` whose class is ``cls``, in table order."""
    return [name for table in tables for name, (_, _, found) in table.items() if found == cls]


NO_CLASS = _of_class(TABLES.values(), None)


def _site(model: FileModel, calls: Any, key: str) -> int:
    """The one CALL whose glued key is ``key``."""
    found = [node for node in model.nodes(Kind.CALL) if calls.key(node) == key]
    assert len(found) == 1, (key, found)
    return found[0]


def _command_flows(row: Row) -> list[Any]:
    """The ``command`` candidates whose sink is the row's call."""
    spec, key, _ = row
    model = subject(spec)
    site = _site(model, Engine(model).calls, key)
    return [flow for flow in candidates_of(model, "command") if flow.sink == site]


def _origins(row: Row) -> tuple[str, ...]:
    """The origins of the row's command flows, each ``<class initial>:<role>``, sorted."""
    flows = _command_flows(row)
    return tuple(sorted({f"{o.cls[0]}:{o.role}" for flow in flows for o in flow.origins}))


def _assert_class(row: Row) -> None:
    """The one call with the row's key has the row's class. The site is found first, so a
    malformed row fails on its own assertion, never behind a missing ``command_class``."""
    spec, key, want = row
    model = subject(spec)
    calls = Engine(model).calls
    site = _site(model, calls, key)
    assert calls.command_class(site) == want


# ── the rows ──


def test_every_row_is_in_exactly_one_table() -> None:
    assert sum(map(len, TABLES.values())) == len(ROWS) == 126


def test_every_table_has_a_class_test() -> None:
    assert all(callable(globals().get(f"test_{table.lower()}_class")) for table in TABLES)


@pytest.mark.parametrize("name", list(WS_S_TEXT))
def test_ws_s_text_class(name: str) -> None:
    _assert_class(WS_S_TEXT[name])


@pytest.mark.parametrize("name", list(WS_S_STORE))
def test_ws_s_store_class(name: str) -> None:
    _assert_class(WS_S_STORE[name])


@pytest.mark.parametrize("name", list(WS_S_STAYS_PROCESS))
def test_ws_s_stays_process_class(name: str) -> None:
    _assert_class(WS_S_STAYS_PROCESS[name])


@pytest.mark.parametrize("name", list(CAPS))
def test_caps_class(name: str) -> None:
    _assert_class(CAPS[name])


@pytest.mark.parametrize("name", list(WS_A_TYPE))
def test_ws_a_type_class(name: str) -> None:
    _assert_class(WS_A_TYPE[name])


@pytest.mark.parametrize("name", list(WS_A_BIND))
def test_ws_a_bind_class(name: str) -> None:
    _assert_class(WS_A_BIND[name])


@pytest.mark.parametrize("name", list(WS_A_TX))
def test_ws_a_tx_class(name: str) -> None:
    _assert_class(WS_A_TX[name])


@pytest.mark.parametrize("name", list(WS_C))
def test_ws_c_class(name: str) -> None:
    _assert_class(WS_C[name])


@pytest.mark.parametrize("name", list(WS_D))
def test_ws_d_class(name: str) -> None:
    _assert_class(WS_D[name])


@pytest.mark.parametrize("name", list(STILL_SINK))
def test_still_sink_class(name: str) -> None:
    _assert_class(STILL_SINK[name])


@pytest.mark.parametrize("name", list(E_BASE))
def test_e_base_class(name: str) -> None:
    _assert_class(E_BASE[name])


@pytest.mark.parametrize("name", list(BASE_CLEAN))
def test_base_clean_class(name: str) -> None:
    _assert_class(BASE_CLEAN[name])


@pytest.mark.parametrize("name", list(LOSSES))
def test_losses_class(name: str) -> None:
    _assert_class(LOSSES[name])


@pytest.mark.parametrize("name", list(MISLABELS))
def test_mislabels_class(name: str) -> None:
    _assert_class(MISLABELS[name])


@pytest.mark.parametrize("name", list(GAPS))
def test_gaps_class(name: str) -> None:
    _assert_class(GAPS[name])


@pytest.mark.parametrize("name", list(E5))
def test_e5_class(name: str) -> None:
    _assert_class(E5[name])


@pytest.mark.parametrize("name", list(STILL_SINK))
def test_still_sink_keeps_a_command_flow(name: str) -> None:
    assert _command_flows(STILL_SINK[name])


@pytest.mark.parametrize("name", NO_CLASS)
def test_no_class_has_no_command_flow(name: str) -> None:
    assert _command_flows(ROWS[name]) == []


def test_origin_rows_are_the_store_base_clean_losses_gaps_and_every_unproven_row() -> None:
    store = _of_class((BASE_CLEAN, LOSSES, GAPS), STORE)
    unproven = _of_class(TABLES.values(), UNPROVEN)
    assert set(ORIGINS) == {*store, *unproven}


@pytest.mark.parametrize("name", list(ORIGINS))
def test_flow_origins(name: str) -> None:
    assert _origins(ROWS[name]) == ORIGINS[name]


# ── the lexicon (LLD B2: subset pins, never equality with a whole set) ──


def test_transaction_words_name_a_data_store() -> None:
    assert {"tx", "txn", "transaction"} <= roles_mod().DATA_STORE_WORDS


def test_system_is_a_command_receiver_bound_key() -> None:
    bound = sink_table("COMMAND_RECEIVER_BOUND_KEYS")
    assert "system" in bound
    assert bound <= roles_mod().COMMAND_STRONG


# ── the caps (limits.py; each cap + 1 is a CAPS row) ──


@pytest.mark.parametrize(("name", "cap"), [("MAX_SPINE", 8), ("MAX_STATEMENT_HEAD", 160)])
def test_statement_text_cap(name: str, cap: int) -> None:
    assert required("limits", name) == cap


# ── the language fact (§4.7) ──


def test_value_imports_is_javascript_typescript_and_python() -> None:
    found = {profile.language for profile in PROFILES.values() if profile.value_imports}
    assert found == {"javascript", "typescript", "python"}


# ── the answer schema and the command_class codec (§4.4) ──


def test_answer_schema_is_three() -> None:
    assert shared.ast.ANSWER_SCHEMA == 3


def _codec() -> Any:
    codec = required("answer", "_CODECS").get("command_class")
    assert codec is not None, "answer._CODECS has no command_class"
    return codec


def _bounds() -> Any:
    """What a reader is handed beside the value: a command family answer's bounds."""
    return required("answer", "_Bounds")(family="command", size=1, lines=1, shared={})


@pytest.mark.parametrize(
    "value", ["", UNPROVEN, TEXT, STORE], ids=["empty", UNPROVEN, TEXT, STORE]
)
def test_command_class_codec_round_trips(value: str) -> None:
    codec = _codec()
    assert codec.read(codec.write(value), _bounds()) == value


@pytest.mark.parametrize("value", ["x", 1])
def test_command_class_codec_refuses(value: object) -> None:
    codec = _codec()
    with pytest.raises(ModelError):
        codec.read(value, _bounds())


# ── E4's table (§4.5): Flow.command_class x origins -> (process_flow, statement_flow) ──

E4: list[tuple[str, str, str, tuple[bool, bool]]] = [
    ("process-external", "", "external", (True, False)),
    ("process-parameter", "", "parameter", (True, False)),
    ("process-hint", "", "hint", (True, False)),
    ("unproven-external", UNPROVEN, "external", (True, False)),
    ("unproven-parameter", UNPROVEN, "parameter", (False, False)),
    ("unproven-hint", UNPROVEN, "hint", (False, False)),
    ("text-external", TEXT, "external", (False, True)),
    ("text-parameter", TEXT, "parameter", (False, True)),
    ("text-hint", TEXT, "hint", (False, True)),
    ("store-external", STORE, "external", (False, True)),
    ("store-parameter", STORE, "parameter", (False, False)),
    ("store-hint", STORE, "hint", (False, False)),
]


def _origin_set(name: str) -> tuple[Any, ...]:
    """A real external origin, a parameter, or R-T's hint alone (no real external origin)."""
    sets = {"external": (external("request"),), "parameter": (unknown("param"),),
            "hint": (external(HINT),)}
    return sets[name]


@pytest.mark.parametrize(("cls", "origins", "want"), cases(E4))
def test_e4_table(cls: str, origins: str, want: tuple[bool, bool]) -> None:
    consume = consume_mod()
    flow = dataclasses.replace(flow_with("command", *_origin_set(origins)), command_class=cls)
    assert (consume.process_flow(flow), consume.statement_flow(flow)) == want


# ── the parse worker's safety (B5) ──

_NO_TOOLS = (
    "import sys, shared.ast.sql_shape; "
    "assert not [m for m in sys.modules if m.startswith('shared.tools')]"
)


def test_sql_shape_loads_no_tools_module(tmp_path: Path) -> None:
    path = os.pathsep.join(map(str, (SHARED_ROOT, SHARED_ROOT.parent / "cwe")))
    done = subprocess.run(
        [sys.executable, "-c", _NO_TOOLS], cwd=tmp_path, env={**os.environ, "PYTHONPATH": path},
        capture_output=True, text=True, timeout=budget(30.0), check=False,
    )
    assert done.returncode == 0, done.stderr
