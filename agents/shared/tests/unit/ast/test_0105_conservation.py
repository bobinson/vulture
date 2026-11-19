"""Feature 0105 (LLD §5.2): a statement prefix never takes a command sink away.

Metamorphic and generated. Each of the 20 sinks below is a command sink of a language with a
concatenation operator (Go, JavaScript, TypeScript, Python, Java: ``+``; PHP: ``.``). Its
TAINTED argument (the one the row names: for ``exec.Command("sh", "-c", x)`` it is ``x``,
never the interpreter literal) is replaced by ``<opener literal> <join> <argument>``, for each
SQL opener of ``OPENERS``: 100 pairs. Each pair gets two tests:

* the flow half: a ``command`` flow still reaches the call;
* the class half: ``Calls.command_class`` of the call is not None (the site stays a command
  site), and every such flow is accepted by a rule, through LLD E4's table
  (``consume.process_flow`` for CWE-78 or ``consume.statement_flow`` for CWE-89; the flow's
  ``command_class`` field carries its site's class), so a narrowing can never hide a row here.

C, C++ and Rust are not generated: their concatenation is a call, so no prefix makes statement
text. Measured on the 0105 prototype with every piece on: 85 pairs ``process`` (CWE-78), 15
``text`` (``remote.exec``, ``runner.exec``, Java ``r.exec``: CWE-89), none without a class, and
every flow accepted. The class is not pinned here: every pair is ``process`` from P4 until P6
adds ``text``, and the file is green from P4 on.

The flow half is green at RED: the base already keeps every pair's flow, so a piece that dropped
one fails it. The class half is RED until P4: ``Calls.command_class`` lands at P4 (the two
``consume`` readers at P3). Each is reached only from a test body, so its absence fails each
test instead of the collection.
"""

from __future__ import annotations

from itertools import filterfalse
from typing import Any, NamedTuple

import pytest

from shared.ast import FileModel
from shared.ast._origins import Engine
from tests.unit.ast._analysis import Spec, candidates_of, subject

pytestmark = pytest.mark.usefixtures("real_pool")


class Row(NamedTuple):
    """A command sink: its language code, its source with ``{A}`` at the tainted argument,
    that argument, and the call's glued key."""

    lang: str
    source: str
    arg: str
    key: str


GO = 'package m\nimport "net/http"\n'
OPENERS = (
    "DELETE FROM t WHERE id = ", "INSERT INTO t VALUES (", "UPDATE t SET a = ",
    "SELECT a FROM t WHERE b = ", "DROP TABLE ",
)
# How a language joins the opener literal to the argument.
JOIN = {
    "go": '"{o}" + {a}', "js": '"{o}" + {a}', "ts": '"{o}" + {a}', "py": '"{o}" + {a}',
    "java": '"{o}" + {a}', "php": '"{o}" . {a}',
}
ROWS = {
    "go_sh_c": Row(
        "go",
        GO + 'import "os/exec"\n'
        'func f(r *http.Request) { exec.Command("sh", "-c", {A}).Run() }\n',
        'r.FormValue("c")', "command",
    ),
    "go_syscall": Row(
        "go",
        GO + 'import "syscall"\nfunc f(p string, a []string) { syscall.Exec({A}, a, nil) }\n',
        "p", "exec",
    ),
    "go_cgo": Row(
        "go",
        'package m\n// #include <stdlib.h>\nimport "C"\nimport "net/http"\n'
        "func f(r *http.Request) { C.system(C.CString({A})) }\n",
        'r.FormValue("c")', "system",
    ),
    "go_pkg_noword": Row(
        "go",
        GO + 'import "example.com/x/util"\nfunc f(r *http.Request) { util.System({A}) }\n',
        'r.FormValue("c")', "system",
    ),
    "js_cp": Row(
        "js",
        'const cp = require("child_process");\nfunction f(req) { cp.exec({A}); }\n',
        "req.query.cmd", "exec",
    ),
    "js_remote": Row(
        "js", "function f(remote, cmd) { remote.exec({A}); }\n", "cmd", "exec",
    ),
    "ts_runner": Row(
        "ts",
        "export function f(runner: ChildProcessRunner, cmd: string) { runner.exec({A}); }\n",
        "cmd", "exec",
    ),
    "java_runtime": Row(
        "java",
        "class A { void f(String cmd) throws Exception "
        "{ Runtime r = Runtime.getRuntime(); r.exec({A}); } }\n",
        "cmd", "exec",
    ),
    "java_type_import": Row(
        "java",
        "import com.acme.Palette;\n"
        "class A { String f(String t) { return Palette.system({A}); } }\n",
        "t", "system",
    ),
    "java_import_static": Row(
        "java",
        "import static com.acme.Ui.palette;\n"
        "class A { void f(String t) { palette.system({A}); } }\n",
        "t", "system",
    ),
    "js_local_class": Row(
        "js",
        "class Runner { static system(c) { return c; } }\n"
        "function f(cmd) { Runner.system({A}); }\n",
        "cmd", "system",
    ),
    "py_popen": Row(
        "py", "import subprocess\ndef f(cmd):\n    subprocess.Popen({A}, shell=True)\n",
        "cmd", "popen",
    ),
    "py_os": Row("py", "import os\ndef f(c):\n    os.system({A})\n", "c", "system"),
    "py_os_as": Row("py", "import os as o\ndef f(c):\n    o.system({A})\n", "c", "system"),
    "py_posix": Row("py", "import posix\ndef f(c):\n    posix.system({A})\n", "c", "system"),
    "py_shell_param": Row("py", "def f(shell, c):\n    shell.system({A})\n", "c", "system"),
    "py_from_os": Row(
        "py", "from os import system\ndef f(c):\n    system({A})\n", "c", "system",
    ),
    "php_bare": Row("php", "<?php\nfunction f($cmd) { system({A}); }\n", "$cmd", "system"),
    "php_static": Row(
        "php", "<?php\nfunction f($c) { Runner::system({A}); }\n", "$c", "system",
    ),
    "php_use_static": Row(
        "php", "<?php\nuse App\\Runner;\nfunction f($c) { Runner::system({A}); }\n",
        "$c", "system",
    ),
}
PAIRS = [
    pytest.param(name, opener, id=f"{name}-{opener.split()[0]}")
    for name in ROWS for opener in OPENERS
]


def _program(name: str, opener: str) -> Spec:
    """Row ``name`` with its tainted argument prefixed by ``opener``."""
    row = ROWS[name]
    return row.lang, row.source.replace("{A}", JOIN[row.lang].format(o=opener, a=row.arg))


def _site(model: FileModel, calls: Any, key: str) -> int:
    """The first CALL whose glued key is ``key``: the row's sink."""
    return next(call for call in model.calls() if calls.key(call) == key)


def _flows_at(model: FileModel, site: int) -> list[Any]:
    """The ``command`` candidates whose sink is ``site``."""
    return [flow for flow in candidates_of(model, "command") if flow.sink == site]


def _pair(name: str, opener: str) -> tuple[FileModel, Any, int]:
    """The pair's model, its ``Calls`` and the row's sink."""
    model = subject(_program(name, opener))
    calls = Engine(model).calls
    return model, calls, _site(model, calls, ROWS[name].key)


@pytest.mark.parametrize(("name", "opener"), PAIRS)
def test_statement_prefix_keeps_a_command_flow(name: str, opener: str) -> None:
    model, _, site = _pair(name, opener)
    assert _flows_at(model, site), f"{name}: no command flow reaches the call"


@pytest.mark.parametrize(("name", "opener"), PAIRS)
def test_statement_prefix_keeps_the_command_class(name: str, opener: str) -> None:
    model, calls, site = _pair(name, opener)
    assert calls.command_class(site) is not None, f"{name}: the call lost its command class"
    flows = _flows_at(model, site)
    from shared.ast.consume import process_flow, statement_flow

    def accepted(flow: Any) -> bool:
        return process_flow(flow) or statement_flow(flow)

    assert list(filterfalse(accepted, flows)) == [], f"{name}: a flow no rule accepts"
