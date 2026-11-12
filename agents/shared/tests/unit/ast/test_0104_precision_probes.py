"""Feature 0104 WS-C (LLD §4.3; D-N (1); A49, A54 protoKS4): a bare existence probe of an
entry's hinted parameter is no request path.

Rule. A ``path`` flow that ``decide`` would report is declined, with the recorded label
``probe:param_hint`` (OD-12; after ``sanitized:`` and ``guarded:``, so a guarded probe keeps its
label), when all of these hold:

1. it is hint-only (``flow.hint_only``, HT-7);
2. its sink key is a probe: ``path_sink_key(sink_key)`` in ``roles.PROBE_PATH_KEYS``
   (``exists``, ``access``, ``stat``, ``lstat``, ``isfile``, ``isdir``; sync twins by A44 (1));
3. ``Flow.bare_path_arg``: computed in the BASE context only, in a JS/TS file only, and true
   only when the argument is the hinted parameter ITSELF -- every reaching Def a hint-named
   PARAM -- that parameter is a bare identifier (a destructured or rest parameter, the shape
   frameworks deliver request data in, starts its slot before the name), and every same-file
   use of the function's name is its declaration, an export listing or a call the call graph
   resolves (the second skeptic's R-C1: an instance, static or object method call, ``.call``
   / ``.apply``, a callback reference keep the flow).

The bit is the fifth element of the ``_add`` key, so a base flow and a summary flow with equal
origins stay two flows: a same-file caller that composes the path keeps its own row
(``c_collide_tpl``). ``bare_path_arg`` crosses the worker wire (``answer._CODECS``), so
``ANSWER_SCHEMA`` is 2. Its default False keeps today's verdict everywhere else.

Accepted losses (``test_0104_known_gaps.py``): the cross-file existence oracle incl. the JS
serve-file helpers, K5 t7, C-R1 (a ``"use server"`` export's bare positional probe).

RED until C lands: the cleans, the decline label, the key bit, the codec, the schema and the
table. Green today, and kept: every composed argument, every other language, every unresolved
same-file use, every destructured parameter, a guarded probe's label, a content read.
"""

from __future__ import annotations

import pytest

import shared.ast
from shared.ast._frames import ModelError
from tests.unit.ast._0104 import HINT, PROBE, cases, field_of, required, sink_table
from tests.unit.ast._analysis import (
    PATH_CONTAIN,
    Spec,
    decided,
    external,
    flow_with,
    flows_at_call,
    judge,
    roles_mod,
    subject,
    verdicts_at,
)
from tests.unit.ast.test_0102_precision_a44 import _reported
from tests.unit.ast.test_0102_roles import ENTRY, violations

pytestmark = pytest.mark.usefixtures("real_pool")

BARE = "bare_path_arg"
PROBE_KEYS = frozenset({"exists", "access", "stat", "lstat", "isfile", "isdir"})


def _ts(body: str) -> Spec:
    return "ts", 'import fs from "node:fs";\nimport path from "node:path";\n\n' + body


# ── declined: the hinted parameter itself, at a probe, in an entry nothing else uses ──

_STAT: Spec = _ts("""export function isFresh(filePath: string, maxAge: number): boolean {
  return Date.now() - fs.statSync(filePath).size < maxAge;
}
""")
_EXISTS: Spec = _ts("""export function present(filePath: string): boolean {
  return fs.existsSync(filePath);
}
""")
_ACCESS: Spec = ("js", """
    const fs = require("node:fs");

    function readable(fileName) {
      fs.accessSync(fileName, fs.constants.R_OK);
      return true;
    }

    module.exports = { readable };
""")
_LSTAT: Spec = ("js", """
    const fs = require("node:fs");

    exports.folder = function (filePath) {
      return fs.lstatSync(filePath).isDirectory();
    };
""")
_RESOLVED_CALLER: Spec = _ts("""export function present(filePath: string): boolean {
  return fs.existsSync(filePath);
}

export function presentDefault(): boolean {
  return present("defaults.json");
}
""")

DECLINED: list[tuple[str, Spec, str]] = [
    ("statSync", _STAT, "fs.statSync"),
    ("existsSync", _EXISTS, "fs.existsSync"),
    ("accessSync, a module.exports listing", _ACCESS, "fs.accessSync"),
    ("lstatSync, an exports.f function", _LSTAT, "fs.lstatSync"),
    ("a same-file call the call graph resolves", _RESOLVED_CALLER, "fs.existsSync"),
]


@pytest.mark.parametrize(("spec", "head"), cases(DECLINED))
def test_bare_probe_is_not_reported(spec: Spec, head: str) -> None:
    assert not _reported(spec, "path", head)


@pytest.mark.parametrize(("spec", "head"), cases(DECLINED))
def test_bare_probe_declines_with_its_label(spec: Spec, head: str) -> None:
    """OD-12 / A49: a recorded decline, one per silenced flow, never a silent ``none``."""
    model = subject(spec)
    assert verdicts_at(model, "path", head) == PROBE
    assert judge(model, "path").declines.count(PROBE) == 1


def test_bare_bit_marks_the_base_flow() -> None:
    flows = flows_at_call(subject(_EXISTS), "path", "fs.existsSync")
    assert [field_of(flow, BARE) for flow in flows] == [True]


# ── kept: everything else still reports ──

_JOIN: Spec = _ts("""export function present(fileName: string): boolean {
  return fs.existsSync(path.join("/srv/vault", fileName));
}
""")
_CONCAT: Spec = _ts("""export function present(fileName: string): boolean {
  return fs.existsSync("/srv/vault/" + fileName);
}
""")
_TEMPLATE: Spec = _ts("""export function present(fileName: string): boolean {
  return fs.existsSync(`/srv/vault/${fileName}`);
}
""")
_AWAIT: Spec = _ts("""export async function weigh(filePath: string) {
  const full = await fs.promises.realpath(path.join("/srv/vault", filePath));
  return (await fs.promises.stat(full)).size;
}
""")
_TERNARY: Spec = _ts("""export function present(fileName: string): boolean {
  const target = path.isAbsolute(fileName) ? fileName : path.join("/srv/vault", fileName);
  return fs.existsSync(target);
}
""")
_AUG: Spec = _ts("""export function present(fileName: string): boolean {
  let target = "/srv/vault/";
  target += fileName;
  return fs.existsSync(target);
}
""")
_MEMBER_OF_CALL: Spec = _ts("""export function present(fileName: string): boolean {
  return fs.existsSync(new URL(fileName, "file:///srv/vault/").pathname);
}
""")
_CHAIN_BASE: Spec = _ts("""export function present(fileName: string): boolean {
  const parsed = path.parse(path.join("/srv/vault", fileName));
  return fs.existsSync(parsed.dir);
}
""")
_DESTRUCTURED: Spec = _ts("""export function present({ filePath }: { filePath: string }): boolean {
  return fs.existsSync(filePath);
}
""")
_CALL_REFERENCE: Spec = ("js", """
    const fs = require("fs");
    const app = require("express")();

    function checkPath(filePath) {
      return fs.existsSync(filePath);
    }

    app.get("/a", (req, res) => res.json(checkPath.call(null, req.query.p)));
    module.exports = app;
""")
_CALLBACK_REFERENCE: Spec = ("js", """
    const fs = require("fs");
    const app = require("express")();

    function pathPresent(filePath) {
      return fs.existsSync(filePath);
    }

    app.post("/many", (req, res) => res.json(req.body.paths.map(pathPresent)));
    module.exports = app;
""")
_CONTENT: Spec = _ts("""export function sheetText(filePath: string): string {
  return fs.readFileSync(filePath, "utf8");
}
""")
_PYTHON: Spec = ("py", """
    import os


    def present(file_path):
        return os.path.exists(file_path)
""")
_GO: Spec = ("go", """
    package svc

    import "os"

    func Present(filePath string) bool {
    	_, err := os.Stat(filePath)
    	return err == nil
    }
""")
_JAVA: Spec = ("java", """
    import java.io.File;

    public class Probe {
        public static boolean present(String filePath) {
            return new File(filePath).exists();
        }
    }
""")

KEPT: list[tuple[str, Spec, str]] = [
    ("a join (CALL)", _JOIN, "fs.existsSync"),
    ("a concatenation (BINOP)", _CONCAT, "fs.existsSync"),
    ("a template", _TEMPLATE, "fs.existsSync"),
    ("an awaited call", _AWAIT, "fs.promises.stat"),
    ("a ternary over a call", _TERNARY, "fs.existsSync"),
    ("an augmented assignment", _AUG, "fs.existsSync"),
    ("a member of a call", _MEMBER_OF_CALL, "fs.existsSync"),
    ("a chain base bound to a call", _CHAIN_BASE, "fs.existsSync"),
    ("a destructured parameter", _DESTRUCTURED, "fs.existsSync"),
    ("an unresolved .call use", _CALL_REFERENCE, "fs.existsSync"),
    ("a callback reference", _CALLBACK_REFERENCE, "fs.existsSync"),
    ("a content read", _CONTENT, "fs.readFileSync"),
    ("python", _PYTHON, "os.path.exists"),
    ("go", _GO, "os.Stat"),
    ("java", _JAVA, "new File(filePath).exists"),
]


@pytest.mark.parametrize(("spec", "head"), cases(KEPT))
def test_other_flows_keep_reporting(spec: Spec, head: str) -> None:
    assert _reported(spec, "path", head)
    assert all(field_of(f, BARE) is not True for f in flows_at_call(subject(spec), "path", head))


def test_a_guarded_bare_probe_keeps_its_guard_label() -> None:
    spec = _ts("""export function hasCrate(filePath: string): boolean {
  if (!filePath.startsWith("/srv/crates")) {
    throw new Error("outside the crate root");
  }
  return fs.existsSync(filePath);
}
""")
    assert verdicts_at(subject(spec), "path", "fs.existsSync") == PATH_CONTAIN


_COLLIDE: Spec = _ts("""export function crateFound(filePath: string): boolean {
  return fs.existsSync(filePath);
}

export async function crateExists(fileName: string) {
  return crateFound(`/srv/crates/${fileName}`);
}
""")


def test_base_and_summary_flows_stay_two() -> None:
    """The key bit: the caller's composed path is a flow of its own, which reports."""
    flows = flows_at_call(subject(_COLLIDE), "path", "fs.existsSync")
    assert sorted(field_of(f, BARE) is True for f in flows) == [False, True]
    assert _reported(_COLLIDE, "path", "fs.existsSync")


def test_default_bit_leaves_decide_unchanged() -> None:
    """Polarity: a flow built without the bit (``flow_with``) decides as before."""
    assert decided(flow_with("path", external(HINT)), "path")[0] == "report"


# ── the wire and the table ──


def test_codec_round_trips_the_bit_and_refuses_an_int() -> None:
    codec = required("answer", "_CODECS").get(BARE)
    assert codec is not None, "answer._CODECS has no bare_path_arg"
    assert codec.read(codec.write(True), None) is True
    with pytest.raises(ModelError):
        codec.read(1, None)


def test_answer_schema_is_two() -> None:
    assert shared.ast.ANSWER_SCHEMA == 2


def test_probe_path_keys_are_exact() -> None:
    assert sink_table("PROBE_PATH_KEYS") == PROBE_KEYS


def test_new_tables_are_generic() -> None:
    """HT-5: concept words a path sink key is spelled with, each a path sink key itself."""
    keys = sink_table("PROBE_PATH_KEYS")
    assert keys <= roles_mod().SINK_WORDS["path"]
    assert violations(keys, ENTRY.fullmatch) == []
