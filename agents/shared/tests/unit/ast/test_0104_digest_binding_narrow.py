"""Feature 0104 WS-D (D-S (6), detection rate first): only a BINDING of ``hash`` lifts the digest.

Rule (D-S (6)). ``Calls.binds_name`` lifts the digest rule (``hash`` / ``hexdigest`` are numeric
digest keys) when the file binds the name itself. The D-P (1) spellings read three shapes too
widely, so a file whose ``hash`` is IMPORTED -- a real digest -- loses the rule and a request
value it carries into a path sink reports, where aec5910e kept it sanitised:

* a keyword argument whose value is a constant (``field(hash=False)``, ``make(hash="sha256")``,
  ``dict(hash=0)``) names an option, not a value of the file's own ``hash``;
* a struct field whose type is no function (Go ``Hash string``, Rust ``hash: String``) holds
  data: a call of ``hash`` cannot be a call of it;
* a method merely NAMED ``setattr`` / ``defineProperty`` on a receiver the file binds (a local,
  a parameter's member: ``view.setattr("title", "hash")``,
  ``res.locals.view.defineProperty(o, "hash", d)``) is that object's own API, not the
  language's reflective binder.

RED until the fix lands: each of those reports on the working tree; none does on aec5910e.

Pinned, detection first (each reports today and must keep reporting): a keyword whose value is a
function, a lambda, an attribute or a call (``make(hash=lambda s: s)``,
``make(hash=helpers.join)``); a Go or Rust struct field of a function type; the free
``setattr(obj, "hash", fn)``; ``Object.defineProperty`` and ``Reflect.defineProperty`` on the
language global the file does not bind. On aec5910e none of these pins reports: each reports
only through the binding D-P (1) added, so each holds that binding in place.
``test_0104_digest_bindings.py`` holds the D-P (1) spellings themselves (run it beside this
module as the regression); and each RED program, renamed, reports -- the flow is found, so only
the digest rule silences it.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast.test_0102_precision_a44 import _reported
from tests.unit.ast.test_0104_digest_bindings import Program, _renamed

pytestmark = pytest.mark.usefixtures("real_pool")

# ── an imported ``hash`` beside a shape that binds no ``hash`` of the file's own ──

_FIELD_FALSE_PY: Program = ("py", """
    import os
    from dataclasses import dataclass, field

    from flask import request
    from naming import hash

    ROOT = "/srv/shelf"


    @dataclass
    class Entry:
        name: str
        tags: list = field(default_factory=list, hash=False)


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_STRING_KW_PY: Program = ("py", """
    import os

    from flask import request
    from naming import hash, make_digest

    ROOT = "/srv/shelf"
    checksum = make_digest(hash="sha256")


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_NUMBER_KW_PY: Program = ("py", """
    import os

    from flask import request
    from naming import hash

    ROOT = "/srv/shelf"
    counts = dict(hash=0, size=0)


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_DATA_FIELD_GO: Program = ("go", """
    package svc

    import (
        "net/http"
        "os"
        "path/filepath"

        "example.com/shelf/naming"
    )

    type Commit struct {
        Hash string
    }

    func Shelf(w http.ResponseWriter, r *http.Request) {
        data, _ := os.ReadFile(filepath.Join("/srv/shelf", naming.Hash(r.FormValue("name"))))
        w.Write(data)
    }
""")
_DATA_FIELD_RS: Program = ("rs", """
    use naming::hash;

    const ROOT_DIR: &str = "/srv/docs";

    struct Commit {
        hash: String,
    }

    #[derive(Deserialize)]
    struct DocQuery {
        file: String,
    }

    async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
        fs::read_to_string(Path::new(ROOT_DIR).join(hash(&q.file)))
    }
""")
_SETATTR_METHOD_JS: Program = ("js", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";
    export function get(req, res) {
      const view = res.locals.view;
      view.setattr("title", "hash");
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
_DEFINE_METHOD_JS: Program = ("js", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";
    export function get(req, res) {
      const o = {};
      const d = { enumerable: true };
      res.locals.view.defineProperty(o, "hash", d);
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")

# (case, program, the path sink CALL's head): none reports, as on aec5910e
OVER_BOUND: list[tuple[str, Program, str]] = [
    ("py dataclass field(hash=False)", _FIELD_FALSE_PY, "open"),
    ("py keyword hash='sha256'", _STRING_KW_PY, "open"),
    ("py keyword hash=0", _NUMBER_KW_PY, "open"),
    ("go struct field Hash string", _DATA_FIELD_GO, "os.ReadFile"),
    ("rust struct field hash: String", _DATA_FIELD_RS, "fs::read_to_string"),
    ("js view.setattr method", _SETATTR_METHOD_JS, "fs.readFileSync"),
    ("js res.locals.view.defineProperty method", _DEFINE_METHOD_JS, "fs.readFileSync"),
]

# ── the file binds ``hash`` itself by a narrow shape: detection first, it reports ──

# A factory that makes an object of its keywords (``_FACTORY_KW_PY``'s shape): a ``make(hash=v)``
# value is reached as ``layout.hash``, through no binding the file spells otherwise.
_MAKE_PY = """
    class Layout:
        def __init__(self, **parts):
            self.__dict__.update(parts)


    def make(**parts):
        return Layout(**parts)
"""


def _with_make(head: str, tail: str) -> Program:
    """A Python program: ``head`` (imports), the ``make`` factory (``_MAKE_PY``), ``tail``."""
    return "py", f"{head}{_MAKE_PY}{tail}"


_LAMBDA_KW_PY: Program = _with_make("""
    import os

    from flask import request
""", """

    layout = make(hash=lambda n: os.path.join("/srv/shelf", n))


    def shelf():
        with open(layout.hash(request.args["name"])) as fh:
            return fh.read()
""")
_FUNCTION_KW_PY: Program = _with_make("""
    import os

    from flask import request
""", """

    def under_shelf(n):
        return os.path.join("/srv/shelf", n)


    layout = make(hash=under_shelf)


    def shelf():
        with open(layout.hash(request.args["name"])) as fh:
            return fh.read()
""")
_ATTRIBUTE_KW_PY: Program = _with_make("""
    import helpers
    from flask import request
""", """

    layout = make(hash=helpers.join)


    def shelf():
        with open(layout.hash("/srv/shelf", request.args["name"])) as fh:
            return fh.read()
""")
_CALL_KW_PY: Program = _with_make("""
    import functools
    import os

    from flask import request
""", """

    layout = make(hash=functools.partial(os.path.join, "/srv/shelf"))


    def shelf():
        with open(layout.hash(request.args["name"])) as fh:
            return fh.read()
""")
_FN_FIELD_RS: Program = ("rs", """
    use shelf::make_layout;

    struct Layout {
        hash: fn(&str, &str) -> PathBuf,
    }

    #[derive(Deserialize)]
    struct DocQuery {
        file: String,
    }

    async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
        let lay: Layout = make_layout();
        fs::read_to_string((lay.hash)("/srv/docs", &q.file))
    }
""")
_REFLECT_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = {};
    Reflect.defineProperty(layout, "hash", { value: path.join });
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_SETATTR_CMD_PY: Program = ("py", """
    import subprocess

    from flask import request


    class Runner:
        pass


    runner = Runner()
    setattr(runner, "hash", "tar -czf /tmp/out.tgz {}".format)


    def pack():
        subprocess.run(runner.hash(request.args["name"]), shell=True)
        return "ok"
""")
_DEFINE_CMD_JS: Program = ("js", """
    const { exec } = require("child_process");
    const util = require("util");
    const runner = {};
    Object.defineProperty(runner, "hash", { value: util.format });
    exports.pack = function (req, res) {
      exec(runner.hash("tar -czf /tmp/out.tgz %s", req.query.name), () => res.end());
    };
""")
_FN_FIELD_CMD_GO: Program = ("go", """
    package svc

    import (
        "fmt"
        "net/http"
        "os/exec"
    )

    type runner struct {
        hash func(string, ...any) string
    }

    var run = runner{fmt.Sprintf}

    func Pack(w http.ResponseWriter, r *http.Request) {
        exec.Command("sh", "-c", run.hash("tar -czf /tmp/out.tgz %s", r.FormValue("name"))).Run()
    }
""")
_REFLECT_REQ_JS: Program = ("js", """
    const axios = require("axios");
    const util = require("util");
    const probe = {};
    Reflect.defineProperty(probe, "hash", { value: util.format });
    exports.status = async function (req, res) {
      const r = await axios.get(probe.hash("http://%s/status", req.query.host));
      res.send(r.data);
    };
""")
_ATTRIBUTE_KW_REQ_PY: Program = _with_make("""
    import requests
    from flask import request
""", """

    probe = make(base="http://", hash="{}{}/status".format)


    def status():
        return requests.get(probe.hash(probe.base, request.args["host"])).text
""")

# (case, program, family, the sink CALL's head): each reports, and must keep reporting
NARROW_BINDINGS: list[tuple[str, Program, str, str]] = [
    ("py keyword = lambda", _LAMBDA_KW_PY, "path", "open"),
    ("py keyword = a local function", _FUNCTION_KW_PY, "path", "open"),
    ("py keyword = helpers.join", _ATTRIBUTE_KW_PY, "path", "open"),
    ("py keyword = functools.partial(...)", _CALL_KW_PY, "path", "open"),
    ("rust struct field hash: fn(..)", _FN_FIELD_RS, "path", "fs::read_to_string"),
    ("js Reflect.defineProperty", _REFLECT_JS, "path", "fs.readFileSync"),
    ("command: py free setattr", _SETATTR_CMD_PY, "command", "subprocess.run"),
    ("command: js Object.defineProperty", _DEFINE_CMD_JS, "command", "exec"),
    ("command: go struct field hash func(..)", _FN_FIELD_CMD_GO, "command", "exec.Command"),
    ("request: js Reflect.defineProperty", _REFLECT_REQ_JS, "request", "axios.get"),
    ("request: py keyword = attribute", _ATTRIBUTE_KW_REQ_PY, "request", "requests.get"),
]


def _renamed_any_case(spec: Program) -> Program:
    """``_renamed``, and every ``Hash`` spelled ``Arrange`` (Go exports a capitalised name)."""
    lang, source = _renamed(spec)
    return lang, source.replace("Hash", "Arrange")


@pytest.mark.parametrize(("spec", "head"), cases(OVER_BOUND))
def test_digest_rule_holds_beside_a_shape_that_binds_no_hash(spec: Program, head: str) -> None:
    """RED: the imported ``hash`` is a digest; the shape beside it binds no ``hash`` itself."""
    assert _reported(spec, "path", head) is False


@pytest.mark.parametrize(("spec", "head"), cases(OVER_BOUND))
def test_over_bound_programs_renamed_report(spec: Program, head: str) -> None:
    """Pin: renamed, each RED program reports: the flow is found, only the digest silences it."""
    assert _reported(_renamed_any_case(spec), "path", head) is True


@pytest.mark.parametrize(("spec", "family", "head"), cases(NARROW_BINDINGS))
def test_narrow_bindings_keep_reporting(spec: Program, family: str, head: str) -> None:
    """Pin: the file binds ``hash`` itself to a function, so the digest rule stays lifted."""
    assert _reported(spec, family, head) is True
