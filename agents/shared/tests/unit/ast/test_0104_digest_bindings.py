"""Feature 0104 WS-D rev 4 (LLD §4.4; D-P (1)): each spelling binds ``hash``.

Rule (D-P (1)). The digest rule is skipped whenever the FILE binds the name ``hash`` to anything
other than an import or a parameter. ``Calls.binds_name`` reads four shapes (a function's name,
an ASSIGN target's last identifier, an object or struct literal key that is a NAME, a class
field that is a NAME), so a file binding ``hash`` through any other spelling keeps the digest
rule, and a request value it carries is silenced at a path, command or request sink that the
pre-0104 base reports. The spellings: a quoted or computed object key, a quoted shorthand
method, a quoted class field or method (TS), a subscript assignment, ``Object.defineProperty``,
a keyword argument (Python), ``setattr``, ``globals()[...]`` and a Go struct literal that sets
a func-typed field ``hash`` by position.

RED until the fix lands: every spelling reports, as on the base. Green today, and kept:

* the same programs with ``hash`` renamed report -- the flow itself is found, so only the
  digest rule silences a spelling;
* an import (``from m import hash``, ``import { hash } from``) or a parameter named ``hash``
  stays a digest even beside the new spellings binding OTHER names, or holding ``hash`` (or the
  string ``"hash"``) as a VALUE: only a binding of the name itself lifts the rule.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast._analysis import Spec
from tests.unit.ast.test_0102_precision_a44 import _reported

pytestmark = pytest.mark.usefixtures("real_pool")

# An inline program, ``(lang code, source)``: the ``Spec`` shape ``_renamed`` rewrites.
Program = tuple[str, str]

# ── the file binds ``hash`` by a spelling ``binds_name`` misses: the flow still reaches ──

_QUOTED_KEY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = { "hash": path.join };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_COMPUTED_KEY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = { ["hash"]: path.join };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_QUOTED_METHOD_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = {
      'hash'(n) {
        return path.join("/srv/shelf", n);
      },
    };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash(req.query.name)));
    };
""")
_QUOTED_FIELD_TS: Program = ("ts", """
    import * as fs from "fs";
    import * as path from "path";

    export class Shelf {
      'hash' = path.join;

      get(req: any, res: any) {
        res.send(fs.readFileSync(this.hash("/srv/shelf", String(req.query.name))));
      }
    }
""")
_QUOTED_METHOD_TS: Program = ("ts", """
    import * as fs from "fs";
    import * as path from "path";

    export class Shelf {
      "hash"(n: string): string {
        return path.join("/srv/shelf", n);
      }

      get(req: any, res: any) {
        res.send(fs.readFileSync(this.hash(String(req.query.name))));
      }
    }
""")
_SUBSCRIPT_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = {};
    layout["hash"] = path.join;
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_DEFINE_PROPERTY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = {};
    Object.defineProperty(layout, "hash", { value: path.join });
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_NAMESPACE_KW_PY: Program = ("py", """
    import os
    from types import SimpleNamespace

    from flask import request

    layout = SimpleNamespace(root="/srv/shelf", hash=os.path.join)


    def shelf():
        with open(layout.hash(layout.root, request.args["name"])) as fh:
            return fh.read()
""")
_FACTORY_KW_PY: Program = ("py", """
    import os

    from flask import request


    class Layout:
        def __init__(self, **parts):
            self.__dict__.update(parts)


    def make(**parts):
        return Layout(**parts)


    layout = make(hash=os.path.join)


    def shelf():
        with open(layout.hash("/srv/shelf", request.args["name"])) as fh:
            return fh.read()
""")
_SETATTR_PY: Program = ("py", """
    import os

    from flask import request


    class Layout:
        root = "/srv/shelf"


    layout = Layout()
    setattr(layout, "hash", os.path.join)


    def shelf():
        with open(layout.hash(layout.root, request.args["name"])) as fh:
            return fh.read()
""")
_GLOBALS_PY: Program = ("py", """
    import os

    from flask import request

    ROOT = "/srv/shelf"
    globals()["hash"] = os.path.join


    def shelf():
        with open(hash(ROOT, request.args["name"])) as fh:
            return fh.read()
""")
_POSITIONAL_GO: Program = ("go", """
    package svc

    import (
        "net/http"
        "os"
        "path/filepath"
    )

    type layout struct {
        hash func(...string) string
    }

    var lay = layout{filepath.Join}

    func Shelf(w http.ResponseWriter, r *http.Request) {
        data, _ := os.ReadFile(lay.hash("/srv/shelf", r.FormValue("name")))
        w.Write(data)
    }
""")
_QUOTED_KEY_CMD_JS: Program = ("js", """
    const { exec } = require("child_process");
    const util = require("util");
    const runner = { "hash": util.format };
    exports.pack = function (req, res) {
      exec(runner.hash("tar -czf /tmp/out.tgz %s", req.query.name), () => res.end());
    };
""")
_NAMESPACE_KW_CMD_PY: Program = ("py", """
    import subprocess
    from types import SimpleNamespace

    from flask import request

    runner = SimpleNamespace(hash="tar -czf /tmp/out.tgz {}".format)


    def pack():
        subprocess.run(runner.hash(request.args["name"]), shell=True)
        return "ok"
""")
_SETATTR_REQ_PY: Program = ("py", """
    import requests
    from flask import request


    class Probe:
        base = "http://"


    probe = Probe()
    setattr(probe, "hash", "{}{}/status".format)


    def status():
        return requests.get(probe.hash(probe.base, request.args["host"])).text
""")
_COMPUTED_KEY_REQ_JS: Program = ("js", """
    const axios = require("axios");
    const util = require("util");
    const probe = { ["hash"]: util.format };
    exports.status = async function (req, res) {
      const r = await axios.get(probe.hash("http://%s/status", req.query.host));
      res.send(r.data);
    };
""")
_POSITIONAL_REQ_GO: Program = ("go", """
    package svc

    import (
        "fmt"
        "net/http"
    )

    type probe struct {
        hash func(string, ...any) string
    }

    var pr = probe{fmt.Sprintf}

    func Status(w http.ResponseWriter, r *http.Request) {
        resp, _ := http.Get(pr.hash("http://%s/status", r.FormValue("host")))
        defer resp.Body.Close()
    }
""")

# (case, program, family, the sink CALL's head): each reports, as on the base
BINDINGS: list[tuple[str, Program, str, str]] = [
    ("js quoted object key", _QUOTED_KEY_JS, "path", "fs.readFileSync"),
    ("js computed object key", _COMPUTED_KEY_JS, "path", "fs.readFileSync"),
    ("js quoted shorthand method", _QUOTED_METHOD_JS, "path", "fs.readFileSync"),
    ("ts quoted class field", _QUOTED_FIELD_TS, "path", "fs.readFileSync"),
    ("ts quoted class method", _QUOTED_METHOD_TS, "path", "fs.readFileSync"),
    ("js subscript assignment", _SUBSCRIPT_JS, "path", "fs.readFileSync"),
    ("js Object.defineProperty", _DEFINE_PROPERTY_JS, "path", "fs.readFileSync"),
    ("py SimpleNamespace keyword", _NAMESPACE_KW_PY, "path", "open"),
    ("py factory keyword", _FACTORY_KW_PY, "path", "open"),
    ("py setattr", _SETATTR_PY, "path", "open"),
    ("py globals subscript", _GLOBALS_PY, "path", "open"),
    ("go positional struct literal", _POSITIONAL_GO, "path", "os.ReadFile"),
    ("command: js quoted object key", _QUOTED_KEY_CMD_JS, "command", "exec"),
    ("command: py keyword", _NAMESPACE_KW_CMD_PY, "command", "subprocess.run"),
    ("request: py setattr", _SETATTR_REQ_PY, "request", "requests.get"),
    ("request: js computed key", _COMPUTED_KEY_REQ_JS, "request", "axios.get"),
    ("request: go positional literal", _POSITIONAL_REQ_GO, "request", "http.Get"),
]

# ── an import or a parameter named ``hash`` beside the new spellings: still a digest ──

_IMPORT_BESIDE_PY: Spec = ("py", """
    import os
    from types import SimpleNamespace

    from flask import request
    from shelf_naming import hash

    ROOT = "/srv/shelf"
    naming = SimpleNamespace(digest=hash, kind="hash")
    setattr(naming, "label", hash)
    globals()["digest"] = hash


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_IMPORT_BESIDE_JS: Spec = ("js", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";
    const naming = { "digest": hash, ["kind"]: "hash" };
    naming["label"] = hash;
    Object.defineProperty(naming, "alias", { value: hash });
    export function get(req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
_PARAM_BESIDE_PY: Spec = ("py", """
    import os
    from types import SimpleNamespace

    from flask import request

    naming = SimpleNamespace(digest=None, kind="hash")


    def shelf(hash=None):
        setattr(naming, "label", hash)
        with open(os.path.join("/srv/shelf", hash(request.args["name"]))) as fh:
            return fh.read()
""")
_PARAM_BESIDE_TS: Spec = ("ts", """
    import * as fs from "fs";
    import * as path from "path";

    export class Shelf {
      "kind" = "hash";

      "read"(hash: (n: string) => string, req: any, res: any) {
        res.send(fs.readFileSync(path.join("/srv/shelf", hash(String(req.query.name)))));
      }
    }
""")
_PARAM_BESIDE_GO: Spec = ("go", """
    package svc

    import (
        "net/http"
        "os"
        "path/filepath"
    )

    type layout struct {
        root string
    }

    var lay = layout{"/srv/shelf"}

    func Reader(hash func(string) string) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            data, _ := os.ReadFile(filepath.Join(lay.root, hash(r.FormValue("name"))))
            w.Write(data)
        }
    }
""")

# (case, program, the path sink CALL's head): none is reported
CONTROLS: list[tuple[str, Spec, str]] = [
    ("from m import hash beside keyword/setattr/globals", _IMPORT_BESIDE_PY, "open"),
    ("import { hash } beside keys/subscript/defineProperty", _IMPORT_BESIDE_JS,
     "fs.readFileSync"),
    ("a parameter (py) named hash", _PARAM_BESIDE_PY, "open"),
    ("a parameter (ts) beside quoted class members", _PARAM_BESIDE_TS, "fs.readFileSync"),
    ("a parameter (go) beside a positional literal", _PARAM_BESIDE_GO, "os.ReadFile"),
]


def _renamed(spec: Program) -> Program:
    """``spec`` with every ``hash`` spelled ``arrange``: the same program under a name that is
    no digest key."""
    lang, source = spec
    return lang, source.replace("hash", "arrange")


@pytest.mark.parametrize(("spec", "family", "head"), cases(BINDINGS))
def test_digest_binding_spellings_report(spec: Program, family: str, head: str) -> None:
    """RED: the file binds ``hash`` itself, so the digest rule is skipped and the flow reports."""
    assert _reported(spec, family, head) is True


@pytest.mark.parametrize(("spec", "family", "head"), cases(BINDINGS))
def test_digest_binding_spellings_renamed_report(spec: Program, family: str, head: str) -> None:
    """Pin: renamed, each program reports today: the flow is found, only the key silences it."""
    assert _reported(_renamed(spec), family, head) is True


@pytest.mark.parametrize(("spec", "head"), cases(CONTROLS))
def test_digest_binding_controls_stay_sanitised(spec: Spec, head: str) -> None:
    """Pin: an import or a parameter named ``hash`` stays a digest beside the new spellings."""
    assert _reported(spec, "path", head) is False
