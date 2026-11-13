"""Feature 0104 WS-D rev 4 (LLD §4.4; D-P (1), R-D3 / A68): the file's own ``hash`` is no digest.

Rule. ``hash`` and ``hexdigest`` are numeric digest keys (rev 3, ``test_0104_precision_digest``)
unless the FILE binds that name itself. Rev 3 counted a function only; rev 4 counts any value:
an alias (``hash = os.path.join``, ``const hash = path.join``, ``hash := filepath.Join``), an
object or struct literal key, a factory's or a ``functools.partial`` value, a ``self.hash`` /
``this.hash`` assignment, a class field. Such a ``hash`` is the file's own code, so a request
value it carries still reaches the sink.

An import binding keeps the digest rule -- ``from m import hash``, ``import { hash } from``, a
namespace import's ``digests.hash(...)``, ``const hash = require(...)`` and a destructured
``require`` -- and so does a parameter named ``hash``, and the builtin ``hash`` the file never
binds. Accepted loss (``test_0104_known_gaps.py``): a Java lambda implementing an imported
``Hasher``.

Green since aec5910e landed rev 4: every shape the file binds by a value reports, and the
import, parameter and builtin controls stay digests.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast._analysis import Spec
from tests.unit.ast.test_0102_precision_a44 import _reported

pytestmark = pytest.mark.usefixtures("real_pool")

# ── the file binds ``hash`` to a value of its own: the request still reaches the sink ──

_ALIAS_PY: Spec = ("py", """
    import os

    from flask import request

    ROOT = "/srv/shelf"
    hash = os.path.join


    def shelf():
        with open(hash(ROOT, request.args["name"])) as fh:
            return fh.read()
""")
_ALIAS_JS: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    const hash = path.join;
    exports.get = function (req, res) {
      res.send(fs.readFileSync(hash("/srv/shelf", req.query.name)));
    };
""")
_ALIAS_GO: Spec = ("go", """
    package svc

    import (
        "net/http"
        "os"
        "path/filepath"
    )

    func Shelf(w http.ResponseWriter, r *http.Request) {
        hash := filepath.Join
        data, _ := os.ReadFile(hash("/srv/shelf", r.FormValue("name")))
        w.Write(data)
    }
""")
_OBJECT_KEY: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    const layout = { hash: path.join };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
_STRUCT_KEY: Spec = ("go", """
    package svc

    import (
        "net/http"
        "os"
        "path/filepath"
    )

    type layout struct {
        hash func(...string) string
    }

    var lay = layout{hash: filepath.Join}

    func Shelf(w http.ResponseWriter, r *http.Request) {
        data, _ := os.ReadFile(lay.hash("/srv/shelf", r.FormValue("name")))
        w.Write(data)
    }
""")
_FACTORY_PY: Spec = ("py", """
    import os

    from flask import request


    def make_layout(root):
        return lambda name: os.path.join(root, name)


    hash = make_layout("/srv/shelf")


    def shelf():
        with open(hash(request.args["name"])) as fh:
            return fh.read()
""")
_FACTORY_JS: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    const makeLayout = (root) => (name) => path.join(root, name);
    const hash = makeLayout("/srv/shelf");
    exports.get = function (req, res) {
      res.send(fs.readFileSync(hash(req.query.name)));
    };
""")
_PARTIAL_PY: Spec = ("py", """
    import functools
    import os

    from flask import request

    hash = functools.partial(os.path.join, "/srv/shelf")


    def shelf():
        with open(hash(request.args["name"])) as fh:
            return fh.read()
""")
_SELF_ASSIGN_PY: Spec = ("py", """
    import os

    from flask import request


    class Shelf:
        def __init__(self, root):
            self.root = root
            self.hash = os.path.join


    shelf = Shelf("/srv/shelf")


    def get():
        return open(shelf.hash(shelf.root, request.args["name"])).read()
""")
_CLASS_FIELD_TS: Spec = ("ts", """
    import * as fs from "fs";
    import * as path from "path";

    export class Shelf {
      hash = path.join;

      get(req: any, res: any) {
        res.send(fs.readFileSync(this.hash("/srv/shelf", String(req.query.name))));
      }
    }
""")

# ── an import, a parameter or the builtin: the digest rule holds ──

_FROM_IMPORT_PY: Spec = ("py", """
    import os

    from flask import request
    from shelf_naming import hash

    ROOT = "/srv/shelf"


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_NAMED_IMPORT_JS: Spec = ("js", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";
    export function get(req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
_NAMESPACE_IMPORT_TS: Spec = ("ts", """
    import * as fs from "fs";
    import * as path from "path";
    import * as digests from "./digests";

    export function settle(req: any, res: any) {
      const ref = digests.hash(req.body.email).slice(0, 4) + "-" + Date.now();
      fs.createWriteStream(path.join("out/", `receipt_${ref}.pdf`));
      res.end();
    }
""")
_REQUIRED_JS: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    const hash = require("./hash");
    exports.get = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
_DESTRUCTURED_REQUIRE_JS: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash: digest } = require("./naming");
    exports.get = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", digest(req.query.name))));
    };
""")
_PARAM_JS: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    function reader(hash) {
      return function read(req, res) {
        res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
      };
    }
    module.exports = reader((n) => n.slice(0, 2) + "/" + n);
""")
_PARAM_PY: Spec = ("py", """
    import os

    from flask import request


    def shelf(hash=None):
        with open(os.path.join("/srv/shelf", hash(request.args["name"]))) as fh:
            return fh.read()
""")
_BUILTIN_PY: Spec = ("py", """
    import os

    from flask import request


    def shard():
        bucket = hash(request.args["k"]) % 64
        with open(os.path.join("/srv/shards", str(bucket))) as fh:
            return fh.read()
""")

# (case, program, the path sink's head, whether ``decide`` reports it)
FLOWS: list[tuple[str, Spec, str, bool]] = [
    ("an alias (py)", _ALIAS_PY, "open", True),
    ("an alias (js)", _ALIAS_JS, "fs.readFileSync", True),
    ("an alias (go)", _ALIAS_GO, "os.ReadFile", True),
    ("an object key bound to a member", _OBJECT_KEY, "fs.readFileSync", True),
    ("a struct literal key (go)", _STRUCT_KEY, "os.ReadFile", True),
    ("a factory's value (py)", _FACTORY_PY, "open", True),
    ("a factory's value (js)", _FACTORY_JS, "fs.readFileSync", True),
    ("a functools.partial value", _PARTIAL_PY, "open", True),
    ("a self.hash assignment", _SELF_ASSIGN_PY, "open", True),
    ("a class field bound to a member", _CLASS_FIELD_TS, "fs.readFileSync", True),
    ("control: from m import hash", _FROM_IMPORT_PY, "open", False),
    ("control: import { hash }", _NAMED_IMPORT_JS, "fs.readFileSync", False),
    ("control: a namespace import's hash", _NAMESPACE_IMPORT_TS, "fs.createWriteStream", False),
    ("control: const hash = require()", _REQUIRED_JS, "fs.readFileSync", False),
    ("control: a destructured require", _DESTRUCTURED_REQUIRE_JS, "fs.readFileSync", False),
    ("control: a parameter (js)", _PARAM_JS, "fs.readFileSync", False),
    ("control: a parameter (py)", _PARAM_PY, "open", False),
    ("control: the builtin hash", _BUILTIN_PY, "open", False),
]


@pytest.mark.parametrize(("spec", "head", "reported"), cases(FLOWS))
def test_digest_rev4_flows(spec: Spec, head: str, reported: bool) -> None:
    assert _reported(spec, "path", head) is reported
