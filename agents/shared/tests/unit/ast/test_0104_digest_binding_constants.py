"""Feature 0104 WS-D, decision D-S (7): a constant value binds no ``hash`` — key or assignment.

D-S (6) read a keyword argument whose value is a constant as no binding (``make(hash="sha256")``).
D-S (7) applies the same check wherever the file pairs the name with a value: an object or
dict key (``{ name: "HMAC", hash: "SHA-256" }``, the WebCrypto parameter shape) and an
assignment (a class attribute ``hash = ""``, ``cfg.hash = 0``). A constant cannot be called, so
the file's ``hash(...)`` is still the imported digest and its numeric reading stays. An
assignment with no value (``let hash;``) still binds: detection first.

RED until the constant check covers keys and assignments: today each shape binds ``hash``,
lifts the digest rule and the request-reaching path sink reports.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast.test_0102_precision_a44 import _reported
from tests.unit.ast.test_0104_digest_bindings import Program

pytestmark = pytest.mark.usefixtures("real_pool")

SINK_JS = "fs.readFileSync"
SINK_PY = "open"

_WEBCRYPTO_KEY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash } = require("./naming");

    const algorithm = { name: "HMAC", hash: "SHA-256" };

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
_CLASS_ATTRIBUTE_TS: Program = ("ts", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";

    export class Settings {
      hash = "";
    }

    export function shelf(req: any, res: any) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
_MEMBER_ASSIGN_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash } = require("./naming");

    const settings = {};
    settings.hash = 0;

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
_DICT_KEY_PY: Program = ("py", """
    import os

    from flask import request
    from naming import hash

    ROOT = "/srv/shelf"
    OPTIONS = {"hash": "sha256", "salt": None}


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_CLASS_ATTRIBUTE_PY: Program = ("py", """
    import os

    from flask import request
    from naming import hash

    ROOT = "/srv/shelf"


    class Settings:
        hash = "sha256"


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
CONSTANT = [
    ("a WebCrypto-style object key (js)", _WEBCRYPTO_KEY_JS, SINK_JS),
    ("a class attribute with a string (ts)", _CLASS_ATTRIBUTE_TS, SINK_JS),
    ("a member assigned a number (js)", _MEMBER_ASSIGN_JS, SINK_JS),
    ("a dict key (py)", _DICT_KEY_PY, SINK_PY),
    ("a class attribute with a string (py)", _CLASS_ATTRIBUTE_PY, SINK_PY),
]

_UNASSIGNED_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");

    let hash;
    hash = path.join;

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(hash("/srv/shelf", req.query.name)));
    };
""")
_CALLABLE_KEY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");

    const layout = { name: "shelf", hash: path.join };

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name)));
    };
""")
STILL_BOUND = [
    ("a declaration with no value, assigned a function later (js)", _UNASSIGNED_JS, SINK_JS),
    ("an object key holding a function beside a constant key (js)", _CALLABLE_KEY_JS, SINK_JS),
]


@pytest.mark.parametrize(("spec", "head"), cases(CONSTANT))
def test_a_constant_key_or_assignment_binds_no_hash(spec: Program, head: str) -> None:
    """RED: the imported ``hash`` stays a digest beside a constant key or assignment."""
    assert _reported(spec, "path", head) is False


@pytest.mark.parametrize(("spec", "head"), cases(STILL_BOUND))
def test_a_callable_or_unvalued_binding_still_binds(spec: Program, head: str) -> None:
    """Pin (detection first): the file binds ``hash`` to a callable, so the sink reports."""
    assert _reported(spec, "path", head) is True
