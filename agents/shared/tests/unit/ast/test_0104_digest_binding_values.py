"""Feature 0104 WS-D: a binder's VALUE decides whether it binds ``hash`` (D-S (6)/(7)).

The constant-value rule — "a constant cannot be called, so it binds no name" — reaches the
keyword argument (``_keyword``), the object/dict key (``_object_key``) and the assignment
(``_unbound`` / ``_assigned_constant``). This module covers the three value shapes that the
D-S cycle's own tests left unpinned, and closes the one binder spelling the rule had missed:

* **Reflective binders** (``setattr`` / ``defineProperty``) with a CONSTANT value. Every sibling
  binder drops a constant; the reflective binder did not, so ``setattr(cfg, "hash", "sha256")``
  and ``Object.defineProperty(o, "hash", { value: "sha256" })`` still bound ``hash`` and
  re-admitted the digest false positive. RED until ``_reflected`` applies the same constant rule;
  the asymmetry with ``cfg.hash = "sha256"`` (already silenced) is the defect.
* **The null / unfilled rule** (``_UNFILLED``): a ``null`` value is a slot not yet filled, so it
  still binds (``{ hash: null }``, ``hash = null``), detection first.
* **The string-callable languages** (``_STRING_CALLABLE_LANGUAGES``): PHP calls a string by name,
  so a string value there still binds, where in JavaScript/Python a string is a constant.
* **The ``_assigned_constant`` separator guards**: a valueless class field (``hash;``) before a
  private member (``#secret = "x";``) keeps binding — the ``;`` / newline between them stops the
  next member's value being read as this field's.

Pins report today and must keep reporting; the reflective-constant cases are RED until the fix.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast.test_0102_precision_a44 import _reported
from tests.unit.ast.test_0104_digest_bindings import Program, _renamed

pytestmark = pytest.mark.usefixtures("real_pool")

# ── #1 a reflective binder of a CONSTANT value binds no ``hash`` (RED until the fix) ──

_SETATTR_CONST_PY: Program = ("py", """
    import os

    from flask import request
    from naming import hash

    ROOT = "/srv/shelf"


    class Settings:
        pass


    cfg = Settings()
    setattr(cfg, "hash", "sha256")


    def shelf():
        with open(os.path.join(ROOT, hash(request.args["name"]))) as fh:
            return fh.read()
""")
_DEFINE_CONST_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash } = require("./naming");

    const o = {};
    Object.defineProperty(o, "hash", { value: "sha256" });

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
_REFLECT_CONST_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash } = require("./naming");

    const o = {};
    Reflect.defineProperty(o, "hash", { value: "sha256" });

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
REFLECTIVE_CONST: list[tuple[str, Program, str]] = [
    ("py setattr(o, 'hash', 'sha256')", _SETATTR_CONST_PY, "open"),
    ("js Object.defineProperty value const", _DEFINE_CONST_JS, "fs.readFileSync"),
    ("js Reflect.defineProperty value const", _REFLECT_CONST_JS, "fs.readFileSync"),
]

# ── pins: a binder value that holds a callable still binds ``hash`` (null, PHP string) ──

_NULL_KEY_JS: Program = ("js", """
    const fs = require("fs");
    const path = require("path");
    const { hash } = require("./naming");

    const algorithm = { name: "HMAC", hash: null };

    exports.shelf = function (req, res) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    };
""")
_NULL_FIELD_TS: Program = ("ts", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";

    export class Settings {
      hash = null;
    }

    export function shelf(req: any, res: any) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
_PHP_STRING_BIND: Program = ("php", """<?php
$hash = 'under_shelf';
readfile('/srv/shelf/' . $hash($_GET['name']));
""")
_VALUELESS_BEFORE_PRIVATE_TS: Program = ("ts", """
    import fs from "fs";
    import path from "path";
    import { hash } from "./naming";

    export class Settings {
      hash;
      #secret = "x";
    }

    export function shelf(req: any, res: any) {
      res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name))));
    }
""")
STILL_BINDS: list[tuple[str, Program, str]] = [
    ("a null object key is unfilled (js)", _NULL_KEY_JS, "fs.readFileSync"),
    ("a null class field is unfilled (ts)", _NULL_FIELD_TS, "fs.readFileSync"),
    ("a php string value is callable", _PHP_STRING_BIND, "readfile"),
    ("valueless field, private next (ts)", _VALUELESS_BEFORE_PRIVATE_TS, "fs.readFileSync"),
]


@pytest.mark.parametrize(("spec", "head"), cases(REFLECTIVE_CONST))
def test_a_reflective_binder_of_a_constant_binds_no_hash(spec: Program, head: str) -> None:
    """RED: a reflective binder setting a constant names an option; ``hash`` stays a digest."""
    assert _reported(spec, "path", head) is False


@pytest.mark.parametrize(("spec", "head"), cases(REFLECTIVE_CONST))
def test_reflective_constant_programs_renamed_report(spec: Program, head: str) -> None:
    """Pin: renamed off the digest key, each flow is found — only the digest rule silenced it."""
    assert _reported(_renamed(spec), "path", head) is True


@pytest.mark.parametrize(("spec", "head"), cases(STILL_BINDS))
def test_a_value_that_can_hold_a_callable_still_binds(spec: Program, head: str) -> None:
    """Pin (detection first): null is unfilled, a PHP string callable, a valueless field binds."""
    assert _reported(spec, "path", head) is True
