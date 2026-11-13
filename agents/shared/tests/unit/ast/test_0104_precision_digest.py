"""Feature 0104 WS-D (LLD §4.4; D-N (4); A50, A55 rev 3): a digest call is numeric.

Rule. The exact glued keys ``hash`` and ``hexdigest`` join ``SANITIZER_KEYS["numeric"]``: the
result of such a call keeps no external origin (``_sanitised``: constants and the non-external
arguments; the receiver is not carried, so ``h.hexdigest()`` is constant), and a flow left
constant-only is "nothing" (D9). Exact keys, never words: ``hashPath``, ``newHashSet``,
``blob_path_for_digest`` and ``digest.Digest`` are untouched. A constructor has no sanitiser
roles. The key is skipped when the FILE binds that name to a function itself -- a declaration
(a function, a method of any class), an object key, an assignment target (``X.prototype.hash``,
``this.hash``), through one wrapping call (``staticmethod(lambda ...)``) or a class field --
because that ``hash`` is the file's own code, not a digest (rev 3, the second skeptic's R-D2).

Kept false positive: ``.digest('hex')`` and a bare ``.digest()`` (no exact key).
Accepted losses (``test_0104_known_gaps.py``): a ``hash`` the file does not bind (an imported
helper), bcrypt-style outputs.

RED until D lands: the numeric roles of the two keys and the cleans. Green today, and kept:
the words, the constructor, the kept FP and every same-file binding of ``hash``.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._0104 import cases
from tests.unit.ast._analysis import Spec, call_at, judge, sanitizer_roles_of, subject
from tests.unit.ast.test_0102_precision_a44 import _reported

pytestmark = pytest.mark.usefixtures("real_pool")

# ── the roles: exact keys, never words ──

# (case, program, the CALL's head, whether its sanitiser roles hold ``numeric``)
ROLES: list[tuple[str, Spec, str, bool]] = [
    ("member hash", ("js", "const k = util.hash(email);\n"), "util.hash", True),
    ("hexdigest", ("py", "k = h.hexdigest()\n"), "h.hexdigest", True),
    ("php hash()", ("php", "<?php\n$k = hash('sha256', $v);\n"), "hash", True),
    ("hashPath, a word", ("js", "const k = store.hashPath(v);\n"), "store.hashPath", False),
    ("newHashSet, a word", ("java", "class A { void f() { Sets.newHashSet(v); } }\n"),
     "Sets.newHashSet", False),
    ("blob_path_for_digest, a word", ("py", "k = blob_path_for_digest(v)\n"),
     "blob_path_for_digest", False),
    ("digest.Digest, a conversion", ("go", "package a\n\nfunc f() { digest.Digest(v) }\n"),
     "digest.Digest", False),
]


@pytest.mark.parametrize(("spec", "head", "numeric"), cases(ROLES))
def test_digest_roles_are_exact_keys(spec: Spec, head: str, numeric: bool) -> None:
    model = subject(spec)
    assert ("numeric" in sanitizer_roles_of(model, call_at(model, head))) is numeric


# ── the flows: cleaned by a digest, kept by a word or the file's own ``hash`` ──

_ORDER_HASH: Spec = ("js", """
    const fs = require('fs')
    const path = require('path')
    const util = require('./util')
    exports.settle = function (req, res) {
      const ref = util.hash(req.body.email).slice(0, 4) + '-' + Date.now()
      fs.createWriteStream(path.join('out/', `receipt_${ref}.pdf`))
    }
""")
_HEXDIGEST: Spec = ("py", """
    import hashlib
    import os

    from flask import request


    def preview():
        h = hashlib.sha256(request.args["u"].encode())
        return open(os.path.join("/srv/shelf", h.hexdigest() + ".png"), "rb").read()
""")
_PHP_HASH: Spec = ("php", """<?php
$name = hash('sha256', $_GET['u']);
readfile('/srv/shelf/' . $name . '.png');
""")
_LOCAL_FUNCTION: Spec = ("js", """
    const fs = require('fs')
    function hash (s) { return 'pages/' + s }
    exports.page = function (req, res) {
      res.send(fs.readFileSync(hash(req.query.p)))
    }
""")
_DIGEST_HEX: Spec = ("js", """
    const fs = require("fs");
    const crypto = require("crypto");
    exports.stamp = function (req, res) {
      const id = crypto.createHash("sha1").update(req.query.f).digest("hex");
      fs.readFileSync("/srv/" + id);
    };
""")
# R-X: a C++ declaration the scope pass confirmed as a stack-constructor call of ``Hash``.
_CONSTRUCTOR: Spec = ("cpp", """
    #include <fstream>
    #include <string>

    int main(int argc, char** argv) {
        std::string name = argv[1];
        Hash key(name);
        std::ifstream in(key);
        return 0;
    }
""")
_WORD: Spec = ("js", """
    const fs = require("fs");
    exports.open = function (req, res) {
      fs.readFile(shelf.pathForHash(req.query.h), () => {});
    };
""")
_OBJECT_KEY: Spec = ("js", """
    const fs = require("fs");
    const layout = { hash: (name) => name.slice(0, 2) + "/" + name };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash(req.query.name)));
    };
""")
_OBJECT_METHOD: Spec = ("js", """
    const fs = require("fs");
    const layout = {
      hash (name) { return name.slice(0, 2) + "/" + name }
    };
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash(req.query.name)));
    };
""")
_PROTOTYPE: Spec = ("js", """
    const fs = require("fs");
    function Layout(root) { this.root = root; }
    Layout.prototype.hash = function (name) { return this.root + "/" + name; };
    const layout = new Layout("/srv/shards");
    exports.get = function (req, res) {
      res.send(fs.readFileSync(layout.hash(req.query.name)));
    };
""")
_THIS_ASSIGN: Spec = ("js", """
    const fs = require("fs");
    const path = require("path");
    function Shelf(root) {
      this.hash = (name) => path.join(root, name);
    }
    const shelf = new Shelf("/srv/shards");
    exports.get = function (req, res) {
      res.send(fs.readFileSync(shelf.hash(req.query.name)));
    };
""")
_CLASS_FIELD: Spec = ("ts", """
    import * as fs from "fs";

    export class Shards {
      hash = (name: string) => name.slice(0, 2) + "/" + name;

      get(req: any, res: any) {
        res.send(fs.readFileSync(this.hash(String(req.query.name))));
      }
    }
""")
_STATIC_METHOD: Spec = ("ts", """
    import { readFileSync } from "fs";

    export class ShardIndex {
      static hash(name: string): string {
        return name.slice(0, 2) + "/" + name;
      }
    }

    export function download(req: any, res: any) {
      res.send(readFileSync(ShardIndex.hash(req.query.name)));
    }
""")
_INSTANCE_METHOD: Spec = ("py", """
    import os

    from flask import request, send_file


    class ShardIndex:
        def hash(self, name):
            return os.path.join(name[:2], name)


    index = ShardIndex()


    def shard():
        return send_file(index.hash(request.args["name"]))
""")
_USER_HEXDIGEST: Spec = ("py", """
    from flask import request


    class Slip:
        def __init__(self, raw):
            self.raw = raw

        def hexdigest(self):
            return self.raw.strip()


    def slip():
        return open(Slip(request.args["t"]).hexdigest()).read()
""")
_WRAPPED_LAMBDA: Spec = ("py", """
    from flask import request


    class Layout:
        hash = staticmethod(lambda name: name[:2] + "/" + name)


    def shard():
        return open(Layout.hash(request.args["name"])).read()
""")

# A C++ out-of-line definition: its NAME is ``Index::hash``, a function the file declares.
_OUT_OF_LINE: Spec = ("cpp", """
    #include <cstdio>
    #include <string>

    struct Index {
        std::string hash(const std::string& name);
    };

    std::string Index::hash(const std::string& name) { return name.substr(0, 2) + "/" + name; }

    int main(int argc, char** argv) {
        Index idx;
        FILE* f = fopen(idx.hash(argv[1]).c_str(), "r");
        return f ? 0 : 1;
    }
""")

# (case, program, the path sink's head, whether ``decide`` reports it)
FLOWS: list[tuple[str, Spec, str, bool]] = [
    ("an imported util.hash", _ORDER_HASH, "fs.createWriteStream", False),
    ("hexdigest, the receiver dropped", _HEXDIGEST, "open", False),
    ("php hash('sha256', ...)", _PHP_HASH, "readfile", False),
    ("a same-file function hash", _LOCAL_FUNCTION, "fs.readFileSync", True),
    ("kept FP: .digest('hex')", _DIGEST_HEX, "fs.readFileSync", True),
    ("a word, pathForHash", _WORD, "fs.readFile", True),
    ("an object key bound to an arrow", _OBJECT_KEY, "fs.readFileSync", True),
    ("an object-literal method", _OBJECT_METHOD, "fs.readFileSync", True),
    ("a prototype assignment", _PROTOTYPE, "fs.readFileSync", True),
    ("a this.hash assignment", _THIS_ASSIGN, "fs.readFileSync", True),
    ("a class field arrow", _CLASS_FIELD, "fs.readFileSync", True),
    ("a static method", _STATIC_METHOD, "readFileSync", True),
    ("a python instance method", _INSTANCE_METHOD, "send_file", True),
    ("a user hexdigest method", _USER_HEXDIGEST, "open", True),
    ("one wrapping call (staticmethod)", _WRAPPED_LAMBDA, "open", True),
    ("a C++ out-of-line method", _OUT_OF_LINE, "fopen", True),
]


@pytest.mark.parametrize(("spec", "head", "reported"), cases(FLOWS))
def test_digest_flows(spec: Spec, head: str, reported: bool) -> None:
    assert _reported(spec, "path", head) is reported


def test_a_constructor_has_no_sanitiser_roles() -> None:
    """R-X: ``Hash key(name)`` constructs a value; it is no digest call, so argv reaches the
    stream it opens."""
    assert 7 in judge(subject(_CONSTRUCTOR), "path").reported
