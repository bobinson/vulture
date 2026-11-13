"""Feature 0104 WS-H (LLD §4.8; D-N (6); A51, A56 protoH3c): Go calls read as Go reads them.

Three Go semantics the single-file flow pass did not model, each a measured false-positive
class of the Go self-scan:

H1  A call whose callee text is exactly one of the language's predeclared functions
    (``roles.PREDECLARED_CALLS["go"]``: ``delete``, ``len`` ...) and that the file does not
    rebind is the language's own operation -- ``delete(m, k)`` removes a map key -- so it is no
    HTTP-client evidence. Exact text: Go is case-sensitive, so an exported ``Delete(...)`` (a
    sibling helper, a dot import) is never the builtin. A ``delete`` the file rebinds (a
    function, a closure, a parameter) is analysed as user code.
H2  ``readall`` is a generic path verb (listed edit 4): a reader drain (``io.ReadAll``) is a
    path sink only with file-system evidence. A ``readall`` read with no such evidence is the
    accepted loss H2L (any language; ``test_0104_known_gaps.py``).
H3  In a language whose every library call is package-qualified
    (``roles.QUALIFIED_CALL_LANGUAGES``: Go), a bare call the file binds no Def for is a
    same-package function, never a language global, so it is no file-system evidence. A
    sibling-file path helper is the accepted loss H3L, with its dot-import extension.

Both tables are ``roles/sinks.py`` constants, exported by ``roles`` (HT-20 re-freeze).
RED until H lands: the tables and the three clean rows. Green today, and kept: every real Go
client and file call, every rebound ``delete``, and the other languages' bare calls.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.unit.ast._0104 import cases, sink_table
from tests.unit.ast._analysis import Spec
from tests.unit.ast.test_0102_precision_a44 import _reported
from tests.unit.ast.test_0102_roles import ENTRY, violations

pytestmark = pytest.mark.usefixtures("real_pool")

_GO_PREDECLARED = frozenset({
    "append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make",
    "max", "min", "new", "panic", "print", "println", "real", "recover",
})


def test_predeclared_calls_are_exactly_gos() -> None:
    table = sink_table("PREDECLARED_CALLS")
    assert dict(table) == {"go": _GO_PREDECLARED}
    with pytest.raises(TypeError):
        table["python"] = frozenset()


def test_qualified_call_languages_are_exactly_go() -> None:
    assert sink_table("QUALIFIED_CALL_LANGUAGES") == frozenset({"go"})


@pytest.mark.parametrize("name", ["PREDECLARED_CALLS", "QUALIFIED_CALL_LANGUAGES"])
def test_tables_are_sink_side_lexicons(name: str) -> None:
    """HT-20: both live in ``roles/sinks.py`` and ``roles`` exports them."""
    sink_table(name)


def test_new_tables_are_generic() -> None:
    """HT-5: language names and the language's own predeclared spellings, nothing else."""
    from shared.ast.profile import PROFILES

    calls: Any = sink_table("PREDECLARED_CALLS")
    languages: Any = sink_table("QUALIFIED_CALL_LANGUAGES")
    assert set(languages) <= set(PROFILES) and set(calls) <= set(languages)
    assert violations(set().union(*calls.values()), ENTRY.fullmatch) == []


_DELETE_BUILTIN: Spec = ("go", """
    package svc

    import (
    	"encoding/json"
    	"net/http"
    )

    func Strip(w http.ResponseWriter, r *http.Request) {
    	var m map[string]any
    	json.NewDecoder(r.Body).Decode(&m)
    	delete(m, "token")
    }
""")
_DELETE_FUNCTION: Spec = ("go", """
    package svc

    import "net/http"

    func delete(target string) (*http.Response, error) {
    	req, _ := http.NewRequest(http.MethodDelete, target, nil)
    	return http.DefaultClient.Do(req)
    }

    func Purge(w http.ResponseWriter, r *http.Request) {
    	delete(r.FormValue("t"))
    }
""")
_DELETE_PARAM: Spec = ("go", """
    package svc

    import "net/http"

    func run(delete func(string) (*http.Response, error), target string) {
    	delete(target)
    }

    func Purge(w http.ResponseWriter, r *http.Request) {
    	run(http.Get, r.FormValue("t"))
    }
""")
_EXPORTED_DELETE: Spec = ("go", """
    package svc

    import "net/http"

    func Purge(w http.ResponseWriter, r *http.Request) {
    	Delete(r.FormValue("t"))
    }
""")
_RECEIVER_DELETE: Spec = ("go", """
    package svc

    import (
    	"net/http"

    	"example.invalid/restlike"
    )

    var restClient = restlike.New()

    func Purge(w http.ResponseWriter, req *http.Request) {
    	url := req.FormValue("url")
    	r := restClient.R()
    	r.Delete(url)
    }
""")
_DOT_GET: Spec = ("go", """
    package svc

    import (
    	. "net/http"
    )

    func Relay(w ResponseWriter, r *Request) {
    	Get(r.URL.Query().Get("u"))
    }
""")
_READ_ALL: Spec = ("go", """
    package svc

    import (
    	"io"
    	"net/http"
    )

    func Echo(w http.ResponseWriter, r *http.Request) {
    	b, _ := io.ReadAll(r.Body)
    	w.Write(b)
    }
""")
_READ_FILE: Spec = ("go", """
    package svc

    import (
    	"net/http"
    	"os"
    )

    func Files(w http.ResponseWriter, r *http.Request) {
    	b, _ := os.ReadFile(r.URL.Query().Get("p"))
    	w.Write(b)
    }
""")
_FILES_READ_ALL: Spec = ("go", """
    package svc

    import "net/http"

    func Fetch(w http.ResponseWriter, r *http.Request) {
    	files.ReadAll(r.FormValue("p"))
    }
""")
_TS_READ_ALL: Spec = ("ts", """
    import * as fs from "./fs-shim";

    export function dump(req: any, res: any) {
      res.send(fs.readAll(req.query.p as string));
    }
""")
_TRUNCATE: Spec = ("go", """
    package svc

    import "net/http"

    func Report(w http.ResponseWriter, r *http.Request) {
    	msg := truncate(r.FormValue("s"), 64)
    	w.Write([]byte(msg))
    }
""")
_PY_OPEN: Spec = ("py", """
    from flask import request


    def read_view():
        return open(request.args["p"]).read()
""")
_C_REMOVE: Spec = ("c", """
    #include <stdio.h>

    int main(int argc, char **argv) {
        return remove(argv[1]);
    }
""")

# (case, program, family, the sink CALL's head, whether ``decide`` reports it)
FLOWS: list[tuple[str, Spec, str, str, bool]] = [
    ("H1: predeclared delete of a map", _DELETE_BUILTIN, "request", "delete", False),
    ("H1: a function delete the file declares", _DELETE_FUNCTION, "request",
     "http.DefaultClient.Do", True),
    ("H1: a parameter named delete", _DELETE_PARAM, "request", "delete", True),
    ("H1: an exported Delete", _EXPORTED_DELETE, "request", "Delete", True),
    ("H1: a receiver's Delete", _RECEIVER_DELETE, "request", "r.Delete", True),
    ("H1: a dot-imported Get", _DOT_GET, "request", "Get", True),
    ("H2: io.ReadAll of a body", _READ_ALL, "path", "io.ReadAll", False),
    ("H2: os.ReadFile", _READ_FILE, "path", "os.ReadFile", True),
    ("H2: ReadAll on a files receiver", _FILES_READ_ALL, "path", "files.ReadAll", True),
    ("H2: readAll on an fs receiver (ts)", _TS_READ_ALL, "path", "fs.readAll", True),
    ("H3: a same-package truncate", _TRUNCATE, "path", "truncate", False),
    ("H3: python's bare open", _PY_OPEN, "path", "open", True),
    ("H3: c's bare remove", _C_REMOVE, "path", "remove", True),
]


@pytest.mark.parametrize(("spec", "family", "head", "reported"), cases(FLOWS))
def test_go_calls(spec: Spec, family: str, head: str, reported: bool) -> None:
    assert _reported(spec, family, head) is reported
