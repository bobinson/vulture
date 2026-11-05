"""Unit tests for the single-line rule precision fixes.

The business contract is ``tests/e2e/test_single_rule_precision.py``. These pin
the pieces each fix is built from, and the edges the E2E fixtures do not reach:
cleanup after an inner block (CWE-404), a dereference inside the negated branch
(CWE-476), a channel operator inside a string (CWE-662), the language gate of
the blank-identifier rule (CWE-252), every constant-declaration form (CWE-369),
undecodable token segments (CWE-200), and the CWE-20 caller follow.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cwe_agent.skills.buffer_check import check_buffer_handling
from cwe_agent.skills.concurrency_check import check_concurrency
from cwe_agent.skills.divide_by_zero_check import _is_compile_time
from cwe_agent.skills.error_handling_check import check_error_handling
from cwe_agent.skills.input_validation_check import (
    _BOUND_NAMES,
    _GUARD_SHAPE,
    _call_sites,
    _check_no_validation,
    _returns_input,
    _routine_name,
)
from cwe_agent.skills.resource_check import (
    _CLOSE_CALL,
    _OPEN_BINDING,
    RESOURCE_CLOSE_SAFE,
    check_resource_management,
)
from cwe_agent.skills.secret_scan.cloud_providers import _jwt_issued, find_cloud_secrets


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _rows(skill, tmp_path: Path, name: str, body: str, check: str) -> list[dict]:
    (tmp_path / name).write_text(body)
    return [f for f in skill(str(tmp_path))["findings"] if f.get("check_id") == check]


# ============ CWE-404: improper shutdown ======================================

SHUTDOWN = "cwe.resource.improper_shutdown"


@pytest.mark.parametrize("text", ["defer f.Close()", "with open(p) as f:", "with closing(f):"])
def test_scope_exit_cleanup_forms(text: str) -> None:
    assert RESOURCE_CLOSE_SAFE.search(text)


@pytest.mark.parametrize("text", ["f.close()", "return r.Close()", "await handle.close();"])
def test_close_calls(text: str) -> None:
    assert _CLOSE_CALL.search(text)


@pytest.mark.parametrize("text", ["closeAll(files)", "x.closer()", "deferred := 1", "f.close", "without"])
def test_cleanup_evidence_is_not_a_word_inside_another(text: str) -> None:
    assert RESOURCE_CLOSE_SAFE.search(text) is None and _CLOSE_CALL.search(text) is None


def test_go_handle_assigned_in_a_branch_and_closed_after_it_is_clean(tmp_path: Path) -> None:
    body = (
        "package load\n\nimport \"os\"\n\n"
        "func load(path string) error {\n"
        "\tvar f *os.File\n\tvar err error\n"
        "\tif path == \"-\" {\n\t\tf = os.Stdin\n\t} else {\n"
        "\t\tf, err = os.Open(path)\n"
        "\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n"
        "\tdefer f.Close()\n\treturn nil\n}\n"
    )
    assert _rows(check_resource_management, tmp_path, "load.go", body, SHUTDOWN) == []


def test_js_open_with_an_options_literal_closed_later_is_clean(tmp_path: Path) -> None:
    body = (
        "function save(p, rows) {\n"
        "  const out = fs.createWriteStream(p, { flags: \"a\" });\n"
        "  for (const row of rows) {\n    out.write(row);\n  }\n"
        "  out.close();\n}\n"
    )
    assert _rows(check_resource_management, tmp_path, "save.js", body, SHUTDOWN) == []


def test_python_module_level_open_closed_below_is_clean(tmp_path: Path) -> None:
    body = "handle = open(\"settings.txt\")\nSETTINGS = handle.read()\nhandle.close()\n"
    assert _rows(check_resource_management, tmp_path, "settings.py", body, SHUTDOWN) == []


@pytest.mark.parametrize("prefix, name", [
    ("\tr, err := ", "r"),
    ("\tif f, ferr := ", "f"),
    ("    handle = await ", "handle"),
    ("  const out = ", "out"),
    ("    FILE *fp = ", "fp"),
    ("        self.fh = ", "fh"),
    ("    data = json.load(", None),
    ("    return ", None),
])
def test_open_binding_names_the_handle(prefix: str, name: str | None) -> None:
    bound = _OPEN_BINDING.search(prefix)
    assert (bound.group(1) if bound else None) == name


def test_closing_another_handle_does_not_excuse_this_one(tmp_path: Path) -> None:
    body = (
        "def copy(src, dst):\n"
        "    a = open(src)\n"
        "    b = open(dst, \"w\")\n"
        "    b.write(a.read())\n"
        "    b.close()\n"
    )
    rows = _rows(check_resource_management, tmp_path, "copy.py", body, SHUTDOWN)
    assert [r["line_start"] for r in rows] == [2]


@pytest.mark.parametrize("name, body", [
    ("finally.py", "def read(p):\n    fh = open(p)\n    try:\n        return fh.read()\n"
                   "    finally:\n        fh.close()\n"),
    ("finally.js", "async function read(p) {\n  const handle = await fs.open(p, \"r\");\n  try {\n"
                   "    return await handle.readFile();\n  } finally {\n    await handle.close();\n  }\n}\n"),
    ("deferred.go", "package p\n\nfunc read(p string) error {\n\tf, err := os.Open(p)\n"
                    "\tdefer func() {\n\t\t_ = f.Close()\n\t}()\n\treturn err\n}\n"),
    ("with.py", "def read(p):\n    fh = open(p)\n    with fh:\n        return fh.read()\n"),
    ("exists.js", "async function read(p) {\n  let handle;\n  try {\n    handle = await fs.open(p, \"r\");\n"
                  "    return await handle.readFile();\n  } finally {\n    if (handle) {\n"
                  "      await handle.close();\n    }\n  }\n}\n"),
    ("checked.go", "package p\n\nfunc save(p string) error {\n\tf, err := os.Create(p)\n"
                   "\tif err != nil {\n\t\treturn err\n\t}\n\tif err := f.Close(); err != nil {\n"
                   "\t\treturn err\n\t}\n\treturn nil\n}\n"),
])
def test_cleanup_on_the_open_path_counts(tmp_path: Path, name: str, body: str) -> None:
    assert _rows(check_resource_management, tmp_path, name, body, SHUTDOWN) == []


@pytest.mark.parametrize("name, body", [
    ("loop.py", "def read(paths):\n    fh = open(paths[0])\n    for p in paths:\n        fh.close()\n"),
    ("except.py", "def read(p):\n    try:\n        fh = open(p)\n        return fh.read()\n"
                  "    except OSError:\n        fh.close()\n        raise\n"),
    ("argument.js", "function serve(p, res) {\n  const s = fs.createReadStream(p);\n"
                    "  res.on(\"close\", () => s.close());\n  s.pipe(res);\n}\n"),
    ("catch.js", "function serve(p) {\n  const s = fs.createReadStream(p);\n"
                 "  try { s.pipe(out); } catch (e) { s.close(); }\n}\n"),
    # A test of something other than the handle makes the close conditional.
    ("other.go", "package p\n\nfunc save(p string, ok bool) {\n\tf, _ := os.Create(p)\n"
                 "\tif ok {\n\t\tf.Close()\n\t}\n}\n"),
])
def test_cleanup_off_the_open_path_does_not_count(tmp_path: Path, name: str, body: str) -> None:
    assert len(_rows(check_resource_management, tmp_path, name, body, SHUTDOWN)) == 1


def test_python_close_in_a_sibling_method_does_not_count(tmp_path: Path) -> None:
    body = (
        "class Log:\n"
        "    def start(self, path):\n"
        "        self.fh = open(path, \"a\")\n"
        "\n"
        "    def stop(self):\n"
        "        self.fh.close()\n"
    )
    assert len(_rows(check_resource_management, tmp_path, "log.py", body, SHUTDOWN)) == 1


# ============ CWE-476: nil dereference ========================================

NULL_DEREF = "cwe.resource.null_deref"
_CACHE_HEAD = "package c\n\nfunc f(c Cache, k string) string {\n"


def test_dereference_inside_the_negated_branch_is_reported(tmp_path: Path) -> None:
    body = _CACHE_HEAD + (
        "\te, ok := c.Lookup(k)\n\tif !ok {\n\t\tlog(e.Name)\n\t\treturn \"\"\n\t}\n\treturn e.Name\n}\n"
    )
    assert len(_rows(check_resource_management, tmp_path, "c.go", body, NULL_DEREF)) == 1


def test_a_discarded_second_result_is_not_a_comma_ok_guard(tmp_path: Path) -> None:
    body = _CACHE_HEAD + "\te, _ := c.Lookup(k)\n\tif !ok {\n\t\treturn \"\"\n\t}\n\treturn e.Name\n}\n"
    assert len(_rows(check_resource_management, tmp_path, "c.go", body, NULL_DEREF)) == 1


@pytest.mark.parametrize("lines", [
    "\tif ok {\n\t\treturn e.Name\n\t}\n\treturn \"\"\n",
    "\tif ok && e.Name != \"\" {\n\t\treturn e.Name\n\t}\n\treturn \"\"\n",
    "\tif !ok || e.Name == \"\" {\n\t\treturn \"\"\n\t}\n\treturn e.Name\n",
    "\treturn map[bool]string{true: \"\"}[!ok || e.Name == \"\"]\n",
])
def test_comma_ok_guards_that_prove_the_value(tmp_path: Path, lines: str) -> None:
    body = _CACHE_HEAD + "\te, ok := c.Lookup(k)\n" + lines + "}\n"
    assert _rows(check_resource_management, tmp_path, "c.go", body, NULL_DEREF) == []


@pytest.mark.parametrize("lines", [
    # `!ok &&` is the miss case, and `x.ok` is another value's field.
    "\tif !ok && e.Name == \"\" {\n\t\treturn \"\"\n\t}\n\treturn k\n",
    "\tif x.ok && e.Name != \"\" {\n\t\treturn e.Name\n\t}\n\treturn k\n",
    # The use sits in the else branch of the positive test.
    "\tif ok {\n\t\treturn k\n\t} else {\n\t\treturn e.Name\n\t}\n",
])
def test_comma_ok_tests_that_do_not_prove_the_value(tmp_path: Path, lines: str) -> None:
    body = _CACHE_HEAD + "\te, ok := c.Lookup(k)\n" + lines + "}\n"
    assert len(_rows(check_resource_management, tmp_path, "c.go", body, NULL_DEREF)) == 1


def test_comma_ok_guard_that_continues_a_loop_is_clean(tmp_path: Path) -> None:
    body = (
        "package c\n\nfunc names(c Cache, keys []string) (out []string) {\n"
        "\tfor _, k := range keys {\n"
        "\t\te, ok := c.Lookup(k)\n\t\tif !ok {\n\t\t\tcontinue\n\t\t}\n"
        "\t\tout = append(out, e.Name)\n\t}\n\treturn out\n}\n"
    )
    assert _rows(check_resource_management, tmp_path, "c.go", body, NULL_DEREF) == []


# ============ CWE-662: goroutine without synchronisation =======================

NO_SYNC = "cwe.concurrency.no_sync"


def test_channel_arrow_inside_a_string_is_not_synchronisation(tmp_path: Path) -> None:
    body = "package p\n\nfunc f(n *int) {\n\tgo func() { *n++; println(\"a <- b\") }()\n}\n"
    assert len(_rows(check_concurrency, tmp_path, "p.go", body, NO_SYNC)) == 1


def test_a_method_named_close_is_not_the_channel_builtin(tmp_path: Path) -> None:
    body = "package p\n\nfunc f(c *conn, n *int) {\n\tgo func() {\n\t\t*n++\n\t\tc.close()\n\t}()\n}\n"
    assert len(_rows(check_concurrency, tmp_path, "p.go", body, NO_SYNC)) == 1


@pytest.mark.parametrize("decl, call", [
    ("var wg sync.WaitGroup", "defer wg.Done()"),
    ("wg := &sync.WaitGroup{}", "wg.Done()"),
    ("wg := new(sync.WaitGroup)", "wg.Done()"),
    ("var s struct{ wg sync.WaitGroup }", "s.wg.Done()"),
])
def test_wait_group_signal_is_synchronisation(tmp_path: Path, decl: str, call: str) -> None:
    body = (
        f"package p\n\nfunc f(n []int) {{\n\t{decl}\n\tgo func() {{\n\t\t{call}\n"
        "\t\tn[0] = 1\n\t}()\n}\n"
    )
    assert _rows(check_concurrency, tmp_path, "p.go", body, NO_SYNC) == []


def test_python_thread_arm_is_unchanged(tmp_path: Path) -> None:
    body = "import threading\n\n\ndef run(work):\n    threading.Thread(target=work).start()\n"
    assert len(_rows(check_concurrency, tmp_path, "w.py", body, NO_SYNC)) == 1


# ============ CWE-252: explicit discard ========================================

UNCHECKED = "cwe.error_handling.unchecked_return"


@pytest.mark.parametrize("name", ["cli.py", "app.js", "app.ts", "Main.java"])
def test_blank_name_discard_outside_go_is_not_reported(tmp_path: Path, name: str) -> None:
    assert _rows(check_error_handling, tmp_path, name, "_ = parser.parse_args()\n", UNCHECKED) == []


def test_go_discard_is_low_and_says_it_was_explicit(tmp_path: Path) -> None:
    body = "package p\n\nfunc f(c Closer) {\n\t_ = c.Close()\n}\n"
    [row] = _rows(check_error_handling, tmp_path, "p.go", body, UNCHECKED)
    assert row["severity"] == "low"
    assert row["title"] == "Unchecked return value"
    assert row["description"] == "Error explicitly discarded by assignment to the blank identifier at line 4"


# ============ CWE-125: index arithmetic ========================================

OOB_READ = "cwe.buffer.oob_read"


@pytest.mark.parametrize("name", ["w.c", "w.h", "w.cpp", "w.hpp"])
def test_index_arithmetic_is_reported_in_c_family(tmp_path: Path, name: str) -> None:
    body = "int f(const int *a, int i) {\n    return a[i + 1];\n}\n"
    assert len(_rows(check_buffer_handling, tmp_path, name, body, OOB_READ)) == 1


def test_index_arithmetic_is_not_reported_in_go(tmp_path: Path) -> None:
    body = "package p\n\nfunc f(a []int, i int) int {\n\treturn a[i+1]\n}\n"
    assert _rows(check_buffer_handling, tmp_path, "p.go", body, OOB_READ) == []


# ============ CWE-369: compile-time division ===================================

def _const(source: str, suffix: str) -> bool:
    lines = tuple(source.splitlines())
    return _is_compile_time(lines, len(lines), suffix)


@pytest.mark.parametrize("source, suffix", [
    ("const ratio = total / parts", ".go"),
    ("const (\n\t// a comment\n\n\tratio = total / parts", ".go"),
    ("const (\n\tsum = (a +\n\t\tb) / c", ".go"),
    ("pub(crate) const PER: u32 = A / B;", ".rs"),
    ("static mut PER: u32 = A / B;", ".rs"),
    ("const _: () = assert!(A / B > 0);", ".rs"),
    ("inline constexpr auto kPer = sizeof(T) / kN;", ".hpp"),
    ("constexpr int kPer = kA / kB;", ".c"),
])
def test_constant_declarations_are_compile_time(source: str, suffix: str) -> None:
    assert _const(source, suffix)


@pytest.mark.parametrize("source, suffix", [
    ("x := total / parts", ".go"),
    ("var (\n\tratio = total / parts", ".go"),
    ("const (\n\ta = 1\n)\n\nfunc f(x, y int) int {\n\treturn x / y", ".go"),
    ("const (\n\ta = 1\n)\nvar z = a / b", ".go"),
    ("pub const fn per(a: u32, b: u32) -> u32 { a / b }", ".rs"),
    ("let per: u32 = a / b;", ".rs"),
    ("constexpr int per(int a, int b) { return a / b; }", ".cpp"),
    ("const int per = a / b;", ".cpp"),
    ("const ratio = total / parts", ".rs"),
])
def test_run_time_divisions_are_not_compile_time(source: str, suffix: str) -> None:
    assert not _const(source, suffix)


# ============ CWE-200: JWT format ==============================================

_HS256 = _b64(b'{"alg":"HS256"}')
_PAYLOAD = _b64(b'{"sub":"u"}')
_MAC = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.mark.parametrize("token", [
    f"{_HS256}.{_PAYLOAD}.{_MAC}",
    f"{_b64(json.dumps({'alg': 'ES256', 'kid': 'k'}).encode())}.{_PAYLOAD}.{_MAC}",
    # A segment that does not decode cannot be judged, so the token is kept.
    f"{_HS256}.{_PAYLOAD}.{_MAC}x",
])
def test_signed_tokens_are_issued(token: str) -> None:
    assert _jwt_issued(token)


@pytest.mark.parametrize("token", [
    f"{_HS256}.{_PAYLOAD}.{_b64(b'legacy-signature')}",
    f"{_HS256}.{_PAYLOAD}.{_b64(b'this-is-a-much-longer-readable-signature')}",
    f"{_HS256}.{_PAYLOAD}.{_b64(bytes(range(200, 215)))}",
    f"{_b64(b'{\"typ\":\"JWT\"}')}.{_PAYLOAD}.{_MAC}",
    f"{_b64(b'[\"alg\"]')}.{_PAYLOAD}.{_MAC}",
    f"{_b64(b'{\"not json')}.{_PAYLOAD}.{_MAC}",
    # Nesting past the interpreter's recursion limit is refused, not raised.
    f"{_b64(b'[' * 100000)}.{_PAYLOAD}.{_MAC}",
])
def test_fixture_tokens_are_not_issued(token: str) -> None:
    assert not _jwt_issued(token)


def test_a_fixture_token_is_not_reported_and_a_signed_one_is() -> None:
    fixture = f"{_HS256}.{_PAYLOAD}.{_b64(b'legacy-signature')}"
    content = f'a = "{fixture}"\nb = "{_HS256}.{_PAYLOAD}.{_MAC}"\n'
    rows = [f for f in find_cloud_secrets(Path("t.ts"), content) if f["check_id"].endswith(".jwt")]
    assert [r["line_start"] for r in rows] == [2]


# ============ CWE-20: returned input ===========================================

@pytest.mark.parametrize("line, expected", [
    ("        return await req.json()", True),
    ("    return request.json", True),
    ("  return req.body.payload;", True),
    ("    return render(request.GET['x'])", False),
    ("    data = request.json", False),
])
def test_returned_input_is_the_whole_return_operand(line: str, expected: bool) -> None:
    assert _returns_input(line) is expected


@pytest.mark.parametrize("header, name", [
    ("async def _read_json(req) -> Any:", "_read_json"),
    ("def body_of(request):", "body_of"),
    ("function readBody(req) {", "readBody"),
    ("const readBody = async (req) => {", "readBody"),
    ("  async readBody(req) {", "readBody"),
    ("func (s *Server) readBody(r *http.Request) []byte {", "readBody"),
])
def test_routine_name_from_header(header: str, name: str) -> None:
    assert _routine_name(header) == name


def test_call_sites_exclude_the_header_comments_and_strings() -> None:
    lines = [
        "def body_of(request):",
        "    return request.json",
        "x = self.body_of(r)  # body_of(r) again",
        "y = 'body_of(r)'",
        "# body_of(r)",
        "z = await body_of(r)",
    ]
    assert _call_sites(lines, "body_of") == [3, 6]


@pytest.mark.parametrize("line", [
    "    if not data:",
    "    if data is None:",
    "    if data is not None and data.ok:",
    "    if not isinstance(data, dict): raise TypeError()",
    "    if 'id' not in data: raise KeyError('id')",
])
def test_python_guard_shapes(line: str) -> None:
    assert _GUARD_SHAPE.search(line)


def test_annotated_assignment_binds_its_name() -> None:
    assert [m for m in _BOUND_NAMES.findall("    body: dict[str, Any] = await read(req)") if any(m)]


def _cwe20(src: str, name: str = "api.py") -> list[dict]:
    lines = src.split("\n")
    found: list[dict] = []
    for i, line in enumerate(lines, start=1):
        _check_no_validation(Path(name), line, i, lines, found)
    return [f["line_start"] for f in found]


def test_returned_input_whose_caller_returns_it_again_is_reported() -> None:
    src = (
        "def body_of(request):\n    return request.json\n\n\n"
        "def view(request):\n    return body_of(request)\n"
    )
    assert _cwe20(src) == [2]


def test_returned_input_whose_caller_guards_it_is_clean() -> None:
    src = (
        "def body_of(request):\n    return request.json\n\n\n"
        "def view(request, store):\n    data = body_of(request)\n    store.a()\n    store.b()\n"
        "    store.c()\n    if not data:\n        raise ValueError('empty')\n    store.save(data)\n"
    )
    assert _cwe20(src) == []
