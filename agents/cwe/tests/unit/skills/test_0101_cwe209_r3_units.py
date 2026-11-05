"""Feature 0101 revision 3 -- the CWE-209 arm functions, one table function at a time (LLD 5.3.6).

The E2E file (`tests/e2e/test_0101_cwe209_r3.py`) holds the business contract;
these pin the building blocks it rests on, so a regression names the function
that broke: the field test and its getters/transforms, M and R, the positional
mapping per declaration form, the fill rule P (a named routine against a
callback, the 2-hop limit), return binding, the declaration look-ahead (a call
statement ending in `)` is not a declaration; Allman bodies are), Y's key roles
and the plural exclusion, the W forms including inserts, the C1 name test, the
C2 parameter test, H's written-parameter set, the excuses V and T, and S's
enclosing-block search including a same-line `case`.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from cwe_agent.skills import info_exposure_check as iec

TS = ".ts"


def _scope(lines: list[str], line_num: int, prefix: str = "", suffix: str = TS) -> iec._Scope:
    return iec._Scope(lines, line_num, prefix, 0, suffix)


# ---- the field test (F, M) ----

@pytest.mark.parametrize(("member", "detail_ok", "expected"), [
    ("error", True, True), ("lastFailure", True, True), ("errs", False, True),
    ("errorCode", True, False), ("error_type", True, False), ("statusMessage", True, False),
    ("message", True, True), ("message", False, False), ("reason", True, True),
    ("errorMessage", False, True), ("value", True, False),
])
def test_error_field(member: str, detail_ok: bool, expected: bool) -> None:
    assert iec._error_field(member, detail_ok) is expected


def test_detail_only_field_is_m() -> None:
    assert iec._detail_only("message") and iec._detail_only("details")
    assert not iec._detail_only("error") and not iec._detail_only("errorMessage")


@pytest.mark.parametrize(("chain", "root", "fields"), [
    (".error", "outcome", ["error"]),
    (".getError", "outcome", ["error"]),                 # a getter reads as its field
    (".error.toString", "outcome", ["error"]),           # a trailing transform is ignored
    (".error.trim", "outcome", ["error"]),
    (".errorCode", "outcome", []),                       # a projection word: not text
    (".ERROR", "outcome", []),                           # an all-caps member: a constant
    (".error", "Codes", []),                             # a member of a type
    (".message", "job", ["message"]),                    # M: a detail word, judged by provenance
])
def test_chain_error_fields(chain: str, root: str, fields: list[str]) -> None:
    assert list(iec._chain_error_fields([chain], root)) == fields


# ---- text helpers ----

def test_split_top_and_cut_respect_brackets_and_literals() -> None:
    assert [p.strip() for p in iec._split_top('a, f(b, c), "x, y", [d, e]')] == ["a", "f(b, c)", '"x, y"', "[d, e]"]
    assert iec._top_level_cut("err.message, other)") == "err.message"
    assert iec._top_level_cut("f(a, b); next") == "f(a, b)"
    assert iec._top_level_cut("value) + 1") == "value"


@pytest.mark.parametrize(("args", "idx", "name", "expected"), [
    ("false, e.message", 1, "error", "e.message"),
    ("ok=False, error=str(e)", 1, "error", "str(e)"),     # the keyword wins over the position
    ("Ok = false, Error = msg", 0, "error", " msg"),
    ("true", 1, "error", None),
])
def test_pick_argument(args: str, idx: int, name: str, expected: str | None) -> None:
    got = iec._pick_argument(args, idx, name)
    assert (got.strip() if got is not None else None) == (expected.strip() if expected else None)


# ---- declarations: look-ahead, Allman, extents ----

def test_a_call_statement_ending_in_paren_is_not_a_declaration() -> None:
    go = ["func process(id string) Result {", "\trecord(id)", "\treturn remote.Do(id)", "}"]
    assert iec._is_declaration(go[0], go, 0)
    assert not iec._is_declaration(go[1], go, 1)
    py = ["def load(ident):", "    _note(ident)", "    return remote_lookup(ident)"]
    assert iec._is_declaration(py[0], py, 0)
    assert not iec._is_declaration(py[1], py, 1)


def test_allman_body_on_the_next_line_is_a_declaration() -> None:
    cs = ["    static Outcome Load(string id)", "    {", "        return new Outcome();", "    }"]
    assert iec._is_declaration(cs[0], cs, 0)
    attr = ["    [HttpGet]", "    public static Outcome Load(string id)", "    [Obsolete]", "    {", "    }"]
    assert iec._is_declaration(attr[1], attr, 1)
    call = ["    Load(id)", "    other(id);"]
    assert not iec._is_declaration(call[0], call, 0)


def test_def_rows_find_only_declarations() -> None:
    lines = ["function load(id) {", "  return load2(id);", "}", "const fail = (msg) => ({ error: msg });",
             "load(1);"]
    assert iec._def_rows(lines, "load") == [0]
    assert iec._def_rows(lines, "fail") == [3]
    assert iec._def_rows(lines, "load2") == []


def test_routine_end_by_braces_indentation_and_ruby_end() -> None:
    ts = ["function a() {", "  if (x) {", "    y();", "  }", "}", "next();"]
    assert iec._routine_end(ts, 0) == 5
    py = ["def a():", "    try:", "        x()", "    except E:", "        y()", "", "def b():"]
    assert iec._routine_end(py, 0) == 6
    rb = ["def load(id)", "  Store.read(id)", "rescue StandardError => e", "  fail(e)", "end", "x = 1"]
    assert iec._routine_end(rb, 0) == 5


# ---- K: positional members per declaration form ----

@pytest.mark.parametrize(("lines", "name", "members"), [
    (["public record Outcome(bool Ok, string Error);"], "Outcome", ["Ok", "Error"]),
    (["data class Outcome(val ok: Boolean, val error: String?)"], "Outcome", ["ok", "error"]),
    (["Outcome = Struct.new(:ok, :error)"], "Outcome", ["ok", "error"]),
    (["type Outcome struct {", "\tOk  bool", "\tErr string", "}"], "Outcome", ["Ok", "Err"]),
    (["from dataclasses import dataclass", "@dataclass", "class Outcome:", "    ok: bool",
      "    error: str | None = None", "", "def f():", "    pass"], "Outcome", ["ok", "error"]),
    (["class Outcome { constructor() {} }"], "Outcome", None),
])
def test_type_members(lines: list[str], name: str, members: list[str] | None) -> None:
    assert iec._type_members(lines, name) == members


# ---- rule P: parameter-sourced fills ----

HELPER = [
    "const fail = (msg: string) => ({ ok: false, error: msg });",     # 0: a named routine's parameter
    "async function load(id: string) {",
    "  try { return { ok: true, data: await store.read(id) }; }",
    "  catch (err) { return fail(err.message); }",                     # 3: the caller passes an error
    "}",
]


def test_named_routine_parameter_needs_a_caller_passing_an_error() -> None:
    assert iec._fill_is_error(HELPER, 0, "const fail = (msg: string) => ({ ok: false, error: ", " msg")
    quiet = [HELPER[0], "function load2() { return fail('E_NOT_FOUND'); }"]
    assert not iec._fill_is_error(quiet, 0, "const fail = (msg: string) => ({ ok: false, error: ", " msg")


def test_a_callback_parameter_keeps_the_error_first_convention() -> None:
    lines = ["export function track(upload) {", "  upload.promise.catch((err) => { upload.error = err.message; });", "}"]
    assert iec._fill_is_error(lines, 1, "  upload.promise.catch((err) => { upload.error = ", " err.message")


def test_caller_hops_stop_at_two() -> None:
    lines = [
        "function a(m) { return { error: m }; }",
        "function b(m) { return a(m); }",
        "function c(m) { return b(m); }",
        "function d(m) { return c(m); }",
        "try { x(); } catch (err) { d(err.message); }",
    ]
    assert iec._fill_is_error(lines, 0, "function a(m) { return { error: ", " m", 0) is False
    two = lines[:2] + ["try { x(); } catch (err) { b(err.message); }"]
    assert iec._fill_is_error(two, 0, "function a(m) { return { error: ", " m", 0)


# ---- return binding: producer evidence inside the returned value only ----

def test_producer_fill_must_be_in_the_returned_value() -> None:
    returned = ["async function load(id) {", "  try { return { ok: true }; }",
                "  catch (e) { return { ok: false, error: e.message }; }", "}"]
    assert iec._producer_fills(returned, "error", "load")
    persisted = ["async function run(id) {", "  try { await work(id); return { ok: true, error: null }; }",
                 "  catch (e) {", "    await db.update({ data: { error: e.message } });",
                 "    return { ok: false, error: 'JOB_FAILED' };", "  }", "}"]
    assert not iec._producer_fills(persisted, "error", "run")


def test_returned_variable_fill_counts() -> None:
    lines = ["Res load(String id) {", "  Res r = new Res();", "  try { x(); } catch (Exception e) { r.error = e.getMessage(); }",
             "  return r;", "}"]
    assert iec._producer_fills(lines, "error", "load")


def test_a_throw_is_not_a_returned_value() -> None:
    lines = ["async function load(id) {", "  try { await db.get(id); } catch (e) { throw new HttpError(500, e); }",
             "  return remote.lookup(id);", "}"]
    assert not iec._producer_fills(lines, "error", "load")


# ---- arm F and R through a sink's scope ----

def test_field_discloses_through_the_producer() -> None:
    lines = ["async function load(id) {", "  try { return { ok: true }; }",
             "  catch (err) { return { ok: false, error: err.message }; }", "}",
             "export async function show(req, res) {", "  const outcome = await load(req.params.id);",
             "  res.status(500).json({ error: outcome.error });", "}"]
    assert iec._field_discloses("error", _scope(lines, 7), "outcome")
    assert not iec._field_discloses("errorCode", _scope(lines, 7), "outcome")


def test_alias_field_reads_the_renamed_key() -> None:
    lines = ["export async function show(req, res) {", "  const { error: loadError } = await load(req.params.id);",
             "  res.status(500).json({ message: loadError });", "}"]
    assert iec._alias_field("loadError", _scope(lines, 3)) == "error"
    assert iec._alias_field("other", _scope(lines, 3)) is None


def test_destructure_aliases_keep_the_exact_error_name_rule() -> None:
    assert iec._destructure_aliases("const { error: loadError, data } = x") == (("loadError", "error"),)
    assert iec._destructure_aliases("const { error: err } = x") == ()


# ---- arm Y ----

@pytest.mark.parametrize(("members", "expected"), [
    (["error"], True), (["errors"], False), (["errorCode"], False), (["failedReason"], False),
    (["getError"], True),
])
def test_keyed_error_field_is_singular(members: list[str], expected: bool) -> None:
    assert iec._keyed_error_field("status", members) is expected


@pytest.mark.parametrize(("text", "expected"), [
    ("{ error: 'FAILED', message: status.error }", True),
    ("{ code: Codes.UNAVAILABLE, detail: r.error }", True),
    ("{ message: r.error }", False),
    ("{ error: r.error }", False),
])
def test_code_key_marks_a_code_detail_pair(text: str, expected: bool) -> None:
    assert bool(iec._CODE_KEY.search(text)) is expected


# ---- arm W ----

def _w(lines: list[str], line_num: int) -> str | None:
    return iec._member_write(lines, line_num, lines[line_num - 1], TS)


@pytest.mark.parametrize("write", [
    "    out.error = String(err);",
    "    out['error'] = String(err);",
    "    out.setError(err.message);",
    "    out.push({ reason: err.message });",
])
def test_member_write_forms_then_sent_whole(write: str) -> None:
    lines = ["export function h(req, res) {", "  const out: any = {};", "  try { run(); } catch (err) {", write,
             "  }", "  res.json(out);", "}"]
    assert _w(lines, 4) == "out"


def test_member_write_not_sent_or_instance_state_is_not_w() -> None:
    not_sent = ["export function h(req, res) {", "  const job: any = {};", "  try { run(); } catch (err) {",
                "    job.error = err.message;", "  }", "  res.json({ id: job.id });", "}"]
    assert _w(not_sent, 4) is None
    own = ["class V {", "  refresh(req, res) {", "    try { run(); } catch (err) {", "      this.error = err.message;",
           "    }", "    res.json(this);", "  }", "}"]
    assert _w(own, 4) is None


def test_w_helper_follows_a_same_file_caller() -> None:
    lines = ["function check(id, response) {", "  const r = lookup(id);", "  if (!r.ok) {",
             "    response.error = `lookup failed: ${r.error.message}`;", "  }", "}",
             "export function handler(req, res) {", "  const response = { ok: true };",
             "  check(req.query.id, response);", "  res.status(200).json(response);", "}"]
    assert iec._reaches_peer_whole(lines, "response", 3, 0)


# ---- arms C1, C2, H and the excuses ----

@pytest.mark.parametrize(("name", "expected"), [
    ("writeError", True), ("jsonError", True), ("sendJson", True), ("sendJsonError", True), ("respondText", True),
    ("send", False), ("respond", False), ("httpError", False), ("renderJSON", False), ("writeLog", False),
    # review round 1 (RED-R209-6): `err` is a response-shape word; a name with no response verb is not C1
    ("writeErr", True), ("sendErr", True), ("respondErr", True), ("renderError", False), ("errorResponse", False),
])
def test_c1_name_test(name: str, expected: bool) -> None:
    assert iec._is_response_helper(name) is expected


def test_c2_responder_must_be_a_parameter() -> None:
    lines = ["export const handlers = {", "  read: async ({ params, respond }) => {", "    respond(false, String(err));",
             "  },", "};"]
    assert iec._is_param_callback(lines, 3, "respond")
    local = ["function respond(ok, body) { send(body); }", "function h() {", "  respond(false, String(err));", "}"]
    assert not iec._is_param_callback(local, 3, "respond")


def test_helper_writes_its_parameters_whole() -> None:
    lines = ["function sendJson(res, status, body) {", "  res.statusCode = status;", "  res.end(JSON.stringify(body));",
             "}", "function sendError(res, err) {", "  logger.error(err);", "  res.status(500).json({ error: 'INTERNAL' });",
             "}"]
    assert iec._helper_writes(lines, "sendJson") == {2}
    assert iec._helper_writes(lines, "sendError") == set()
    assert iec._helper_writes(lines, "missing") is None


def test_v_excuses_a_validator_sourced_value() -> None:
    lines = ["func Create(w http.ResponseWriter, r *http.Request) {", "\treq, err := validateCreateRequest(r)",
             "\tif err != nil {", "\t\twriteError(w, http.StatusBadRequest, err.Error())", "\t}", "}"]
    assert iec._excused(lines, 4, "err.Error()")
    lines[1] = "\treq, err := h.svc.Create(r)"
    assert not iec._excused(lines, 4, "err.Error()")


def test_v_excuses_a_literal_errors_only_routine() -> None:
    lines = ["func parseLimit(s string) (int, error) {", "\tif s == \"\" {", "\t\treturn 0, errors.New(\"limit is required\")",
             "\t}", "\treturn 1, nil", "}", "func Get(w http.ResponseWriter, r *http.Request) {",
             "\tn, err := parseLimit(r.URL.Query().Get(\"limit\"))", "\tif err != nil {",
             "\t\twriteError(w, 400, err.Error())", "\t}", "}"]
    assert iec._literal_errors_only(lines, "parseLimit")
    assert iec._excused(lines, 10, "err.Error()")


def test_t_excuses_a_content_tested_branch() -> None:
    lines = ["export async function up(req, res) {", "  try { await put(req.body); } catch (err) {",
             "    const text = String(err);", "    if (text.includes('too large')) {",
             "      sendJsonError(res, 413, text);", "    }", "  }", "}"]
    assert iec._excused(lines, 5, "text")
    lines[3] = "    if (text) {"
    assert not iec._excused(lines, 5, "text")


# ---- arm S ----

SWITCH = [
    "export async function chat(req, res) {",
    "  for await (const event of agent.stream(req.body)) {",
    "    switch (event.type) {",
    "      case 'text':",
    "        res.write(JSON.stringify({ text: event.text }));",
    "        break;",
    "      case 'error':",
    "        res.write(JSON.stringify({ error: String(event.error) }));",
    "        break;",
    "    }",
    "  }",
    "}",
]


def test_stream_error_event_under_a_switch_label() -> None:
    assert iec._stream_event(SWITCH, 8, SWITCH[7], TS)


def test_stream_same_line_case_label() -> None:
    lines = ["export async function chat(req, res) {", "  for await (const ev of src()) {", "    switch (ev.type) {",
             "      case 'error': res.write(String(ev.error)); break;", "    }", "  }", "}"]
    assert iec._stream_event(lines, 4, lines[3], TS)


def test_stream_needs_iteration_and_discriminant() -> None:
    no_iter = ["export async function show(req, res) {", "  const r = await load(req.params.id);",
               "  if (r.type === 'error') {", "    res.write(r.error);", "  }", "}"]
    assert not iec._stream_event(no_iter, 4, no_iter[3], TS)
    no_disc = ["export async function rows(req, res) {", "  for await (const row of cursor) {", "    res.write(row.error);",
               "  }", "}"]
    assert not iec._stream_event(no_disc, 3, no_disc[2], TS)


def test_enclosing_blocks_innermost_first() -> None:
    blocks = list(iec._enclosing_blocks(SWITCH, 7))
    assert [r for r, _, _ in blocks][:3] == [2, 1, 0]
    assert blocks[0][2] and "case 'error'" in blocks[0][2][0]


# ---- arms X / X2: definitions ----

def test_definition_renders_a_parameter_detail() -> None:
    renders = ["export function formatFailure(value) {", "  if (value instanceof Error) {",
               "    return `${value.name}: ${value.message}`;", "  }", "  return String(value);", "}"]
    assert iec._definition_renders(renders, 0, 6)
    classifies = ["export function formatQuota(err) {", "  if (err.message.includes('quota')) {", "    return 'QUOTA';",
                  "  }", "  return 'INTERNAL';", "}"]
    assert not iec._definition_renders(classifies, 0, 6)


def test_definition_of_prefers_the_same_file() -> None:
    lines = ["function formatIt(e) { return String(e); }", "res.json({ error: formatIt(err) });"]
    src, rows = iec._definition_of(lines, "formatIt")
    assert src is lines and rows == [0]
    src, rows = iec._definition_of(lines, "formatElsewhere")
    assert src is None and rows == []


def test_file_facts_prefilter() -> None:
    facts = iec._file_facts(SWITCH)
    assert facts.async_iter and facts.w and facts.bare is not None
    quiet = ["const a = 1;", "function f() { return a; }"]
    facts = iec._file_facts(quiet)
    assert not facts.async_iter and not facts.w and facts.bare is None


def test_scan_reports_through_the_entry_point() -> None:
    """The arms run under the public entry point (a scan context is created and released).
    A plain temporary directory: pytest's own names a test path, which the rule skips."""
    root = Path(tempfile.mkdtemp())
    app = root / "srv" / "app"
    app.mkdir(parents=True)
    (app / "h.go").write_text("package h\n\nfunc (h *H) Get(w http.ResponseWriter, r *http.Request) {\n"
                              "\tif err := h.svc.Load(); err != nil {\n"
                              "\t\twriteError(w, 500, err.Error())\n\t}\n}\n")
    try:
        rows = [f["line_start"] for f in iec.check_information_exposure(str(root))["findings"]
                if f["category"] == "CWE-209"]
    finally:
        shutil.rmtree(root)
    assert rows == [5]
    assert iec._SCAN.get() is None
