"""Feature 0101 revision 3, review round 1 -- unit contracts of the CWE-209 arm corrections."""
from __future__ import annotations

import pytest

from cwe_agent.skills import info_exposure_check as iec


@pytest.mark.parametrize(("entry", "name_first", "expected"), [
    ("w http.ResponseWriter", True, "w"), (" msg string", True, "msg"), ("args ...any", True, "args"),
    ("code", True, "code"), ("_ w: Writer", True, "w"), ("String msg", False, "msg"), ("msg: string", False, "msg"),
])
def test_parameter_entry_names(entry: str, name_first: bool, expected: str) -> None:
    assert iec._entry_name(entry, name_first) == expected


def test_go_helper_parameters_are_names_not_types() -> None:
    assert iec._helper_params("func fail(w http.ResponseWriter, msg string) {", "fail") == ["w", "msg"]
    assert iec._helper_params("func (h *H) fail(w http.ResponseWriter, code int, msg string) {", "fail") == \
        ["w", "code", "msg"]
    assert iec._helper_params("def fail(handler, msg):", "fail") == ["handler", "msg"]


@pytest.mark.parametrize(("args", "expected"), [
    ("msg.encode()", True), ("msg.encode('utf-8')", True), ("[]byte(msg)", True), ("msg", True),
    ("msg.length", False), ("msg[0]", False), ("message", False),
])
def test_parameter_written_whole_or_converted(args: str, expected: bool) -> None:
    assert iec._written_whole("msg", args) is expected


@pytest.mark.parametrize(("row", "expected"), [
    ("\thttp.Error(w, msg, http.StatusInternalServerError)", ["msg , http.StatusInternalServerError"]),
    ("\tfmt.Fprintf(w, \"%s\", msg)", ["\"%s\" , msg"]),
    ("\tio.WriteString(w, msg)", ["w, msg", "msg"]),   # also a member-call sink (`.WriteString(`)
    ("\t_ = json.NewEncoder(w).Encode(map[string]string{\"error\": msg})", ["map[string]string{\"error\": msg}"]),
    ("\tfmt.Fprintln(os.Stderr, msg)", []),
    ("\t_ = json.NewEncoder(buf).Encode(msg)", []),
    ("\tslog.ErrorContext(ctx, msg)", []),
    ("\tcount(w, msg)", []),
])
def test_writes_that_take_the_peer_writer_as_an_argument(row: str, expected: list[str]) -> None:
    lines = ["func fail(w http.ResponseWriter, msg string) {", row, "}"]
    assert [" ".join(a.split()) for a in iec._peer_write_arguments(lines, 1, row)] == expected


def test_a_routine_header_is_not_a_writer_write() -> None:
    lines = ["function sendJson(res, status, body) {", "  res.end(JSON.stringify(body));", "}"]
    assert list(iec._peer_write_arguments(lines, 0, lines[0])) == []
    assert iec._helper_writes(lines, "sendJson") == {2}


@pytest.mark.parametrize(("decl", "expected"), [
    ("  constructor(public ok: boolean, public error?: string) {}", ["ok", "error"]),
    ("  constructor(public ok: boolean, error?: string) {}", ["ok", ""]),
    ("    public function __construct(public bool $ok, public ?string $error = null) {}", ["ok", "error"]),
    ("    public function __construct(private readonly Clock $clock) {}", ["clock"]),
    ("  constructor(ok, error) { this.ok = ok; this.error = error; }", None),
])
def test_constructor_parameter_members(decl: str, expected: list[str] | None) -> None:
    lines = ["class Outcome {", decl, "}"]
    assert iec._type_members(lines, "Outcome") == expected


def test_constructor_members_stop_at_the_next_class() -> None:
    lines = ["class Outcome {", "}", "class Other {", "  constructor(public error: string) {}", "}"]
    assert iec._type_members(lines, "Outcome") is None


@pytest.mark.parametrize(("text", "expected"), [
    ('{ ok: false, error: "email is required" }', True), ('Check(False, "name is required")', True),
    ('Check{OK: false, Error: "x"}', True), ('Outcome(false, "E", Codes.X_Y)', True), ("null", True),
    ("{ ok: false, error: reason }", False), ('Check(False, f"bad {exc}")', False), ("format_exc()", False),
    ("new Outcome(false, e.message)", False), ("Codes.NotFound", False), ('ok ? "a" : msg', False),
])
def test_literal_values(text: str, expected: bool) -> None:
    assert iec._literal_text(text) is expected


def test_a_literal_only_producer_decides_and_a_parameter_fill_does_not() -> None:
    lines = ["function validate(body) {", '  if (!body.email) return { ok: false, error: "email is required" };',
             "  return { ok: true };", "}",
             "function classify(body, reason) {", "  if (!body.email) return { ok: false, error: reason };",
             "  return { ok: true };", "}"]
    assert iec._producer_decides(lines, "error", "validate")
    assert not iec._producer_decides(lines, "error", "classify")
    assert not iec._producer_decides(lines, "error", "missing")
    assert not iec._producer_decides(lines, "error", None)
