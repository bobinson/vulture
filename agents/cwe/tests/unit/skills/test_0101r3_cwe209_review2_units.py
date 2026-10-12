"""Feature 0101 revision 3, review round 2 -- units of the CWE-209 arm corrections.

The E2E contract is tests/e2e/test_0101r3_cwe209_review2.py; these pin the pieces it rests on.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import info_exposure_check as iec


@pytest.mark.parametrize("entries, expected", [
    (["    public readonly ok: boolean", "    public readonly error?: string", " "], ["ok", "error", ""]),
    (["        public bool $ok", "        public ?string $error = null"], ["ok", "error"]),
    (["  ok: boolean", "  error?: string"], None),
])
def test_wrapped_constructor_parameters_are_members(entries: list[str], expected: list[str] | None) -> None:
    assert iec._declared_members(entries) == expected


def test_a_wrapped_constructor_declares_its_members() -> None:
    lines = ["class Outcome {", "  constructor(", "    public readonly ok: boolean,",
             "    public readonly error?: string,", "  ) {}", "}"]
    assert iec._ctor_property_members(lines, "Outcome") == ["ok", "error"]


def _scope(lines: list[str], line_num: int) -> iec._Scope:
    return iec._Scope(lines, line_num, "", 0, ".ts")


@pytest.mark.parametrize("fill, refilled", [
    ("  v.error = e.message;", True),
    ('  v["error"] = String(e);', True),
    ("  Object.assign(v, { ok: false, error: e.message });", True),
    ("  v.update(error=str(e))", True),
    ('  v.error = "could not save, try again";', False),
    ("  audit.error = e.message;", False),
    ("  // v.error = e.message;", False),
])
def test_a_refill_on_the_read_root_between_binding_and_read(fill: str, refilled: bool) -> None:
    lines = ["export async function signup(req, res) {", "  const v = validate(req.body);", fill,
             "  return res.status(400).json({ error: v.error });", "}"]
    assert iec._refilled_since_binding("v", "error", _scope(lines, 4)) is refilled


def test_a_fill_above_the_binding_is_not_a_refill() -> None:
    lines = ["export async function signup(req, res) {", "  v.error = e.message;", "  const v = validate(req.body);",
             "  return res.status(400).json({ error: v.error });", "}"]
    assert iec._refilled_since_binding("v", "error", _scope(lines, 4)) is False


@pytest.mark.parametrize("param, args, expected", [
    ("err", " err", True),                      # Go `fmt.Fprint(w, err)`: the name no longer hides it
    ("e", " e.Error() ,  500", True),           # an error-text member of the parameter
    ("e", "e.message", True),
    ("e", "e.getMessage()", True),
    ("e", "e.code", False),
    ("error", "JSON.stringify({ error: text })", False),   # a key named like the parameter is no write of it
    ("error", 'json.dumps({"error": text})', False),       # nor is a quoted key or literal text
    ("err", "render(err=msg)", False),                      # nor a keyword argument's name
    ("msg", "ok ? msg : fallback", True),                    # a ternary's branch is a value
    ("msg", '"internal error"', False),
    ("", "x", False),
])
def test_a_parameter_written_whole_converted_or_through_its_error_member(param: str, args: str,
                                                                          expected: bool) -> None:
    assert iec._written_whole(param, args) is expected


@pytest.mark.parametrize("header, row, reported", [
    ("func fail(w http.ResponseWriter, err error) {", "\thttp.Error(w, err.Error(), 500)", True),   # CWE-550 shape
    ("function fail(res: any, err: Error) {", "  res.status(500).send(err.message);", True),        # value rule
    ("func fail(w http.ResponseWriter, err error) {", "\tfmt.Fprint(w, err)", False),
    ("function fail(res: any, e: Error) {", "  res.status(500).send(e.message);", False),
])
def test_the_base_rule_reporting_a_helper_row(header: str, row: str, reported: bool) -> None:
    assert iec._row_reported([header, row, "}"], 1) is reported


@pytest.mark.parametrize("before, local", [
    ("return Results", False),
    ("return TypedResults", False),
    ("ResultsLog", True),
    ("Fault", True),
])
def test_a_results_factory_root_is_the_peer(before: str, local: bool) -> None:
    assert iec._receiver_is_local(before) is local


@pytest.mark.parametrize("producer, fills", [
    ("  catch (e: any) { return Result.fail(e.message); }", True),
    ("  catch (e: any) { return Outcome.failure(String(e)); }", True),
    ('  catch (e: any) { return Result.fail("INVALID_BODY"); }', False),
    ("  catch (e: any) { return Result.track(e.message); }", False),
    ('  catch (e: any) { return Result.fail("E1", e.message); }', False),
    ("  catch (e: any) { return sanitizeError(e); }", False),       # a sanitiser names the error, it is no failure
    ("  catch (e: any) { return toPublicError(e); }", False),
    ("  catch (e: any) { return Err(e.to_string()); }", True),
])
def test_an_error_role_factory_fills_the_error_field(producer: str, fills: bool) -> None:
    lines = ["function validate(body: any) {", "  try { parse(body); return Result.ok(); }", producer, "}"]
    assert iec._producer_fills(lines, "error", "validate", 0) is fills


def test_a_same_file_factory_is_judged_by_its_body_not_its_name() -> None:
    lines = ["function fail(code: string) { return { ok: false, error: code }; }",
             "function validate(body: any) {", "  try { parse(body); return { ok: true }; }",
             "  catch (e: any) { return fail(e.message); }", "}"]
    assert iec._error_factory_fill(lines, (3, 0, "fail"), "", "e.message") is False
