"""Feature 0101 (OPT209) -- per-line prefilters of the CWE-209 path: identical answers, less work.

Every line of every scanned file passes through `_may_disclose` and
`_may_be_server_error`. Measured on one large real tree (754k lines): the
stack-shape alternation `_DISCLOSURE_ANY` cost 237 ms because it carries an
IGNORECASE branch and so has no literal prefix to skip on, while every one of its
alternatives spells `trace` or `stack` (case-folded) -- a lower-cased `in` test
for both costs 65 ms. The server-error word alternation cost 153 ms where four
`in` tests on the lower-cased line cost 99 ms.

The contract is byte-identical behaviour: each prefilter must answer exactly as
the regex it guards, on every line, including case-folded and non-ASCII text.
"""
from __future__ import annotations

import re

import pytest

from cwe_agent.skills import info_exposure_check as iec

LINES = [
    "",
    "const x = 1;",
    "traceback.print_exc()",
    "TRACEBACK.print_exc()",
    "    traceback.format_exc ()",
    "e.printStackTrace();",
    "debug.PrintStack()",
    "return traceback.format_exc()",
    "RETURN  a + STACKTRACE",
    "return x.stack_trace",
    "return x.Stack_Trace",
    "return xs.ſtack_trace",                       # long s folds to `s` under IGNORECASE
    "return TRACİ",                             # dotted capital I lowers to two code points
    "res.send(err.stack)",
    "res.json({ s: err.stack })",
    "process.stderr.write(err.stack)",
    "res.status(500).json({ error: err.message })",
    "res.Send(x)",
    "res->write(x)",
    "w.Write([]byte(err.Error()))",
    "http.Error(w, err.Error(), 500)",
    "response.sendError(500, e.getMessage())",
    "Response.Write(ex.Message)",
    "return jsonify(msg=str(e))",
    "JSONIFY(str(e))",
    "İSTACK K",
    "x" * 2500 + " res.send(err.stack)",
    "res.send(" + "a" * 2500 + ".stack)",
]


def _disclose_reference(line: str) -> bool:
    if iec._RESPONSE_WRITE.search(line[: iec.MAX_SCAN_CHARS]):
        return True
    return iec._DISCLOSURE_ANY.search(line) is not None


def _server_reference(line: str) -> bool:
    if not any(w in line.lower() for w in iec._SERVER_ERROR_WORDS):
        return False
    return any(p.search(line) for p in iec._SERVER_ERROR_PATTERNS)


@pytest.mark.parametrize("line", LINES)
def test_may_disclose_answers_as_the_regexes(line: str) -> None:
    assert iec._may_disclose(line) == _disclose_reference(line)


@pytest.mark.parametrize("line", LINES)
def test_may_be_server_error_answers_as_the_patterns(line: str) -> None:
    assert iec._may_be_server_error(line) == _server_reference(line)


class _Spy:
    """Stands in for a compiled pattern and counts the searches asked of it."""

    def __init__(self, real) -> None:
        self.real, self.calls = real, 0

    def search(self, text, *a):
        self.calls += 1
        return self.real.search(text, *a)


def test_stack_shapes_are_not_searched_on_a_line_without_stack_words(monkeypatch) -> None:
    spy = _Spy(iec._DISCLOSURE_ANY)
    monkeypatch.setattr(iec, "_DISCLOSURE_ANY", spy)
    for line in ("const total = items.length;", "def run(self):", "if (ready) { go(); }"):
        assert not iec._may_disclose(line)
    assert spy.calls == 0
    assert iec._may_disclose("e.printStackTrace();")
    assert spy.calls == 1


_WORD_ALTERNATION = re.compile("|".join(iec._SERVER_ERROR_WORDS))


@pytest.mark.parametrize("line", LINES)
def test_server_error_literal_tests_answer_as_the_word_alternation(line: str) -> None:
    """The four literal tests replaced a word alternation over the lower-cased line; they
    must find a word exactly where that alternation would."""
    low = line.lower()
    assert iec._spells_server_error_word(low) == (_WORD_ALTERNATION.search(low) is not None)


# ---- the line gate: a line neither the value rule nor an arm can act on costs two tests ----
#
# Measured on one large real tree: 715k lines reach the value check and ~1% can act; the
# per-line set-up (scan context, emitted-set owner, try/finally, the value rule's own entry)
# ran for all of them.

QUIET = [
    "const total = items.length;",
    "for (const item of items) {",
    "  total += item.price * item.count;",
    "}",
    "function formatFailure(value) { return describe(value); }",
]


def _run_lines(path, lines: list[str], findings: list[dict]) -> None:
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(path, line, n, lines, findings)


def test_quiet_lines_skip_the_value_rule(monkeypatch, tmp_path) -> None:
    calls = []
    real = iec._discloses_error
    monkeypatch.setattr(iec, "_discloses_error", lambda *a: calls.append(a[2]) or real(*a))
    findings: list[dict] = []
    _run_lines(tmp_path / "app" / "quiet.ts", list(QUIET), findings)
    assert findings == [] and calls == []


def test_a_sink_line_is_still_judged(monkeypatch, tmp_path) -> None:
    lines = ["export function h(req, res) {", "  try { run(); } catch (err) {",
             "    res.status(500).json({ error: err.message });", "  }", "}"]
    findings: list[dict] = []
    _run_lines(tmp_path / "app" / "h.ts", lines, findings)
    assert [f["line_start"] for f in findings if f["category"] == "CWE-209"] == [3]


def test_quiet_file_is_still_indexed_for_the_tree(tmp_path) -> None:
    """The tree's declaration index is built from every file the walk reads, whether or not
    any of its lines can report (the X arms follow a name to its only definition)."""
    token = iec._SCAN.set(iec._ScanCtx(complete=False))
    try:
        _run_lines(tmp_path / "app" / "quiet.ts", list(QUIET), [])
        assert iec._active_scan().defs.get("formatFailure") == [str(tmp_path / "app" / "quiet.ts")]
    finally:
        iec._SCAN.reset(token)


# ---- `_could_declare`: the tree index asks it of every line holding `(` ----
#
# Measured over the 195k such lines of one large real tree: 168 ms, 108 of it the unanchored
# routine-keyword search, which every keyword-free line paid in full.

DECL_LINES = [
    "foo.bar(x);", "  call(a, b);", "const f = (a) => a;", "export function run(x) {",
    "def handler(request):", "func (s *Server) Serve(w http.ResponseWriter) {", "fn main() {",
    "fun greet(name: String) {", "sub run($x) {", "x.def(1)", "subscribe(fn)", "funnel(x)",
    "public static void main(String[] args) {", "if (ready) { go(); }", "\tdef\tf(x):", "a.function (x)",
]


def _could_declare_reference(raw: str) -> bool:
    return iec._LEADING_DECL.match(raw) is not None or "=>" in raw or "function" in raw or \
        iec._ROUTINE_KEYWORD.search(raw) is not None


@pytest.mark.parametrize("raw", DECL_LINES)
def test_could_declare_answers_as_before(raw: str) -> None:
    assert iec._could_declare(raw) == _could_declare_reference(raw)


def test_keyword_search_skipped_without_a_keyword(monkeypatch) -> None:
    spy = _Spy(iec._ROUTINE_KEYWORD)
    monkeypatch.setattr(iec, "_ROUTINE_KEYWORD", spy)
    assert not iec._could_declare("obj.run(ready);")
    assert not iec._could_declare("foo.bar(x);")
    assert spy.calls == 0
    assert iec._could_declare("x = 1; def f(a): pass")
    assert spy.calls == 1


def test_arm_rows_are_looked_up_once_while_the_arm_file_holds(monkeypatch, tmp_path) -> None:
    calls = []
    real = iec._arm_rows
    monkeypatch.setattr(iec, "_arm_rows", lambda lines, suffix: calls.append(1) or real(lines, suffix))
    _run_lines(tmp_path / "app" / "quiet.ts", list(QUIET), [])
    assert len(calls) == 1


def test_arm_rows_are_looked_up_again_after_the_file_is_dropped(monkeypatch, tmp_path) -> None:
    calls = []
    real = iec._arm_rows
    monkeypatch.setattr(iec, "_arm_rows", lambda lines, suffix: calls.append(1) or real(lines, suffix))
    lines = list(QUIET)
    path = tmp_path / "app" / "quiet.ts"
    _run_lines(path, lines, [])
    iec._drop_file(lines)
    _run_lines(path, lines, [])
    assert len(calls) == 2


# ---- the return-binding expression scan: one table lookup per bracket, not a call ----

def _scan_reference(text: str, start: int, depth: int) -> tuple[int, int | None]:
    """The revision-3 algorithm, verbatim: a top-level `;` ends the expression; so does a
    bracket closing outside it."""
    for m in re.finditer(r"[()\[\]{},;]", text[start:]):
        ch = m.group()
        if ch == ";" and depth == 0:
            return depth, m.start() + start
        depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(ch, 0)
        if depth < 0:
            return depth, m.start() + start
    return depth, None


SCAN_TEXTS = [
    "", "a;", "f(a, b); g()", "{ x: [1, 2] }, y)", "(a; b)", "a, b", "]", ";", "x = { ok: false, error: e.message };",
    "return new Outcome(false, e.message); } }", "a ) b", "((((", "))))", "[;]", "{a;b};c",
]


@pytest.mark.parametrize("text", SCAN_TEXTS)
@pytest.mark.parametrize("start", [0, 1, 3])
@pytest.mark.parametrize("depth", [-2, -1, 0, 1, 2])
def test_scan_expression_answers_as_before(text: str, start: int, depth: int) -> None:
    assert iec._scan_expression(text, start, depth) == _scan_reference(text, start, depth)


@pytest.mark.parametrize("ch", list("()[]{},;"))
@pytest.mark.parametrize("depth", [-2, -1, 0, 1, 2])
def test_stop_tables_cut_where_the_per_character_rule_did(ch: str, depth: int) -> None:
    """The two tables `_scan_expression` reads encode the old per-character rule: a `;` at
    depth 0 ends the expression; so does any character leaving the depth below 0."""
    after = depth + iec._DEPTH_DELTA.get(ch, 0)
    stops = after < iec._STOP_BELOW.get(ch, 0)
    assert stops == ((ch == ";" and depth == 0) or after < 0)


# ---- the per-file call index: a name call needs `(` or `{` on its line ----

def test_called_names_skip_a_line_without_brackets(monkeypatch) -> None:
    real = iec._NAME_CALL
    seen: list[str] = []
    spy = _Spy(real)
    spy.findall = lambda text: seen.append(text) or real.findall(text)
    monkeypatch.setattr(iec, "_NAME_CALL", spy)
    assert set(iec._called_names("const total = items.length;")) == set()
    assert seen == []
    assert set(iec._called_names("run(a); new Box{ v }")) == set(real.findall("run(a); new Box{ v }"))
    assert len(seen) == 1
