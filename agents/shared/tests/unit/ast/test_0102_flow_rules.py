"""Feature 0102, plan task 2.3 (LLD §8.1-§8.5, D8, D9, D22, D23): the flow engine's rules.

One test per row of the propagation table (§8.2) and of the same-file interprocedural rules
(§8.4), including one per structural rule R-A ... R-X, each on the ``ast_v1`` fixture the
scenario matrix names for it (R-U, R-V and R-W on Go, Java, Rust and PHP sources where the
language has the shape); the family policy (D22, R-P); the plan's named cases (the D6
join, the loop's extra pass, the identity function, the dead call, the partial sanitiser,
``partial(subprocess.run, shell=True)``, the dynamic write, the depth-2 memoised summary, the
recursion cut, the ``MAX_ORIGINS`` collapse); ``decide`` on each of its outcomes against the
harness's recording ``AuditContext``; the revision-9 decision tests (L3, L6, L7, L8, L9/P4/R5,
C2, C3) and the walk corrections (W4, W5/R7/R9/R10, W6, W8, W9, W10, W11, W12, W13, W14); and
the lead's rulings A28 (R-A's payload words win over R-C; R-Q is ``none``, never a decline;
R-P inside ``candidates`` with ``Flow.filtered_roles`` and ``decide``'s two R-P tallies;
``Hop(line, kind, name)`` and ``Flow.arg``; mutual recursion), A30 (1) (``decide`` takes the
consumer's ``path`` and hands it to ``ctx.decline``) and A36 (C++ R-X over a subscript: the
worker ships the argument as SUBSCRIPT(NAME, INDEX) in a synthetic CALL beside C3's).

Guard clauses (§8.5 "Guard", L4, L11, L12 end to end, W2) are ``test_0102_guards.py``'s; the
caps of §8.7 at cap + 1 are ``test_0102_limits.py``'s. A guard appears here only where a rule
of §8.4 produces it (R-R) or a walk correction names a guard outcome (W8).

How a case is read. Every model comes from a real worker through ``_analysis`` (``program``,
``fixture_model``); an inline program is dedented, so its line 1 is its first line. A rule's
effect is asserted as what the analysis exposes (§5): the origins of a node, the candidate
flows of a family, and what ``decide`` makes of them (``judge``: the harness's stub rule and
recording context). "Reports" means ``decide`` returns ``report`` for a candidate on that sink
line; "no sink" means no candidate's sink is that CALL. Lines are compared as sets: one
finding per sink line is the consumer's unit (§9.2), and a rule that emits several flows for
one sink is checked by its own count where the LLD states one (§8.4: once per sink node and
canonical origin set).

RED until plan task 2.3: ``shared.ast.flow`` does not exist, so ``model.analysis()`` and the
harness's ``flow_mod()`` raise ``ModuleNotFoundError`` inside each test (the module collects).
"""

from __future__ import annotations

import functools
import itertools
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from shared.ast import FileModel
from shared.ast.kinds import Field, Kind
from tests.unit.ast._analysis import (
    FAMILIES,
    Spec,
    analysis_of,
    call_at,
    candidates_of,
    constant,
    decided,
    external,
    externals,
    fixture_model,
    flow_mod,
    flow_with,
    flows_on,
    fresh_context,
    judge,
    origins_of,
    program,
    source_of,
    stub_guard,
    subject,
    unknown,
)
from tests.unit.ast._audit import rendered

if TYPE_CHECKING:
    from shared.ast.flow import Flow, Origin

pytestmark = pytest.mark.usefixtures("real_pool")

# A case's subject is a ``Spec`` (``_analysis.subject``): an ``ast_v1`` fixture by stem, or an
# inline ``(lang, source)`` program, dedented with its leading newline dropped (``program``).

# ── helpers ──────────────────────────────────────────────────────────────────


def _lines(m: FileModel, family: str, **options: Any) -> set[int]:
    """The sink lines ``decide`` reports for ``family`` (``options`` as ``judge`` takes
    them: ``server_ctx``, ``gate``)."""
    return set(judge(m, family, **options).reported)


def _labels(m: FileModel, family: str) -> set[str]:
    """The labels of the declines ``decide`` records for ``family``."""
    return set(judge(m, family).declines)


def _externals(m: FileModel, family: str, line: int) -> frozenset[Origin]:
    """Every external origin of the ``family`` candidates on ``line``."""
    return externals(o for f in flows_on(m, family, line) for o in f.origins)


def _holding(m: FileModel, family: str, line: int, origin: Origin) -> list[Flow]:
    """The ``family`` candidates on ``line`` whose origins hold ``origin``."""
    return [f for f in flows_on(m, family, line) if origin in f.origins]


def _sinks(m: FileModel, family: str) -> set[int]:
    """The sink CALLs of the ``family`` candidates."""
    return {f.sink for f in candidates_of(m, family)}


def _arg(m: FileModel, head: str, n: int = 0, *, line: int | None = None) -> frozenset[Origin]:
    """``origins`` of argument ``n`` of the CALL ``head`` (on ``line``)."""
    return origins_of(m, m.args(call_at(m, head, line=line))[n])


def _calls_of(m: FileModel, head: str, count: int) -> list[int]:
    """The first ``count`` CALLs ``head``, in order."""
    return [call_at(m, head, nth=k) for k in range(count)]


def _calls_on(m: FileModel, line: int) -> list[int]:
    """Every CALL on ``line``, in order."""
    return [c for c in m.calls() if m.line(c) == line]


# An origin written as data, so a parametrize table names it before ``shared.ast.flow``
# exists: ("external", role, *via) | ("unknown", reason) | ("constant",).
_MAKERS = {"external": external, "unknown": unknown, "constant": constant}


def _origin(spec: tuple[str, ...]) -> Origin:
    """The ``Origin`` a spec names."""
    cls, *rest = spec
    return _MAKERS[cls](*rest)


# ── §8.2 propagation table: one test per row ─────────────────────────────────


def test_literal_and_substitution_free_template_are_constant() -> None:
    m = program("js", 'sink("a.txt", `b.txt`, 3, true, null, /x/);\n')

    assert [origins_of(m, a) for a in m.args(call_at(m, "sink"))] == [frozenset({constant()})] * 6


_UNION = {
    "template": "`${a}/${b}`",
    "binop": "a + b",
    "ternary": "a ? a : b",
    "array": "[a, b]",
    "object": "{ x: a, y: b }",
    "spread": "[...a, b]",
    "await": "await a",
    "unary": "!a",
}


@pytest.mark.parametrize("expr", _UNION.values(), ids=list(_UNION))
def test_composite_is_the_union_of_its_children(expr: str) -> None:
    # TEMPLATE, BINOP, TERNARY, ARRAY, OBJECT, PAIR, SPREAD, AWAIT, UNARY: union of children.
    m = program("js", f"""
        async function h(req) {{
          const a = req.query.a;
          const b = "k";
          sink({expr});
        }}
        """)
    node = m.args(call_at(m, "sink"))[0]

    got = origins_of(m, node)

    assert got == frozenset().union(*(origins_of(m, c) for c in m.children(node)))
    assert external("request") in got


def test_name_reads_its_def_else_a_source_word_else_unresolved() -> None:
    m = program("js", 'const p = "x";\nsink(p, argv, mystery);\n')

    assert [_arg(m, "sink", n) for n in range(3)] == [
        frozenset({constant()}),
        frozenset({unknown("argv")}),  # W9 (b): the root word; A47 D22-c: unknown outside C4
        frozenset({unknown("unresolved")}),
    ]


_PARAMS = {
    "request word": ("js", "function h(req) {\n  sink(req);\n}\n", ("external", "request")),
    "catch": ("js", "try {\n  go();\n} catch (err) {\n  sink(err);\n}\n", ("external", "error")),
    "hint (R-T)": ("js", "function show(filename) {\n  sink(filename);\n}\n", ("external", "param_hint")),
    "plain": ("js", "function h(p) {\n  sink(p);\n}\n", ("unknown", "param")),
    "c main argv": ("c", "int main(int argc, char **argv) {\n    sink(argv);\n    return 0;\n}\n",
                    ("external", "argv")),
    "c main argv[]": ("c", "int main(int argc, char *argv[]) {\n    sink(argv);\n    return 0;\n}\n",
                      ("external", "argv")),
    "c argv outside main": ("c", "int run(int argc, char **argv) {\n    sink(argv);\n    return 0;\n}\n",
                            ("unknown", "param")),
}


@pytest.mark.parametrize(("lang", "source", "expected"), _PARAMS.values(), ids=list(_PARAMS))
def test_param_origin(lang: str, source: str, expected: tuple[str, ...]) -> None:
    # PARAM: request word / CATCH -> error / R-T -> param_hint / C main argv (C4) / else
    # unknown(param). R-A ... R-E are each their own structural test below.
    m = program(lang, source)

    assert _arg(m, "sink") == {_origin(expected)}


def test_member_reads_its_binding_else_its_root_source() -> None:
    m = program("js", """
        function h(req) {
          const o = {};
          o.f = req.query.f;
          sink(o.f);
        }
        sink(req.body, resp.body, document.body, x.query);
        sink(process.env.HOME, process.argv, event.body);
        """)
    bound, chains, conditional = _calls_of(m, "sink", 3)

    assert origins_of(m, m.args(bound)[0]) == {external("request")}  # read("o.f")
    assert [externals(origins_of(m, a)) for a in m.args(chains)] == [
        {external("request")}, frozenset(), frozenset(), frozenset(),  # W9 (b): ROOT word only
    ]
    # CONDITIONAL_SOURCE_ROOTS; A47 D22-c: argv outside C4 is unknown(argv), no external
    found = map(functools.partial(origins_of, m), m.args(conditional))
    assert [(externals(o), unknown("argv") in o) for o in found] == [
        ({external("env")}, False), (frozenset(), True), ({external("request")}, False),
    ]


def test_member_root_bound_by_an_import_is_skipped() -> None:
    m = program("py", "import flask\n\nsink(flask.request.args)\n")

    assert external("request") in _arg(m, "sink")


def test_subscript_is_object_and_key_plus_a_literal_key_source() -> None:
    m = program("py", """
        def handler(event, context, docs):
            sink(docs[request.args["i"]], event["body"], event[k])
        """)
    index, literal_key, dynamic_key = m.args(call_at(m, "sink"))

    assert external("request") in origins_of(m, index)  # origins(o) | origins(k)
    assert external("request") in origins_of(m, literal_key)  # M1: "body" joins the chain
    assert externals(origins_of(m, dynamic_key)) == frozenset()  # a NAME key joins no chain


def test_sanitiser_call_adds_its_roles_to_via() -> None:
    m = program("js", "sink(path.basename(req.query.f), basename(req.query.f + mystery));\n")

    assert _arg(m, "sink", 0) == {external("request", "path_normalize")}
    assert _arg(m, "sink", 1) == {external("request", "path_normalize"), unknown("unresolved")}


def test_shell_quote_sanitiser_keeps_non_external_members() -> None:
    m = program("py", 'import shlex\n\nsink(shlex.quote(request.args["d"]))\n')

    assert externals(_arg(m, "sink")) == {external("request", "shell_quote")}


_NUMERIC = {
    "Number": ("js", "sink(Number(req.query.i));\n"),
    "parseInt": ("js", "sink(parseInt(req.query.i, 10));\n"),
    "int": ("py", 'sink(int(request.args["i"]))\n'),
    "strconv.Atoi": (
        "go",
        'package app\n\nfunc h(r *http.Request) {\n\tsink(strconv.Atoi(r.FormValue("i")))\n}\n',
    ),
}


@pytest.mark.parametrize(("lang", "source"), _NUMERIC.values(), ids=list(_NUMERIC))
def test_numeric_call_is_constant(lang: str, source: str) -> None:
    # R4: SANITIZER_KEYS["numeric"] by EXACT glued key -> {constant} | non-external members.
    m = program(lang, source)

    assert _arg(m, "sink") == {constant()}


def test_a_number_word_inside_a_name_is_not_numeric() -> None:
    m = program("js", "sink(formatPhoneNumber(req.query.i));\n")

    assert external("request") in _arg(m, "sink")  # rule 15 pass-through (B24)


def test_source_call_takes_the_role_of_its_reading_function() -> None:
    m = program("py", 'import os\n\nsink(input(), os.getenv("X"), sock.recv(1024))\n')

    assert [externals(_arg(m, "sink", n)) for n in range(3)] == [
        {external("stdin")}, {external("env")}, {external("network")},  # SOURCE_CALL_KEYS
    ]


def test_accessor_shaped_call_on_a_request_receiver_is_a_request_read() -> None:
    m = program("js", 'function h(req) {\n  sink(req.headers.get("x"));\n}\n')

    assert externals(_arg(m, "sink")) == {external("request")}  # L6, W9 (c)


def test_unknown_callee_propagates_args_and_receiver() -> None:
    m = program("js", "sink(JSON.parse(req.body.raw), req.body.raw.trim(), now());\n")

    assert external("request") in _arg(m, "sink", 0)  # the arguments
    assert external("request") in _arg(m, "sink", 1)  # the receiver
    assert _arg(m, "sink", 2) == {unknown("external_call")}  # neither


def test_destructured_leaf_reads_its_rhs_path() -> None:
    m = program("js", """
        function h(req) {
          const { a, b: { c }, ...rest } = req.body;
          const [first] = req.query.list;
          sink(a, c, rest, first);
        }
        """)

    assert all(external("request") in _arg(m, "sink", n) for n in range(4))


def test_anything_else_is_unresolved() -> None:
    m = program("js", "sink(() => 1);\n")

    assert _arg(m, "sink") == {unknown("unresolved")}


# ── §8.4 same-file interprocedural rules ─────────────────────────────────────

_SUMMARY = """
    def read_it(p, mode="r"):
        return open(p, mode)


    def two(a, b):
        return open(b)


    def handler(request):
        read_it(mode="r", p=request.args["f"])
        two(request.args["f"])
    """


def test_summary_binds_positionally_then_by_keyword_and_unmatched_is_arity() -> None:
    m = program("py", _SUMMARY)

    assert _lines(m, "path") == {2}  # p bound by keyword
    assert _holding(m, "path", 6, unknown("arity")) != []  # b unmatched


_CALLEE_SINK = """
    function readIt(p) {
      return fs.readFile(p, () => {});
    }
    function a(req) {
      return readIt(req.query.f);
    }
    function b(req) {
      return readIt(req.body.g);
    }
    """


def test_callee_sink_is_emitted_once_per_canonical_origins_with_the_call_site_first() -> None:
    m = program("js", _CALLEE_SINK)
    tainted = _holding(m, "path", 2, external("request"))

    assert (len(tainted), judge(m, "path").reported) == (1, (2,))
    assert (tainted[0].hops[0].kind, tainted[0].hops[0].line in (5, 8)) == ("call", True)


@pytest.mark.parametrize(("stem", "family", "line"), [
    ("cwe_22_13_clean", "path", 6),  # local function readFile
    ("cwe_78_2_clean", "command", 8),  # local function exec
])
def test_a_local_function_is_never_a_sink_by_word(stem: str, family: str, line: int) -> None:
    m = fixture_model(stem)
    shadow = _calls_on(m, line)

    assert _sinks(m, family).isdisjoint(shadow)
    assert _lines(m, family) == set()


def test_a_local_function_is_never_a_source_or_sanitiser_by_word() -> None:
    m = program("js", 'function input() {\n  return "x";\n}\nfs.readFile(input(), () => {});\n')

    assert _lines(fixture_model("cwe_22_10"), "path") == {6}  # local basename: identity
    assert externals(_arg(m, "fs.readFile")) == frozenset()  # local input(): its summary


def test_sink_rebinding_still_reports_with_an_external_origin() -> None:
    m = program("js", 'fs.readFile = wrapper;\nfs.readFile("index.html", () => {});\n')

    assert _lines(fixture_model("cwe_22_54"), "path") == {4}
    assert _lines(m, "path") == set()  # no external origin: not reported


_PARTIAL = """
    from functools import partial

    go = partial(job.run, shell=True)
    stay = partial(job.run)


    def handler(request):
        go("ls " + request.args["d"])
        stay("ls " + request.args["d"])
    """


def test_partial_application_inherits_the_sink_and_its_prebound_kwargs() -> None:
    assert _lines(fixture_model("cwe_78_3"), "command") == {9}  # partial(subprocess.run, shell=True)
    assert _lines(program("py", _PARTIAL), "command") == {8}  # weak run: shell=True strengthens


# ── §8.4 structural rules R-A ... R-X ────────────────────────────────────────


def test_ra_handler_callback_payload_is_network() -> None:
    m = fixture_model("cwe_22_25")

    assert _lines(m, "path") == {3}
    assert external("network") in _externals(m, "path", 3)


_REGISTERED = """
    emitter.on("job", (payload, opts) => {
      fs.readFile(payload, () => {});
      fs.readFile(opts, () => {});
    });
    """


def test_ra_payload_params_are_network_and_the_others_request() -> None:
    # A28 (1): a callback registered through HANDLER_REGISTRATION_WORDS - its params whose
    # words hit CALLBACK_PAYLOAD_WORDS are external(network), R-A winning over the request
    # word `payload`; its other params get R-C's external(request).
    m = program("js", _REGISTERED)

    assert _lines(m, "path") == {2, 3}
    assert [{o.role for o in _externals(m, "path", line)} for line in (2, 3)] == [
        {"network"}, {"request"},
    ]


_REDUCE = """
    function h(req) {
      req.body.names.reduce((acc, n) => fs.readFile(n, () => {}), "");
      req.body.names.reduce((acc, n) => fs.readFile(acc, () => {}), "");
    }
    """


@pytest.mark.parametrize(("spec", "family", "lines"), [
    ("cwe_22_26", "path", {4}),  # forEach: PARAM 0
    ("cwe_918_15", "request", {4}),
    (("js", _REDUCE), "path", {2}),  # reduce: PARAM 1, never PARAM 0
], ids=["forEach", "forEach-request", "reduce"])
def test_rb_iteration_callback_param_takes_the_receiver(spec: Spec, family: str, lines: set[int]) -> None:
    assert _lines(subject(spec), family) == lines


_REPLY = "def view(request, reply):\n    return open(reply)\n"


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_22_23", {4}),  # a route-word decorator
    ("cwe_22_24", {3}),  # a request-named first parameter
    (("py", _REPLY), set()),  # a response-named parameter is never a source
], ids=["decorator", "first-param", "response-named"])
def test_rc_route_handler_params_are_requests(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "path") == lines


@pytest.mark.parametrize(("stem", "line", "role"), [
    ("cwe_22_21", 4, "request"),  # @Query("f")
    ("cwe_22_22", 3, "upload"),  # UploadFile = File(...)
])
def test_rd_annotated_param(stem: str, line: int, role: str) -> None:
    m = fixture_model(stem)

    assert _lines(m, "path") == {line}
    assert external(role) in _externals(m, "path", line)


def test_re_destructured_param_leaf_by_its_own_name() -> None:
    m = fixture_model("cwe_22_27")

    assert _lines(m, "path") == {3}
    assert external("request") in _externals(m, "path", 3)


def test_rf_this_method_resolves_in_the_enclosing_class() -> None:
    assert _lines(fixture_model("cwe_22_30"), "path") == {4}


def test_rg_assigned_function_is_a_function_def() -> None:
    assert _lines(fixture_model("cwe_22_31"), "path") == {2}


def test_ri_request_sink_result_is_network() -> None:
    m = fixture_model("cwe_22_49")

    assert _lines(m, "path") == {5}
    assert external("network") in origins_of(m, call_at(m, "fetch"))
    assert external("network") in _externals(m, "path", 5)


def test_rj_merge_writes_dynamic_origins_into_the_target() -> None:
    m = fixture_model("cwe_22_34")
    merged = _arg(m, "fs.readFile")

    assert _lines(m, "path") == {5}
    assert {external("request"), unknown("dynamic")} <= merged


_DEEP_READ = """
    function h(req) {
      const o = {};
      o.p = req.query.f;
      sink(o.p.q);
    }
    """


def test_rk_deep_write_never_launders_and_deep_read_is_prefix_and_depth() -> None:
    m = fixture_model("cwe_22_35")

    assert (_lines(m, "path"), _labels(m, "path")) == ({4}, set())
    assert {external("request"), unknown("depth")} <= _arg(program("js", _DEEP_READ), "sink")


def test_rl_dollar_with_a_template_is_a_command_sink() -> None:
    plain = program("js", "function h(req) {\n  $(req.query.sel);\n}\n")

    assert _lines(fixture_model("cwe_78_9"), "command") == {4}
    assert _lines(plain, "command") == set()  # no TEMPLATE argument


@pytest.mark.parametrize(("stem", "lines"), [
    ("cwe_78_8", {5}),  # execa: the exec prefix
    ("cwe_78_18", {6}),  # check_output -> checkoutput
    ("cwe_78_16_clean", set()),  # execute: an exact weak key beats the prefix (L2)
])
def test_rn_strong_prefix_unless_an_exact_weak_key(stem: str, lines: set[int]) -> None:
    assert _lines(fixture_model(stem), "command") == lines


def test_ro_closure_reads_the_join_of_every_enclosing_def() -> None:
    m = fixture_model("cwe_22_36")

    assert _lines(m, "path") == {5}
    assert external("request") in _externals(m, "path", 5)


# A command-line program's own arguments and its stdin, each read at a request sink
_ARGV_FETCH = ("js", "function h() {\n  fetch(process.argv[2]);\n}\n")
_STDIN_FETCH = ("js", "function h() {\n  fetch(process.stdin.read());\n}\n")
_POLICY = {
    "env-path": ("cwe_22_48", "path", 3, set(), set()),
    # A47 D22-c: process.argv is unknown(argv), which a rule with no D25 hook leaves unreported
    "argv-command": ("cwe_78_14", "command", 5, set(), set()),
    "c4-argv-command": ("cwe_78_cpp_1", "command", 7, {7}, {"argv"}),
    "env-command": ("cwe_78_15_clean", "command", 5, set(), set()),
    "argv-request": (_ARGV_FETCH, "request", 2, set(), set()),
    "stdin-request": (_STDIN_FETCH, "request", 2, set(), set()),
}


@pytest.mark.parametrize(("spec", "family", "line", "lines", "roles"), _POLICY.values(), ids=list(_POLICY))
def test_rp_family_policy(spec: Spec, family: str, line: int, lines: set[int], roles: set[str]) -> None:
    # D22: env reports for no family; argv/stdin for path and command, never request. An
    # origin outside the family's set is removed before decide runs.
    m = subject(spec)

    assert (_lines(m, family), {o.role for o in _externals(m, family, line)}) == (lines, roles)


def test_rp_a_flow_it_empties_is_none_and_tallied_env_only() -> None:
    # W15 (c): an env-only flow with nothing unknown is `none`, never unknown_only_sinks;
    # A28 (3): decide tallies it env_only_sinks (its filtered_roles are {env}, nothing remains).
    j = judge(program("py", 'import os\nopen(os.getenv("DOC"))\n'), "path")

    assert (j.reported, j.declines, j.tallies) == ((), (), {"env_only_sinks": 1})


_FILTERED = {
    "env-path": ("cwe_22_48", "path", 3, {"env"}),
    # A47 D22-c: process.argv is unknown(argv), no external origin, so R-P removes nothing
    "argv-request": (_ARGV_FETCH, "request", 2, set()),
    # D22: stdin reports for path and command, never request, so R-P removes it here
    "stdin-request": (_STDIN_FETCH, "request", 2, {"stdin"}),
    "argv-command": ("cwe_78_14", "command", 5, set()),
}


@pytest.mark.parametrize(("spec", "family", "line", "filtered"), _FILTERED.values(), ids=list(_FILTERED))
def test_rp_runs_inside_candidates_and_records_the_roles_it_removed(
    spec: Spec, family: str, line: int, filtered: set[str]
) -> None:
    # A28 (3): R-P runs inside candidates(family); each Flow carries filtered_roles, the
    # roles R-P removed from its origins (empty when it removed none).
    m = subject(spec)

    assert [set(f.filtered_roles) for f in flows_on(m, family, line)] == [filtered]


def test_rq_numeric_coercion_leaves_no_external_origin() -> None:
    # A28 (2): a numeric coercion is {constant}, so the sink is `none` - no report, and no
    # decline either (scenario B15 as amended).
    m = fixture_model("cwe_22_47_clean")
    j = judge(m, "path")

    assert (_lines(m, "path"), _externals(m, "path", 4)) == (set(), frozenset())
    assert (j.reported, j.declines) == ((), ())


def test_rr_try_relative_to_is_a_containment_guard() -> None:
    m = fixture_model("cwe_22_46_clean")

    assert (_lines(m, "path"), _labels(m, "path")) == (set(), {"guarded:path_contain"})


_PARENT = """
    from pathlib import Path


    def handler(request):
        name = Path(request.args["f"]).parent
        return open(name)
    """


def test_rs_name_member_on_a_path_call_is_path_normalize() -> None:
    m = fixture_model("cwe_22_42_clean")

    assert (_lines(m, "path"), _labels(m, "path")) == (set(), {"sanitized:path_normalize"})
    assert _lines(program("py", _PARENT), "path") == {6}  # .parent is no name/stem


def test_rt_param_hint_reports_for_path_never_for_request() -> None:
    m = fixture_model("cwe_22_37")
    fetched = program("js", "function show(filename) {\n  fetch(filename);\n}\n")

    assert _lines(m, "path") == {3}
    assert external("param_hint") in _externals(m, "path", 3)
    assert _lines(fetched, "request") == set()


_RU_RUST = """
    fn show(req: HttpRequest) -> String {
        let f = req.match_info().get("f").unwrap();
        fs::read_to_string(f).unwrap()
    }
    """


@pytest.mark.parametrize(("spec", "head", "accessor_line", "sink_line"), [
    ("cwe_22_go_2", "c.Query", 7, 8),  # Gin: *gin.Context -> context
    ("cwe_22_java_2", "request.getParameter", 6, 7),
    (("rs", _RU_RUST), "req.match_info", 2, 3),
    ("cwe_22_php_3", "$request->input", 6, 6),  # Laravel
], ids=["go", "java", "rust", "php"])
def test_ru_request_accessor(spec: Spec, head: str, accessor_line: int, sink_line: int) -> None:
    m = subject(spec)

    assert external("request") in origins_of(m, call_at(m, head, line=accessor_line))
    assert _lines(m, "path") == {sink_line}


_RV_PHP = """
    <?php
    $u = $_GET['u'];
    $request = new Request('GET', $u);
    $client->send($request);
    """


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_918_go_2", {10}),  # Do on a client carrier
    ("cwe_918_java_1", {7}),  # openConnection on new URL(...)
    ("cwe_918_rs_2", {8}),  # send on a client carrier
    (("php", _RV_PHP), {4}),  # send: the carrier argument joins (W10)
], ids=["go", "java", "rust", "php"])
def test_rv_request_terminal_on_a_carrier(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "request") == lines


_RW_GO = """
    package app

    func show(w http.ResponseWriter, r *http.Request) {
        var form struct{ Path string }
        json.NewDecoder(r.Body).Decode(&form)
        os.ReadFile(form.Path)
    }
    """
_RW_RUST = """
    fn show(req: HttpRequest) -> String {
        let mut name = String::new();
        req.body().decode(&mut name);
        fs::read_to_string(name).unwrap()
    }
    """


@pytest.mark.parametrize(("lang", "source", "line"), [
    ("go", _RW_GO, 6),  # Decode(&form)
    ("rs", _RW_RUST, 4),  # decode(&mut name)
], ids=["go", "rust"])
def test_rw_output_parameter_takes_the_receiver(lang: str, source: str, line: int) -> None:
    # Java and PHP have no reference argument, so R-W has no shape there.
    m = program(lang, source)

    assert _lines(m, "path") == {line}
    assert external("request") in _externals(m, "path", line)


# R-H is test_rh_callee_key_from_imported_symbol, R-M test_rm_needs_interpreter_and_flag and
# R-X test_rx_vexing_parse_is_a_constructor_call (revision 9 and walk corrections, below).

# ── the plan's named cases ───────────────────────────────────────────────────


def test_d6_join_keeps_the_raw_branch() -> None:
    sanitised = fixture_model("cwe_22_7")

    assert _lines(fixture_model("cwe_918_5"), "request") == {5}  # if (!t) t = constant
    assert _lines(sanitised, "path") == {5}  # if (strict) p = path.basename(p)
    assert _externals(sanitised, "path", 5) == {
        external("request"), external("request", "path_normalize"),
    }


# Language code -> (the program, its sink line).
_LOOPS = {
    "js": ("""
        function h(req) {
          let p = "index.html";
          for (const x of [1, 2]) {
            fs.readFile(p, () => {});
            p = req.query.f;
          }
        }
        """, 4),
    "py": ("""
        def h(request):
            p = "index.html"
            while True:
                open(p)
                p = request.args["f"]
        """, 4),
}


@pytest.mark.parametrize(("lang", "case"), _LOOPS.items(), ids=list(_LOOPS))
def test_loop_body_runs_one_extra_pass(lang: str, case: tuple[str, int]) -> None:
    # The write after the sink reaches it only on the second pass (D6).
    source, line = case
    assert _lines(program(lang, source), "path") == {line}


@pytest.mark.parametrize(("stem", "line"), [
    ("cwe_22_10", 6),  # identity function named basename
    ("cwe_22_11", 5),  # dead sanitiser call, result discarded
])
def test_laundering_by_name_or_by_a_dead_call_reports(stem: str, line: int) -> None:
    assert _lines(fixture_model(stem), "path") == {line}


def test_partial_sanitiser_covers_only_its_own_argument() -> None:
    m = fixture_model("cwe_22_6")

    assert _lines(m, "path") == {6}
    assert _externals(m, "path", 6) == {external("request"), external("request", "path_normalize")}


def test_sanitiser_on_another_variable_leaves_the_sink_raw() -> None:
    assert _lines(fixture_model("cwe_918_3"), "request") == {5}


def test_dynamic_write_adds_the_value_never_the_key() -> None:
    m = program("js", """
        function h(req) {
          const opts = {};
          opts[req.query.key] = "index.html";
          fs.readFile(opts.file, () => {});
        }
        """)
    read = _arg(m, "fs.readFile")

    assert unknown("dynamic") in read
    assert (externals(read), _lines(m, "path")) == (frozenset(), set())


_DEPTH_TWO = """
    function inner(p) { return fs.readFile(p, () => {}); }
    function outer(p) { return inner(p); }
    function a(req) { return outer(req.query.f); }
    function b(req) { return outer(req.body.g); }
    """


def test_depth_two_summary_is_memoised_per_canonical_origins() -> None:
    m = program("js", _DEPTH_TWO)

    assert judge(m, "path").reported == (1,)
    assert len(_holding(m, "path", 1, external("request"))) == 1


_RECURSION = """
    function walk(p, n) {
      if (n > 0) return walk(p, n - 1);
      return fs.readFile(p, () => {});
    }
    function h(req) {
      return walk(req.query.f, 3);
    }
    """


def test_recursion_is_cut_to_unknown() -> None:
    m = program("js", _RECURSION)

    assert unknown("recursion") in origins_of(m, call_at(m, "walk", line=2))
    assert _lines(m, "path") == {3}


_MUTUAL = """
    function ping(p, n) {
      if (n > 0) return pong(p, n - 1);
      return fs.readFile(p, () => {});
    }
    function pong(p, n) {
      return ping(p, n);
    }
    function h(req) {
      return ping(req.query.f, 3);
    }
    """


def test_mutual_recursion_is_cut_to_unknown_before_the_depth_cap() -> None:
    # A28 (10): re-entering ANY callee already on the summary stack is unknown(recursion),
    # tested before the depth cap: h -> ping -> pong -> ping re-enters ping past
    # MAX_SUMMARY_DEPTH, and answers recursion, never summary_cap.
    m = program("js", _MUTUAL)
    from_h = origins_of(m, call_at(m, "ping", line=9))

    assert unknown("recursion") in origins_of(m, call_at(m, "pong", line=2))
    assert (unknown("recursion") in from_h, unknown("summary_cap") in from_h) == (True, False)
    assert _lines(m, "path") == {3}


# Five sanitiser callees, one role each (P1 words, R4 composition, L12 (c)); every subset of
# them wraps req.query.f into a distinct external(request, via) origin.
_WRAPPERS = {
    "basename": "path_normalize",
    "allow": "allowlist",
    "validate": "validate",
    "shellEscape": "shell_quote",
    "privateOnly": "host_allow",
}
_SUBSETS = tuple(itertools.islice(
    itertools.chain.from_iterable(itertools.combinations(_WRAPPERS, k) for k in range(len(_WRAPPERS) + 1)),
    17,
))


def _wrapped(names: tuple[str, ...]) -> str:
    return functools.reduce(lambda inner, name: f"{name}({inner})", names, "req.query.f")


def _summed(count: int) -> str:
    return " + ".join(map(_wrapped, _SUBSETS[:count]))


def _wrapped_origin(names: tuple[str, ...]) -> Origin:
    """The origin ``_wrapped(names)`` reaches the sink with: ``request`` via each wrapper's
    role, in order."""
    return external("request", *(_WRAPPERS[w] for w in names))


def test_seventeen_origins_collapse_to_any_and_overflow() -> None:
    m = program("js", f"function h(req) {{\n  sink({_summed(16)});\n  sink({_summed(17)});\n}}\n")
    expected = set(map(_wrapped_origin, _SUBSETS[:16]))

    assert _arg(m, "sink", line=2) == expected  # MAX_ORIGINS: kept
    assert _arg(m, "sink", line=3) == {external("any"), unknown("overflow")}  # cap + 1: collapsed


def _overflows(count: int) -> int:
    """``analysis.tallies["origin_overflow"]`` of a one-sink program summing ``count``
    distinct origins, read after the sink's argument is resolved."""
    m = program("js", f"function h(req) {{\n  sink({_summed(count)});\n}}\n")
    _arg(m, "sink")
    return analysis_of(m).tallies.get("origin_overflow", 0)


def test_an_origin_overflow_is_a_per_file_analysis_tally() -> None:
    # A28 (3), A32: FlowAnalysis carries its per-file fact counts; the MAX_ORIGINS row
    # tallies origin_overflow at cap + 1, and nothing at the cap.
    assert (_overflows(16), _overflows(17) >= 1) == (0, True)


# ── decide (§8.5) on each outcome, with the recording AuditContext ───────────


def _server_gate(_flow: Any, server_ctx: bool) -> bool:
    """A ``FamilyRule.gate`` of the SSRF gate's shape (§9.3): keep the flow only in a server
    context."""
    return server_ctx


def test_decide_none_when_no_origin_reaches_the_sink() -> None:
    outcome, ctx = decided(flow_with("path"), "path")

    assert (outcome, ctx.tallies, ctx.declines) == ("none", {}, [])


def test_decide_none_when_the_rule_gate_fails() -> None:
    flow = flow_with("request", external("request"))

    assert decided(flow, "request", gate=_server_gate, server_ctx=False)[0] == "none"
    assert decided(flow, "request", gate=_server_gate, server_ctx=True)[0] == "report"


def test_decide_tallies_an_unknown_only_sink() -> None:
    outcome, ctx = decided(flow_with("path", unknown("param"), unknown("unresolved")), "path")

    assert (outcome, dict(ctx.tallies), ctx.declines) == ("none", {"unknown_only_sinks": 1}, [])


def _tallied(flow: Flow, family: str) -> tuple[str, dict[str, int]]:
    outcome, ctx = decided(flow, family)
    return outcome, dict(ctx.tallies)


def test_decide_tallies_role_filtered_sinks() -> None:
    # A28 (3): a flow R-P removed roles from is tallied role_filtered_sinks through
    # ctx.tally, whatever decide then makes of what remains.
    kept = flow_with("request", external("request"), filtered=("argv",))
    emptied = flow_with("request", filtered=("argv", "env"))

    assert [_tallied(kept, "request"), _tallied(emptied, "request")] == [
        ("report", {"role_filtered_sinks": 1}), ("none", {"role_filtered_sinks": 1}),
    ]


def test_decide_tallies_env_only_sinks() -> None:
    # A28 (3): env_only_sinks when filtered_roles == {env} and nothing remains; with an
    # origin remaining, the same filter is role_filtered_sinks.
    env_only = flow_with("path", filtered=("env",))
    env_and_request = flow_with("path", external("request"), filtered=("env",))

    assert [_tallied(env_only, "path"), _tallied(env_and_request, "path")] == [
        ("none", {"env_only_sinks": 1}), ("report", {"role_filtered_sinks": 1}),
    ]


_SANITISED = {
    "path": ("path", [("external", "request", "path_normalize")], "sanitized:path_normalize"),
    "two roles": ("path", [("external", "request", "path_normalize"), ("external", "argv", "numeric"),
                           ("unknown", "param")], "sanitized:numeric+path_normalize"),
    "command": ("command", [("external", "request", "shell_quote")], "sanitized:shell_quote"),
    "request": ("request", [("external", "request", "host_allow")], "sanitized:host_allow"),
}


@pytest.mark.parametrize(("family", "specs", "label"), _SANITISED.values(), ids=list(_SANITISED))
def test_decide_declines_when_every_external_origin_is_covered(
    family: str, specs: list[tuple[str, ...]], label: str
) -> None:
    flow = flow_with(family, *map(_origin, specs))
    path = Path("/audit/src/sanitised.js")

    outcome, ctx = decided(flow, family, path=path)

    assert (outcome, ctx.labels, ctx.tallies) == ("decline", [label], {})
    # A30 (1): ctx.decline(path, flow, rule, label) - the file is the consumer's.
    assert (ctx.declines[0].path, ctx.declines[0].flow is flow) == (path, True)


def test_decide_records_its_decline_on_the_consumers_file(tmp_path: Path) -> None:
    # A30 (1): decided into a real AuditContext, the decline is a DeclineRecord of the path
    # decide was given, at the sink line, with its origins rendered `external:request`.
    ctx = fresh_context(tmp_path)
    flow = flow_with("path", external("request", "path_normalize"), sink_line=4)

    outcome, _ = decided(flow, "path", ctx, path=tmp_path / "src" / "a.js")

    assert (outcome, rendered(ctx.ledger, tmp_path)) == ("decline", [
        "ast_decline family=path file=src/a.js line=4 rule=sanitized:path_normalize"
        " origins=external:request"
    ])


def test_decide_declines_on_the_first_covering_guard_by_its_smallest_role() -> None:
    guards = (stub_guard("host_allow"), stub_guard("validate", "allowlist"), stub_guard("path_contain"))

    outcome, ctx = decided(flow_with("path", external("request"), guards=guards), "path")

    assert (outcome, ctx.labels) == ("decline", ["guarded:allowlist"])  # L4


_REPORTED = {
    "raw": ("path", [("external", "request")], ()),
    "covered for another family": ("command", [("external", "request", "path_normalize")], ()),
    "one origin uncovered": ("path", [("external", "request", "path_normalize"), ("external", "request")], ()),
    "validate covers nothing": ("path", [("external", "request", "validate")], ()),
    "guard for another family": ("path", [("external", "request")], ("host_allow",)),
    "validate never guards request": ("request", [("external", "request")], ("validate",)),
}


@pytest.mark.parametrize(("family", "specs", "guard_roles"), _REPORTED.values(), ids=list(_REPORTED))
def test_decide_reports_an_uncovered_unguarded_external_origin(
    family: str, specs: list[tuple[str, ...]], guard_roles: tuple[str, ...]
) -> None:
    guards = (stub_guard(*guard_roles),) if guard_roles else ()

    outcome, ctx = decided(flow_with(family, *map(_origin, specs), guards=guards), family)

    assert (outcome, ctx.tallies, ctx.declines) == ("report", {}, [])


_COVERED = [
    (("external", "request", "path_normalize"), "path", True),
    (("external", "request", "path_normalize"), "command", False),
    (("external", "request", "numeric"), "request", True),
    (("external", "request", "host_allow"), "request", True),
    (("external", "request", "shell_quote"), "command", True),
    (("external", "request", "allowlist"), "command", True),
    (("external", "request", "allowlist"), "path", False),
    (("external", "request", "validate"), "path", False),
    (("external", "request", "url_parse"), "request", False),  # L5: a parse covers nothing
    (("unknown", "param"), "path", False),
]


@pytest.mark.parametrize(("spec", "family", "expected"), _COVERED)
def test_covered_reads_covered_by_of_the_family(spec: tuple[str, ...], family: str, expected: bool) -> None:
    assert flow_mod().covered(_origin(spec), family) is expected


# ── the flow record (§8.6, A28 (4)) ──────────────────────────────────────────

_HOP_KINDS = frozenset({"param", "member", "assign", "call", "return", "loop", "catch", "sink"})
_ONE_HOP_CHAIN = "function h(req) {\n  const p = req.query.f;\n  fs.readFile(p, () => {});\n}\n"


def test_flow_record_carries_its_argument_node_and_named_hops() -> None:
    # A28 (4): Hop is the NamedTuple Hop(line, kind, name) (name = §10.1's JSON key); Flow.arg
    # is the index of the sink argument's node. §10.1: the chain runs from the source side
    # (the request PARAM) to the sink.
    hop = flow_mod().Hop
    m = program("js", _ONE_HOP_CHAIN)
    (flow,) = flows_on(m, "path", 3)

    assert (hop._fields, flow.arg) == (("line", "kind", "name"), m.args(flow.sink)[0])
    assert all(isinstance(h, hop) and h.kind in _HOP_KINDS for h in flow.hops)
    assert (flow.hops[0], flow.hops[-1]) == (hop(1, "param", "req"), hop(3, "sink", "fs.readFile"))


# ── revision 9 decisions ─────────────────────────────────────────────────────

_RM_GO = """
    package app

    func run(r *http.Request) error {
        x := r.FormValue("c")
        return exec.Command("/bin/bash", "-c", x).Run()
    }
    """
_RM_NO_FLAG = """
    const cp = require("child_process");
    function h(req) {
      cp.spawn("sh", [req.query.c]);
    }
    """


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_78_17_clean", set()),  # spawn("ping", ["-c", "1", h]): a flag, no interpreter
    (("js", _RM_NO_FLAG), set()),  # an interpreter, no flag
    ("cwe_78_c_1_clean", set()),  # execlp("ls", ...): neither
    ("cwe_78_7", {6}),  # spawn("sh", ["-c", x])
    ("cwe_78_c_1", {5}),  # execlp("sh", "sh", "-c", x, NULL)
    ("cwe_78_13", {7}),  # os.execlp("sh", "sh", "-c", cmd)
    (("go", _RM_GO), {5}),  # exec.Command("/bin/bash", "-c", x): the basename
], ids=["flag-only", "interpreter-only", "argv-form", "spawn", "execlp-c", "execlp-py", "go-bash"])
def test_rm_needs_interpreter_and_flag(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "command") == lines


_HEADERS = 'function h(req) {\n  const v = req.headers.get("x");\n  return v;\n}\n'


@pytest.mark.parametrize(("spec", "head", "line"), [
    ("cwe_918_go_2_clean", "r.URL.Query().Get", 5),
    ("cwe_22_go_3", "r.URL.Query().Get", 10),
    (("js", _HEADERS), "req.headers.get", 2),
], ids=["go-query", "go-one-line", "js-headers"])
def test_source_read_is_never_a_sink(spec: Spec, head: str, line: int) -> None:
    m = subject(spec)
    read = call_at(m, head, line=line)

    assert external("request") in origins_of(m, read)
    assert all(read not in _sinks(m, family) for family in FAMILIES)


_RV_PROGRAM = """
    async fn run(q: web::Query<RunQuery>) -> std::io::Result<Vec<u8>> {
        Ok(Command::new(&q.cmd).output()?.stdout)
    }
    """


@pytest.mark.parametrize(("spec", "lines"), [
    (("rs", _RV_PROGRAM), {2}),  # Command::new(x): the program position
    ("cwe_78_rs_1_clean", set()),  # Command::new("ls").arg(x)
    ("cwe_78_go_2_clean", set()),  # exec.Command("ls", dir)
    ("cwe_78_java_2_clean", set()),  # new ProcessBuilder("ls", dir)
    ("cwe_78_rs_1", {8}),  # Command::new("sh").arg("-c").arg(x)
    ("cwe_78_rs_2", {8}),  # .args(["-c", x]): the array flattened once (W15 a)
    ("cwe_78_java_2", {5}),  # new ProcessBuilder("sh", "-c", x)
], ids=["rust-program", "rust-arg", "go-argv", "java-argv", "rust-sh-c", "rust-args-array", "java-sh-c"])
def test_rv_command_builder_program_position_only(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "command") == lines


_OPEN = "function h(req) {\n  open(req.query.u);\n}\n"


@pytest.mark.parametrize(("spec", "head", "request_sink", "path_lines"), [
    ("cwe_918_go_3_clean", "os.Open", False, {6}),  # Go: a path sink only
    ("cwe_22_14", "open", False, {7}),  # Python: a path sink only
    (("js", _OPEN), "open", True, {2}),  # JS is browser_capable: both
    ("cwe_918_6", "urlopen", True, set()),  # urlopen: a request key everywhere
], ids=["go-os.Open", "py-open", "js-open", "py-urlopen"])
def test_open_is_request_sink_only_in_browser_capable_profiles(
    spec: Spec, head: str, request_sink: bool, path_lines: set[int]
) -> None:
    m = subject(spec)

    assert (call_at(m, head) in _sinks(m, "request"), _lines(m, "path")) == (request_sink, path_lines)


def test_browser_open_is_a_request_sink_under_the_server_ctx_gate() -> None:
    js = program("js", _OPEN)

    assert [_lines(js, "request", gate=_server_gate, server_ctx=s) for s in (False, True)] == [set(), {2}]


_PATHS_GET = """
    class Docs {
        byte[] read(HttpServletRequest request) throws IOException {
            return Files.readAllBytes(Paths.get(ROOT, request.getParameter("f")));
        }
    }
    """
_WRITE_FILE = """
    function h(req) {
      fs.writeFile("/srv/out.txt", req.body.data, () => {});
      fs.writeFile(req.query.p, "x", () => {});
    }
    """


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_22_java_1", {8}),  # new File(DOC_ROOT, name): "all", so arg 1
    (("java", _PATHS_GET), {3}),  # the pair key pathsget: "all"
    (("js", _WRITE_FILE), {3}),  # writeFile's data argument is never a path
], ids=["new-File", "Paths.get", "writeFile"])
def test_path_args_all_builtin(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "path") == lines


_C_POSITIONS = {
    "openat path": ("""
        int main(int argc, char **argv) {
            int dirfd = 3;
            int fd = openat(dirfd, argv[1], O_RDONLY);
            return fd;
        }
        """, {3}),
    "openat dirfd": ("""
        int main(int argc, char **argv) {
            int fd = openat(argv[2], "docs/a.txt", O_RDONLY);
            return fd;
        }
        """, set()),
    "fd and buffer calls": ("""
        int main(int argc, char **argv) {
            char *p = argv[1];
            read(p, p, 8);
            fread(p, 1, 8, p);
            fgets(p, 8, p);
            write(p, p, 8);
            fwrite(p, 1, 8, p);
            return 0;
        }
        """, set()),
    "fopen": ("""
        int main(int argc, char **argv) {
            FILE *f = fopen(argv[1], "r");
            return f == NULL;
        }
        """, {2}),
}


@pytest.mark.parametrize("lang", ["c", "cpp"])
@pytest.mark.parametrize(("source", "lines"), _C_POSITIONS.values(), ids=list(_C_POSITIONS))
def test_c_path_sink_positions(lang: str, source: str, lines: set[int]) -> None:
    # P4: openat = (1,); read/fread/fgets (C5) and write/fwrite (R5) carry an EMPTY family
    # set; fopen keeps (0,). C++ inherits all three.
    assert _lines(program(lang, source), "path") == lines


def _calls_to(m: FileModel, key: str, line: int) -> list[int]:
    """The CALLs on ``line`` whose callee chain ends in the glued segment ``key``."""
    return [c for c in _calls_on(m, line) if m.chain_words(m.callee(c))[-1:] == (key,)]


_PROTOTYPE = "int main(int argc, char **argv) {\n    std::ifstream in(DocPath);\n    return 0;\n}\n"
_PARAM_CTOR = "void load(const char *docPath) {\n    std::ifstream in(docPath);\n}\n"


def _assert_a_def_decides_the_parse(in_scope: FileModel) -> None:
    """R-X inline: the prototype's declarator names no in-scope Def, so it is no candidate;
    ``in_scope``'s names a param Def, so it stays the constructor CALL."""
    assert flows_on(program("cpp", _PROTOTYPE), "path", 2) == []  # names no in-scope Def
    assert _holding(in_scope, "path", 2, unknown("param")) != []  # a param Def: kept a CALL


def test_rx_vexing_parse_is_a_constructor_call() -> None:
    clean = fixture_model("cwe_22_cpp_3_clean")
    in_scope = program("cpp", _PARAM_CTOR)

    assert _lines(fixture_model("cwe_22_cpp_3"), "path") == {8}
    assert (_lines(clean, "path"), _labels(clean, "path")) == (set(), {"sanitized:path_normalize"})
    _assert_a_def_decides_the_parse(in_scope)


def test_stack_constructor_is_a_call() -> None:
    """C3: ``std::ifstream in(docPath.c_str())`` is a synthetic CALL ``ifstream`` (its args
    the ``argument_list``), a path sink reached from argv. The flow half is read first, so the
    test is RED on ``shared.ast.flow`` (plan 2.3); the model half, asserted first, pins the
    worker shape §6.3 gives C3 (plan task 1.1)."""
    m = fixture_model("cwe_22_cpp_1")
    reported = (_lines(m, "path"), external("argv") in _externals(m, "path", 8))
    ifstream_args = _constructor_args(m, 8, source_of)

    assert ifstream_args == [["docPath.c_str()"]], (
        "C3, §6.3 C++: a declaration whose init_declarator value is an argument_list ships as "
        "an ASSIGN whose RHS is a synthetic CALL, callee = the declared type"
    )
    assert reported == ({8}, True)


# A36 (2026-10-17): R-X over a subscript. A vexing-parse ``function_declarator`` whose one
# parameter is an ``abstract_array_declarator`` over a type identifier naming an in-scope Def
# (``std::ifstream in(argv[1]);``) is the constructor call, its argument shipped by the worker
# as SUBSCRIPT(NAME, INDEX) in a synthetic CALL beside C3's; the other vexing variants (casts,
# qualified-type arguments, several arguments) are a SKILLS.md known gap (plan task 3.6).
_ARGV_SUBSCRIPT = "int main(int argc, char **argv) { std::ifstream in(argv[1]); }\n"
_LOCAL_ARRAY = """
    int main(int argc, char **argv) {
        char *args[2] = {argv[1], argv[2]};
        int i = 1;
        std::ifstream in(args[i]);
        return 0;
    }
    """
# Case -> (the program, the constructor's line, its argument's (OBJECT, INDEX) children).
_SUBSCRIPT_CTORS = {
    "argv": (
        _ARGV_SUBSCRIPT, 1, ((Field.OBJECT, Kind.NAME, "argv"), (Field.INDEX, Kind.LITERAL, "1")),
    ),
    "local-array": (
        _LOCAL_ARRAY, 4, ((Field.OBJECT, Kind.NAME, "args"), (Field.INDEX, Kind.NAME, "i")),
    ),
}
# A vexing prototype whose subscript names no in-scope Def: at file scope, and in a body.
_NO_DEF_SUBSCRIPTS = {
    "file-scope": "std::ifstream in(Foo[2]);\n",
    "function-body": "void load() {\n    std::ifstream in(Foo[2]);\n}\n",
}


def _shape(m: FileModel, node: int) -> tuple[Kind, tuple[tuple[Field, Kind, str], ...]]:
    """A node's kind and, for each child in document order, its field, kind and source."""
    return m.kind(node), tuple((m.field(c), m.kind(c), source_of(m, c)) for c in m.children(node))


def _constructor_args[T](
    m: FileModel, line: int, read: Callable[[FileModel, int], T] = _shape
) -> list[list[T]]:
    """``read`` (``_shape`` unless given) of each argument of each CALL ``ifstream`` on
    ``line``."""
    return [[read(m, a) for a in m.args(c)] for c in _calls_to(m, "ifstream", line)]


def _argv_flows(m: FileModel) -> list[tuple[int, bool]]:
    """Each path candidate's sink line and whether its origins hold ``external(argv)``."""
    return [(f.sink_line, external("argv") in f.origins) for f in candidates_of(m, "path")]


@pytest.mark.parametrize(
    ("source", "line", "children"), _SUBSCRIPT_CTORS.values(), ids=list(_SUBSCRIPT_CTORS)
)
def test_rx_vexing_subscript_is_a_constructor_call(
    source: str, line: int, children: tuple[tuple[Field, Kind, str], ...]
) -> None:
    """A36: the worker model holds one synthetic CALL ``ifstream`` on the declaration's line
    whose one argument is SUBSCRIPT(NAME, INDEX), and the scope pass keeps it a CALL (the
    NAME is a param or local Def), so it is the one path candidate, reached from argv."""
    m = program("cpp", source)
    shipped, flows = _constructor_args(m, line), _argv_flows(m)

    assert shipped == [[(Kind.SUBSCRIPT, children)]], (
        "A36, C++ R-X: a vexing parse over a subscript of an in-scope Def ships as a synthetic "
        "CALL, callee = the declared type, its argument SUBSCRIPT(NAME, INDEX)"
    )
    assert flows == [(line, True)]


@pytest.mark.parametrize("source", _NO_DEF_SUBSCRIPTS.values(), ids=list(_NO_DEF_SUBSCRIPTS))
def test_rx_vexing_subscript_naming_no_def_is_a_prototype(source: str) -> None:
    """A36: a vexing prototype whose subscript names no in-scope Def is a prototype, not the
    constructor call: no candidate of any family."""
    m = program("cpp", source)

    assert {family: candidates_of(m, family) for family in FAMILIES} == dict.fromkeys(FAMILIES, ())


# ── walk corrections ─────────────────────────────────────────────────────────

_REF_PATH = "fn show(p: &Path) -> String {\n    fs::read_to_string(p).unwrap()\n}\n"
_OS_FILE = "package app\n\nfunc show(f *os.File) ([]byte, error) {\n\treturn os.ReadFile(f.Name())\n}\n"
_NET_IP = 'package app\n\nfunc ping(ip net.IP) (*http.Response, error) {\n\treturn http.Get("http://" + ip.String())\n}\n'


@pytest.mark.parametrize(("spec", "family", "lines"), [
    ("cwe_22_rs_1", "path", {11}),  # web::Query<P> -> query
    ("cwe_918_go_1", "request", {6}),  # *http.Request -> http, request
    (("rs", _REF_PATH), "path", set()),  # &Path: a value type
    (("go", _OS_FILE), "path", set()),  # *os.File
    (("go", _NET_IP), "request", set()),  # net.IP
], ids=["web-Query", "http-Request", "ref-Path", "os-File", "net-IP"])
def test_type_annotation_words(spec: Spec, family: str, lines: set[int]) -> None:
    # W4, R8: a TYPE annotation is read against TYPE_ANNOTATION_WORDS (no path/file/files/ip).
    assert _lines(subject(spec), family) == lines


_PAIR_KEYS = """
    async fn h(q: web::Query<P>) {
        let a = Path::new(&q.p);
        let b = Command::new(&q.p);
    }
    """
_OS_REPLACE = """
    import os


    def move(request):
        os.replace(request.args["a"], "/srv/b")
        os.replace("/srv/a", request.args["b"])
    """
_OS_RENAME = 'import os\n\n\ndef move(request):\n    os.rename(request.args["a"], "/srv/b")\n'


@pytest.mark.parametrize(("spec", "family", "lines"), [
    (("rs", _PAIR_KEYS), "command", {3}),  # commandnew; Path::new keeps its words
    ("cwe_22_rs_2", "command", set()),  # Path::new(&q.file) is no command root
    ("cwe_918_php_2", "request", {5}),  # curl_setopt: arg 2 when arg 1 is CURLOPT_URL (R7)
    (("py", _OS_REPLACE), "path", {5, 6}),  # osreplace: "all" (R9)
    ("cwe_22_40", "path", {4}),  # p.replace("..", "") passes through (R9)
    (("py", _OS_RENAME), "path", {5}),  # rename: still a sink word
], ids=["Command-vs-Path", "rust-arms", "curl_setopt", "os.replace", "str.replace", "os.rename"])
def test_builtin_pair_keys_and_conditional_positions(spec: Spec, family: str, lines: set[int]) -> None:
    assert _lines(subject(spec), family) == lines


_TWO_PATHS = {
    "os.rename dest": ("py", 'import os\n\n\ndef move(request):\n    os.rename("/srv/a", request.args["d"])\n', {5}),
    "copyFile dest": ("js", 'function h(req) {\n  fs.copyFile("/srv/a", req.query.d, () => {});\n}\n', {2}),
    "symlink dest": ("js", 'function h(req) {\n  fs.symlink("/srv/a", req.query.d, () => {});\n}\n', {2}),
    "writeFile data": ("js", 'function h(req) {\n  fs.writeFile(CONST, req.body, () => {});\n}\n', set()),
}


@pytest.mark.parametrize(("lang", "source", "lines"), _TWO_PATHS.values(), ids=list(_TWO_PATHS))
def test_two_path_sinks_check_every_argument(lang: str, source: str, lines: set[int]) -> None:
    # R10: TWO_PATH_SINKS take path_args "all"; a write keeps (0,).
    assert _lines(program(lang, source), "path") == lines


_FROM_IMPORT = 'from os import remove as drop\n\n\ndef clean(request):\n    drop(request.args["f"])\n'
_ALIAS = 'import { readFile as execNow } from "fs";\nexport function h(req) {\n  execNow(req.query.f, () => {});\n}\n'


@pytest.mark.parametrize(("spec", "family", "lines"), [
    ("cwe_22_32", "path", {4}),  # import { readFile as rf }
    ("cwe_22_33", "path", {4}),  # const { readFile: rd } = require("fs")
    (("py", _FROM_IMPORT), "path", {5}),  # from os import remove as drop
    (("js", _ALIAS), "path", {3}),  # keyed by the symbol readFile ...
    (("js", _ALIAS), "command", set()),  # ... never by the alias's exec prefix
], ids=["import-as", "require-pair", "from-import-as", "alias-path", "alias-not-command"])
def test_rh_callee_key_from_imported_symbol(spec: Spec, family: str, lines: set[int]) -> None:
    assert _lines(subject(spec), family) == lines


_BOUND_FIELD = """
    function h(req) {
      const opts = { file: "index.html" };
      opts.file = "index.html";
      opts[req.query.key] = req.query.value;
      fs.readFile(opts.file, () => {});
    }
    """


def test_dynamic_subscript_write_carries_value() -> None:
    clean = fixture_model("cwe_22_12_clean")

    assert _lines(fixture_model("cwe_22_12"), "path") == {5}
    assert (_lines(clean, "path"), _labels(clean, "path")) == (set(), {"guarded:validate"})
    assert _lines(program("js", _BOUND_FIELD), "path") == {5}  # every bound o.* receives it


_PHP_INPUT = """
    <?php
    class Docs
    {
        public function show(Request $request)
        {
            return $request->input('f');
        }
    }
    """
_NEW_REQUEST = 'package app\n\nfunc h() {\n\treq, _ := http.NewRequest("GET", "http://localhost/x", nil)\n\thttp.DefaultClient.Do(req)\n}\n'
_DB_QUERY = 'package app\n\nfunc h() {\n\tdb.Query("select 1")\n}\n'
_CLIENT_REQUEST = 'client.request("GET", url="http://localhost/x")\n'
_NEW_BUILDER = """
    class A {
        void f() {
            HttpRequest b = HttpRequest.newBuilder(URI.create("http://localhost/x")).build();
        }
    }
    """


@pytest.mark.parametrize(("spec", "head", "roles"), [
    (("py", "x = input()\n"), "input", {"stdin"}),  # a reading function
    (("php", _PHP_INPUT), "$request->input", {"request"}),  # R-U is tested first and wins
    ("cwe_22_42", 'new URL(req.url).searchParams.get', {"request"}),  # L6 accessor shape
    (("go", _NEW_REQUEST), "http.NewRequest", set()),  # a request word is no reading function
    (("java", _NEW_BUILDER), "HttpRequest.newBuilder", set()),
    (("go", _DB_QUERY), "db.Query", set()),
    (("py", _CLIENT_REQUEST), "client.request", {"network"}),  # a sink: R-I, never `request`
], ids=["input", "request-input", "searchParams.get", "NewRequest", "newBuilder", "db.Query",
        "client.request"])
def test_call_source_is_a_reading_function(spec: Spec, head: str, roles: set[str]) -> None:
    m = subject(spec)

    assert {o.role for o in externals(origins_of(m, call_at(m, head)))} == roles


_ECHOES = """
    function h(req, res, ws, socket) {
      res.send(req.query.x);
      ws.send(req.query.x);
      socket.send(req.body.data);
    }
    """
_OPTIONS_URL = "function h(req) {\n  client.request({ url: req.query.u });\n}\n"


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_918_9", {5}),  # the url= KWARG
    ("cwe_918_14", {4}),  # the host= KWARG of connect
    (("js", _OPTIONS_URL), {2}),  # an OBJECT PAIR named url
    ("cwe_918_java_1", {7}),  # the receiver under R-V
    ("cwe_918_java_2", {8}),  # send: the argument whose chain words are carriers
    (("js", _ECHOES), set()),  # send on no carrier: response and socket echoes
], ids=["kwarg-url", "kwarg-host", "pair-url", "receiver", "carrier-arg", "echoes"])
def test_request_sink_argument_union(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "request") == lines


_PAIRWISE = """
    package app

    func h(r *http.Request) {
        a, b := r.FormValue("u"), "http://localhost/health"
        http.Get(b)
        http.Get(a)
    }
    """


@pytest.mark.parametrize(("spec", "family", "lines"), [
    ("cwe_78_go_1", "command", {7}),  # Decode(&form): UNARY & over a NAME
    ("cwe_918_go_2", "request", {10}),  # req, err := f(): both targets <- the RHS
    (("go", _PAIRWISE), "request", {6}),  # a, b := x, y: pairwise
], ids=["reference", "two-targets-one-value", "pairwise"])
def test_reference_unary_and_multi_target(spec: Spec, family: str, lines: set[int]) -> None:
    assert _lines(subject(spec), family) == lines


_GET_NAME = """
    class Docs {
        long size(HttpServletRequest request) {
            String p = FilenameUtils.getName(request.getParameter("f"));
            return new File(p).length();
        }
    }
    """


def test_rs_method_form() -> None:
    m = fixture_model("cwe_22_rs_1_clean")

    assert (_lines(m, "path"), _labels(m, "path")) == (set(), {"sanitized:path_normalize"})
    assert _lines(program("java", _GET_NAME), "path") == {4}  # a static helper: G10, gap-only


def test_ro_reads_module_defs() -> None:
    m = fixture_model("cwe_22_15")

    assert _lines(m, "path") == {11}
    assert external("request") in _externals(m, "path", 11)


_ONE_ARG_WRITE = 'def save(request, f):\n    f.write(request.args["s"])\n'


@pytest.mark.parametrize(("spec", "lines"), [
    ("cwe_22_go_3", {10}),  # w.Write(data) on line 11 is data
    (("py", _ONE_ARG_WRITE), set()),  # f.write(s)
    (("js", _WRITE_FILE), {3}),  # fs.writeFile(p, d) sinks on p
], ids=["go-Write", "py-write", "js-writeFile"])
def test_one_argument_write_is_data(spec: Spec, lines: set[int]) -> None:
    assert _lines(subject(spec), "path") == lines
