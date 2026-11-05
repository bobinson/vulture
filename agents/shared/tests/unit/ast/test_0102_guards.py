"""Feature 0102, plan task 2.3 (RED), the guards half: LLD §8.3, §8.5 "Guard"; revision 9
L4, L11, L12 and W2; the lead's rulings R2, R3, R4; scenarios B9-B14, C4, C14, C15, G6, G11.

A guard is an IF (or, through R-R, a TRY) that ``FlowAnalysis.guards_for(sink, arg)`` finds
for one sink argument; ``decide`` declines a flow that has a guard whose role SET meets
``COVERING_GUARDS[family]``, labelled ``guarded:`` + the smallest covering role of the first
such guard. Pinned here, one clause of §8.5 per test:

* **Same Def.** The Defs the TEST's reads resolve to meet ``roots(arg)``: a guard on the value
  that reaches the sink declines; a guard on a name redefined after it, on a PROPERTY that
  merely shares the name (W8), or on another variable (``cwe_22_9``) is no guard. A read is a
  ``(Def, member path)`` pair (A29 (3)): a TEST of chain C guards a sink read of chain C' only
  when C == C' or one is a dotted prefix of the other (``req.query`` guards ``req.query.f``;
  ``req.query.g`` does not).
* **Early exit, clause (a).** The IF ends before the sink and ``exits(CONSEQ)``: a direct
  RETURN, THROW, JUMP (``continue`` / ``break``) or CALL whose glued key is an exit word
  (``process.exit``; ``abort`` in ``cwe_22_45_clean``). A CONSEQ that only logs, an exit one
  IF deeper, and an IF after the sink are no guards.
* **Sink inside CONSEQ, clause (b),** and **negation** (A29 (1)): inside CONSEQ when the TEST
  is not a negation, inside ALT when it is a UNARY ``!`` / ``not`` — so a negated TEST whose
  CONSEQ holds the sink is no guard. A TEST-less IF (a Python ``else``) is never one (A29 (6)).
* **No covering role (A29 (2)).** An IF that meets the Defs and exits is in ``guards_for``
  even with no role at all; ``decide`` then reports. A guard is ``Guard(node, roles)``
  (A29 (5)).
* **Window.** The ``GUARD_WINDOW`` nearest IF or TRY siblings preceding ``stmt(sink)``: the
  guard as the 8th is read, as the 9th is not; plain statements take no slot.
* **Ancestors.** Every IF ancestor of the sink, not only its parent.
* **Roles are a set (L4, R4).** ``includes`` / ``contains`` / ``in_array`` are {allowlist,
  path_contain}, so one guard declines a path AND a command sink, each labelled with the
  smallest role that covers it; Go ``strings.HasPrefix`` is {path_contain} only, so it declines
  ``cwe_22_go_2_clean`` and covers no command sink.
* **Member property names (L11)** reach their roles by their words: ``ip.is_private`` and
  ``addr.isLoopback`` are ``host_allow`` (L12 (c)); a bare NAME is not (R2).
* **``host_allow`` composed (L12, R2, R3).** The host-allowlist cleans decline
  ``guarded:host_allow``, the plural ``ALLOWED_HOSTS`` composes (C15), and a bare truthiness
  test or a presence comparison on a host reports (C14).
* **W2.** ``exits`` reads a braceless consequence, a Python exit-word call, a Go statement
  list, a script-level guard and an R-R TRY sibling.

The propagation and structural rules (§8.2, §8.4) and ``decide``'s four outcomes are
``test_0102_flow_rules.py``'s; the caps at cap + 1 are ``test_0102_limits.py``'s.

RED: ``shared.ast.flow`` and ``shared.ast.roles`` do not exist. Both are reached through
``_analysis``'s lazy accessors, so this module collects and each test fails on the
``ModuleNotFoundError`` of the module it needs; the W2 and L11 shape checks that precede
them read only the Phase-1 model. ``decide`` runs against ``_analysis``'s stand-in rule and
recording context; a found ``Guard`` is read through its ``node`` and ``roles`` (A29 (5)).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from shared.ast import FileModel
from shared.ast.kinds import Field, Kind
from shared.ast.limits import GUARD_WINDOW
from tests.unit.ast._analysis import (
    ALLOWLIST,
    HOST_ALLOW,
    NO_GUARD,
    PATH_CONTAIN,
    READ,
    REPORT,
    SINK,
    SINK_P,
    VALIDATE,
    Spec,
    call_at,
    call_line,
    decided,
    external,
    fixture_model,
    flow_mod,
    flow_with,
    flows_on,
    guard_role_sets,
    guard_roles_of,
    guard_verdict,
    if_test,
    js_handler,
    nested,
    node_at,
    numbered,
    stub_guard,
    subject,
    verdicts_at,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# A program under test is a ``Spec``: an ast_v1 fixture by stem, or ``(language code,
# source)``, dedented (``_analysis.subject``). Its verdicts (``guard_verdict``: a decline
# label, ``REPORT``, or ``NO_GUARD`` when no guard was found at all) and the JS handler most
# cases share (``js_handler``, ``READ``, ``SINK``) are ``_analysis``'s, which the limits
# module's MAX_ARG_NAMES / MAX_TEST_NODES rows read too.


# ── the shape W2 reads (Phase-1 model only) ──────────────────────────────────


def _child(model: FileModel, node: int, kind: Kind) -> int:
    """``node``'s first child of ``kind``."""
    return next(c for c in model.children(node) if model.kind(c) is kind)


def _exit_body(model: FileModel, guard: int) -> int:
    """The body ``exits`` reads (W2): an IF's CONSEQ, a TRY's CATCH's BLOCK (R-R)."""
    if model.kind(guard) is Kind.IF:
        return model.children(guard, Field.CONSEQ)[0]
    return _child(model, _child(model, guard, Kind.CATCH), Kind.BLOCK)


def _statement_kinds(model: FileModel, body: int) -> tuple[Kind, ...]:
    """W2: the kinds of ``body``'s direct statements: its children when it is a BLOCK, else
    ``body`` itself (a braceless consequence)."""
    nodes = model.children(body) if model.kind(body) is Kind.BLOCK else (body,)
    return tuple(map(model.kind, nodes))


# ── same Def; the wrong variable ─────────────────────────────────────────────

_SAME_DEF = [
    pytest.param(
        js_handler(READ, "if (!ALLOWED.includes(p)) return;", SINK_P), ALLOWLIST, id="same-def"
    ),
    pytest.param(
        js_handler("if (!ALLOWED.includes(req.query.f)) return;", f"{SINK}(req.query.f);"),
        ALLOWLIST,
        id="a-chain-read-resolves-to-its-base-def",
    ),
    pytest.param(
        js_handler(
            "let p = req.query.a;", "if (!ALLOWED.includes(p)) return;", "p = req.query.b;", SINK_P
        ),
        NO_GUARD,
        id="redefined-after-the-guard",
    ),
    pytest.param(
        js_handler(
            READ, "const other = req.query.g;", "if (!ALLOWED.includes(other.p)) return;", SINK_P
        ),
        NO_GUARD,
        id="a-property-name-is-never-resolved-on-its-own",
    ),
    pytest.param(
        js_handler("if (!isValid(req.query)) return;", f"{SINK}(req.query.f);"),
        VALIDATE,
        id="a-test-on-a-prefix-chain-guards-the-longer-chain",
    ),
    pytest.param(
        js_handler("if (!ALLOWED.includes(req.query.g)) return;", f"{SINK}(req.query.f);"),
        NO_GUARD,
        id="a-test-on-a-sibling-chain-is-no-guard",
    ),
]


@pytest.mark.parametrize(("program", "verdict"), _SAME_DEF)
def test_guard_tests_the_def_that_reaches_the_sink(program: Spec, verdict: str) -> None:
    assert guard_verdict(subject(program), "path", SINK) == verdict


_WRONG_VARIABLE = [
    pytest.param("cwe_22_9", "fs.readFile", id="cwe_22_9"),
    pytest.param(
        js_handler(READ, "const q = req.query.g;", "if (!ALLOWED.includes(q)) return;", SINK_P),
        SINK,
        id="allowlist-on-q-sink-on-p",
    ),
]


@pytest.mark.parametrize(("program", "head"), _WRONG_VARIABLE)
def test_wrong_variable_guard_is_no_guard(program: Spec, head: str) -> None:
    # B14: the guard's Defs never meet roots(arg), so guards_for finds nothing and it reports.
    assert guard_verdict(subject(program), "path", head) == NO_GUARD


# ── clause (a): early exit ───────────────────────────────────────────────────

_EXITS = [
    pytest.param(js_handler(READ, "if (!ALLOWED.includes(p)) { return; }", SINK_P), SINK, ALLOWLIST,
                 id="return"),
    pytest.param("cwe_22_8_clean", "fs.readFile", PATH_CONTAIN, id="cwe_22_8_clean-return"),
    pytest.param(
        js_handler(READ, 'if (!ALLOWED.includes(p)) { throw new Error("denied"); }', SINK_P),
        SINK, ALLOWLIST, id="throw",
    ),
    pytest.param(
        js_handler("for (const k of KEYS) {", "const p = req.query[k];",
            "if (!ALLOWED.includes(p)) { continue; }", SINK_P, "}"),
        SINK, ALLOWLIST, id="jump-continue",
    ),
    pytest.param(
        js_handler("for (const k of KEYS) {", "const p = req.query[k];",
            "if (!ALLOWED.includes(p)) { break; }", SINK_P, "}"),
        SINK, ALLOWLIST, id="jump-break",
    ),
    pytest.param(js_handler(READ, "if (!ALLOWED.includes(p)) { process.exit(1); }", SINK_P), SINK,
                 ALLOWLIST, id="exit-word-call"),
    pytest.param("cwe_22_45_clean", "open", PATH_CONTAIN, id="cwe_22_45_clean-abort"),
    pytest.param(js_handler(READ, "if (!ALLOWED.includes(p)) { log(p); }", SINK_P), SINK, NO_GUARD,
                 id="a-consequence-that-does-not-exit"),
    pytest.param(js_handler(READ, "if (!ALLOWED.includes(p)) { if (strict) { return; } }", SINK_P),
                 SINK, NO_GUARD, id="an-exit-one-if-deeper-is-no-direct-statement"),
    pytest.param(js_handler(READ, SINK_P, "if (!ALLOWED.includes(p)) { return; }"), SINK, NO_GUARD,
                 id="an-if-after-the-sink"),
    # A29 (2): it meets p's Def and exits, so it is a guard - with no role, it covers nothing.
    pytest.param(js_handler(READ, "if (!p) { return; }", SINK_P), SINK, REPORT,
                 id="an-exiting-if-with-no-role-is-a-guard-that-covers-nothing"),
]


@pytest.mark.parametrize(("program", "head", "verdict"), _EXITS)
def test_early_exit_guards_what_follows(program: Spec, head: str, verdict: str) -> None:
    assert guard_verdict(subject(program), "path", head) == verdict


# ── clause (b): the sink inside the branch; negation ─────────────────────────

_PY_INSIDE = '''\
    def handler(request):
        p = request.args["f"]
        if p.isalnum():
            return open(p)
    '''

_PY_NOT_INSIDE = '''\
    def handler(request):
        p = request.args["f"]
        if not p.isalnum():
            open(p)
    '''

_INSIDE = [
    pytest.param("cwe_22_43_clean", "fs.readFile", ALLOWLIST, id="cwe_22_43_clean"),
    pytest.param(js_handler(READ, "if (ALLOWED.includes(p)) {", SINK_P, "}"), SINK, ALLOWLIST,
                 id="js-allowlist"),
    pytest.param(("py", _PY_INSIDE), "open", VALIDATE, id="py-isalnum"),
    # A29 (1): under a negated TEST the CONSEQ is the rejected branch - no guard, it reports.
    pytest.param(js_handler(READ, "if (!ALLOWED.includes(p)) {", SINK_P, "}"), SINK, NO_GUARD,
                 id="js-negated-test-around-the-sink"),
    pytest.param(("py", _PY_NOT_INSIDE), "open", NO_GUARD, id="py-negated-test-around-the-sink"),
]


@pytest.mark.parametrize(("program", "head", "verdict"), _INSIDE)
def test_sink_inside_the_consequence(program: Spec, head: str, verdict: str) -> None:
    # A29 (1): clause (b) holds for a sink inside CONSEQ only when the TEST is not a negation.
    assert guard_verdict(subject(program), "path", head) == verdict


_PY_ELSE = '''\
    def handler(request):
        p = request.args["f"]
        if {test}:
            log(p)
        else:
            open(p)
    '''

_NEGATION = [
    pytest.param(
        js_handler(READ, "if (!ALLOWED.includes(p)) { log(p); } else {", SINK_P, "}"), SINK,
        ALLOWLIST, id="js-not-then-alternative",
    ),
    pytest.param(("py", _PY_ELSE.replace("{test}", "not p.isalnum()")), "open", VALIDATE,
                 id="py-not-then-alternative"),
    pytest.param(js_handler(READ, "if (ALLOWED.includes(p)) { log(p); } else {", SINK_P, "}"), SINK,
                 NO_GUARD, id="js-alternative-of-a-plain-test"),
    pytest.param(("py", _PY_ELSE.replace("{test}", "p.isalnum()")), "open", NO_GUARD,
                 id="py-alternative-of-a-plain-test"),
]


@pytest.mark.parametrize(("program", "head", "verdict"), _NEGATION)
def test_negated_test_guards_its_alternative(program: Spec, head: str, verdict: str) -> None:
    assert guard_verdict(subject(program), "path", head) == verdict


# ── candidates: the window of preceding siblings; the IF ancestors ───────────

_IF_FILLER = "if (c{i}) { log(c{i}); }\n"
_TRY_FILLER = "try { log(c{i}); } catch (e{i}) { log(e{i}); }\n"

_WINDOW = [
    pytest.param(_IF_FILLER, GUARD_WINDOW - 1, ALLOWLIST, id="guard-is-the-8th-nearest-if"),
    pytest.param(_IF_FILLER, GUARD_WINDOW, NO_GUARD, id="guard-is-the-9th-nearest-if"),
    pytest.param(_TRY_FILLER, GUARD_WINDOW - 1, ALLOWLIST, id="guard-is-the-8th-nearest-try"),
    pytest.param(_TRY_FILLER, GUARD_WINDOW, NO_GUARD, id="guard-is-the-9th-nearest-try"),
    pytest.param("log(c{i});\n", 3 * GUARD_WINDOW, ALLOWLIST, id="plain-statements-take-no-slot"),
]


@pytest.mark.parametrize(("filler", "count", "verdict"), _WINDOW)
def test_guard_window_counts_preceding_if_and_try_siblings(
    filler: str, count: int, verdict: str
) -> None:
    program = js_handler(READ, "if (!ALLOWED.includes(p)) return;", numbered(filler, count), SINK_P)

    assert guard_verdict(subject(program), "path", SINK) == verdict


_ANCESTORS = [
    pytest.param(
        js_handler(
            READ, "if (ALLOWED.includes(p)) {", nested("if (a) {\n", "}\n", 3, f"{SINK_P}\n"), "}"
        ),
        ALLOWLIST, id="guard-three-ifs-up",
    ),
    pytest.param(
        js_handler(READ, "if (ALLOWED.includes(p)) {", "for (const x of xs) {", SINK_P, "}", "}"),
        ALLOWLIST, id="guard-around-a-loop",
    ),
    pytest.param(
        js_handler(
            READ, "if (!ALLOWED.includes(p)) { log(p); } else {", "if (a) {", SINK_P, "}", "}"
        ),
        ALLOWLIST, id="negated-guard-two-ifs-up",
    ),
    pytest.param(
        js_handler(
            READ, "const q = req.query.g;", "if (ALLOWED.includes(q)) {", "if (a) {", SINK_P, "}",
            "}",
        ),
        NO_GUARD, id="an-ancestor-testing-another-def",
    ),
]


@pytest.mark.parametrize(("program", "verdict"), _ANCESTORS)
def test_guards_are_read_from_every_if_ancestor(program: Spec, verdict: str) -> None:
    assert guard_verdict(subject(program), "path", SINK) == verdict


# ── the guard record (A29 (5)) ───────────────────────────────────────────────


def _guard_records(flows: Iterable[Any]) -> list[tuple[int, frozenset[str]]]:
    """Each guard of each flow, in order, as ``(node, roles)``."""
    return [(g.node, frozenset(g.roles)) for flow in flows for g in flow.guards]


def test_a_guard_is_its_if_node_and_its_roles() -> None:
    """A29 (5): ``guards_for`` answers ``Guard(node, roles)``: the guarding IF's node and its
    role set."""
    m = subject(js_handler(READ, "if (!ALLOWED.includes(p)) return;", SINK_P))
    flows = flows_on(m, "path", call_line(m, SINK))
    guards = _guard_records(flows)

    assert guards == [(node_at(m, Kind.IF), frozenset({"allowlist", "path_contain"}))]
    assert flow_mod().Guard(node=0, roles=frozenset()).node == 0


# ── roles: a set (L4, R4), member property names (L11) ───────────────────────

_MEMBERSHIP = frozenset({"allowlist", "path_contain"})

_JAVA_CONTAINS = '''\
    class Docs {
        void serve(HttpServletRequest request) throws Exception {
            String name = request.getParameter("name");
            if (!ALLOWED.contains(name)) return;
            new FileInputStream(name);
            Runtime.getRuntime().exec(name);
        }
    }
    '''

_PHP_IN_ARRAY = '''\
    <?php
    $name = $_GET['name'];
    if (!in_array($name, ALLOWED, true)) {
        exit('denied');
    }
    readfile($name);
    system($name);
    '''

_GO_HAS_PREFIX = '''\
    package app

    func pick(c *gin.Context) {
        p := c.Query("p")
        if !strings.HasPrefix(p, "/srv/docs/") {
            return
        }
        os.Open(p)
        exec.Command(p)
    }
    '''

# (program, the IF's guard roles, {family: (sink head, verdict)})
_ROLE_SETS = [
    pytest.param(
        js_handler("const name = req.query.name;", "if (!ALLOWED.includes(name)) return;",
            "fs.readFileSync(name);", "cp.exec(name);"),
        _MEMBERSHIP, {"path": ("fs.readFileSync", ALLOWLIST), "command": ("cp.exec", ALLOWLIST)},
        id="js-includes",
    ),
    pytest.param(
        ("java", _JAVA_CONTAINS), _MEMBERSHIP,
        {"path": ("new FileInputStream", ALLOWLIST),
         "command": ("Runtime.getRuntime().exec", ALLOWLIST)},
        id="java-contains",
    ),
    pytest.param(
        ("php", _PHP_IN_ARRAY), _MEMBERSHIP,
        {"path": ("readfile", ALLOWLIST), "command": ("system", ALLOWLIST)},
        id="php-in_array",
    ),
    pytest.param(
        ("go", _GO_HAS_PREFIX), frozenset({"path_contain"}),
        {"path": ("os.Open", PATH_CONTAIN), "command": ("exec.Command", REPORT)},
        id="go-HasPrefix-covers-no-command-sink",
    ),
    pytest.param(
        "cwe_22_go_2_clean", frozenset({"path_contain"}), {"path": ("os.Open", PATH_CONTAIN)},
        id="cwe_22_go_2_clean",
    ),
]


@pytest.mark.parametrize(("program", "roles", "sinks"), _ROLE_SETS)
def test_guard_roles_are_a_set(
    program: Spec, roles: frozenset[str], sinks: dict[str, tuple[str, str]]
) -> None:
    m = subject(program)

    assert guard_roles_of(m, if_test(m)) == roles
    assert {family: guard_verdict(m, family, head) for family, (head, _) in sinks.items()} == {
        family: verdict for family, (_, verdict) in sinks.items()
    }


# (the guards' role sets in guards_for order, family, (outcome, decline labels))
_LABELS = [
    pytest.param([("allowlist", "path_contain")], "path", ("decline", [ALLOWLIST]),
                 id="membership-path"),
    pytest.param([("allowlist", "path_contain")], "command", ("decline", [ALLOWLIST]),
                 id="membership-command"),
    pytest.param([("allowlist", "path_contain")], "request", (REPORT, []),
                 id="membership-covers-no-request"),
    pytest.param([("path_contain", "validate")], "path", ("decline", [PATH_CONTAIN]),
                 id="smallest-of-two-covering-roles"),
    pytest.param([("path_contain", "validate")], "command", ("decline", [VALIDATE]),
                 id="the-one-covering-role"),
    pytest.param([("host_allow", "path_contain")], "request", ("decline", [HOST_ALLOW]),
                 id="host-allow-request"),
    pytest.param([("host_allow", "path_contain")], "command", (REPORT, []),
                 id="no-covering-role"),
    pytest.param([("validate",), ("allowlist",)], "path", ("decline", [VALIDATE]),
                 id="the-first-covering-guard-labels"),
    pytest.param([("host_allow",), ("path_contain", "validate")], "path",
                 ("decline", [PATH_CONTAIN]), id="a-guard-covering-nothing-is-skipped"),
]


@pytest.mark.parametrize(("guards", "family", "expected"), _LABELS)
def test_decline_label_is_the_smallest_covering_role(
    guards: list[tuple[str, ...]], family: str, expected: tuple[str, list[str]]
) -> None:
    # L4 / P6: `guarded:` + min(covering roles) of the FIRST guard whose role set covers.
    flow = flow_with(family, external("request"), guards=[stub_guard(*roles) for roles in guards])

    outcome, ctx = decided(flow, family)

    assert (outcome, ctx.labels) == expected


_PY_IS_PRIVATE = '''\
    def view(request):
        ip = ipaddress.ip_address(request.args["host"])
        if ip.is_private:
            abort(403)
        return urlopen(f"http://{ip}/status")
    '''

_MEMBER_GUARDS = [
    pytest.param(("py", _PY_IS_PRIVATE), "urlopen", id="py-ip.is_private"),
    pytest.param(
        js_handler("const addr = parseAddress(req.query.host);", "if (addr.isLoopback) return;",
            "fetch(`http://${addr}/status`);"),
        "fetch", id="js-addr.isLoopback",
    ),
]


@pytest.mark.parametrize(("program", "head"), _MEMBER_GUARDS)
def test_member_property_names_are_guard_words(program: Spec, head: str) -> None:
    m = subject(program)
    test = if_test(m)
    assert m.kind(test) is Kind.MEMBER, "the TEST is a property read, not a call"

    assert "host_allow" in guard_roles_of(m, test)
    assert guard_verdict(m, "request", head) == HOST_ALLOW


def test_a_bare_name_carries_no_address_class_role() -> None:
    # R2: L12 (b) and (c) read callee identifiers and MEMBER property names only.
    m = subject(js_handler(
        "const isLoopback = checkAddress(req.query.host);", "if (isLoopback) return;",
        "fetch(req.query.host);",
    ))
    test = if_test(m)
    assert m.kind(test) is Kind.NAME

    assert "host_allow" not in guard_roles_of(m, test)


# ── host_allow, end to end (L12, R2, R3) ─────────────────────────────────────

_DECLINED = (HOST_ALLOW, True)
_REPORTED = (REPORT, False)

# (program, request sink head, (verdict, any guard carries host_allow))
_HOST_ALLOW = [
    pytest.param("cwe_918_1_clean", "fetch", _DECLINED, id="cwe_918_1_clean"),
    pytest.param("cwe_918_4_clean", "urlopen", _DECLINED, id="cwe_918_4_clean"),
    pytest.param("cwe_918_php_1_clean", "file_get_contents", _DECLINED, id="cwe_918_php_1_clean"),
    pytest.param("cwe_918_java_2_clean", "CLIENT.send", _DECLINED, id="cwe_918_java_2_clean"),
    pytest.param(
        js_handler("const target = req.query.url;", "if (!ALLOWED_HOSTS.includes(target)) return;",
            "fetch(target);"),
        "fetch", _DECLINED, id="C15-R2-plural-host-word",
    ),
    pytest.param(
        js_handler("const u = req.query.url;", "if (!new URL(u).hostname) return;", "fetch(u);"),
        "fetch", _REPORTED, id="C14-bare-truthiness",
    ),
    pytest.param(
        js_handler("const u = new URL(req.query.url);",
            'if (u.hostname == null) throw new Error("no host");', "fetch(u);"),
        "fetch", _REPORTED, id="C14-R3-presence-comparison",
    ),
]


@pytest.mark.parametrize(("program", "head", "expected"), _HOST_ALLOW)
def test_host_allow_composition(program: Spec, head: str, expected: tuple[str, bool]) -> None:
    m = subject(program)
    host_guarded = any("host_allow" in roles for roles in guard_role_sets(m, "request", head))

    assert (verdicts_at(m, "request", head), host_guarded) == expected


# ── W2: exits, single-statement consequences, module-level guards ────────────

# (fixture, family, sink head, decline label, guard kind, kinds of the statements exits reads)
_W2 = [
    pytest.param("cwe_78_11_clean", "command", "cp.exec", ALLOWLIST, Kind.IF, (Kind.RETURN,),
                 id="cwe_78_11_clean-braceless-return"),
    pytest.param("cwe_22_java_1_clean", "path", "new File", ALLOWLIST, Kind.IF, (Kind.THROW,),
                 id="cwe_22_java_1_clean-braceless-throw"),
    pytest.param("cwe_22_44_clean", "path", "open", ALLOWLIST, Kind.IF, (Kind.CALL,),
                 id="cwe_22_44_clean-python-abort"),
    pytest.param("cwe_918_go_1_clean", "request", "http.Get", HOST_ALLOW, Kind.IF,
                 (Kind.RETURN,), id="cwe_918_go_1_clean-go-statement-list"),
    pytest.param("cwe_918_php_2_clean", "request", "curl_setopt", HOST_ALLOW, Kind.IF,
                 (Kind.THROW,), id="cwe_918_php_2_clean-script-level"),
    pytest.param("cwe_22_46_clean", "path", "open", PATH_CONTAIN, Kind.TRY, (Kind.CALL,),
                 id="cwe_22_46_clean-r-r-try-sibling"),
]


@pytest.mark.parametrize(("stem", "family", "head", "label", "guard_kind", "exits"), _W2)
def test_exits_single_statement_and_module_level(
    stem: str, family: str, head: str, label: str, guard_kind: Kind, exits: tuple[Kind, ...]
) -> None:
    m = fixture_model(stem)
    guard, sink = node_at(m, guard_kind), call_at(m, head)
    # The shape the fixture pins: the guard is a sibling of stmt(sink) in the sink's own
    # block (the MODULE for a script) that ends before it, and exits() reads exactly these
    # direct statements.
    shape = (m.parent(guard), m.span(guard)[1] <= m.span(sink)[0], _statement_kinds(m, _exit_body(m, guard)))
    assert shape == (m.block_of(sink), True, exits)

    assert guard_verdict(m, family, head) == label
