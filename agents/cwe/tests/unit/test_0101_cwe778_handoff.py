"""Feature 0101 -- CWE-778 Concept A units (LLD 5.1.2, 5.1.5).

A non-empty handler that neither logs nor propagates is excused only when its
try opener resolves, it HANDS THE FAILURE ON, and the guarded operation is not
security-relevant. These tests pin each predicate in isolation; the business
contract over whole files is ``tests/e2e/test_0101_cwe778_precision.py``.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import insufficient_logging_check as m
from cwe_agent.skills._lexical import MAX_SCAN_CHARS

NONE: frozenset[str] = frozenset()


def ctx(prior=NONE, params=NONE):
    return m._HandlerContext(openers=(), prior=frozenset(prior), params=frozenset(params))


def hands_on(body, binding=("e",), prior=NONE, params=NONE, tail=""):
    return m._handler_hands_on(tail, list(body), m._evidence_names(frozenset(binding)), ctx(prior, params))


# ---------------------------------------------------------------- evidence

class TestEvidence:
    def test_the_binding_itself_is_evidence(self):
        assert m._mentions_evidence("return wrap(err)", {"err"})

    def test_a_longer_identifier_is_not_the_binding(self):
        assert not m._mentions_evidence("return wrap(errCount)", {"err"})

    @pytest.mark.parametrize("text", [
        "type(e)", "typeof e", "e.__class__", "e.constructor", "e.GetType()",
        "e.getClass()", "e.javaClass", "type(e).__name__", "e::class",
    ])
    def test_type_only_use_is_not_evidence(self, text):
        assert not m._mentions_evidence(text, {"e"})

    def test_type_only_reads_a_bounded_look_behind(self):
        # RM-06: the look-behind is a fixed 16-character window, never the prefix.
        far = "typeof " + " " * 40 + "e"
        assert m._mentions_evidence(far, {"e"})

    def test_type_only_helper(self):
        text = "x = typeof e"
        match = m._name_re("e").search(text)
        assert m._type_only(text, match)

    def test_php_sigil_variant_is_evidence(self):
        names = m._evidence_names(frozenset({"e"}))
        assert m._mentions_evidence("return ['error' => $e];", names)

    def test_interpolation_reads_template_holes(self):
        assert m._interpolates('return f"Error: {exc}"', {"exc"})
        assert m._interpolates("return `failed ${ err }`", {"err"})
        assert not m._interpolates("return f'{excess}'", {"exc"})


# ---------------------------------------------------------------- statements

class TestStatements:
    def test_joins_by_bracket_depth(self):
        out = [s for s in m._statements("", ["return {", "  status: 'x',", "  message: err.message,", "};"]) if s[0]]
        assert len(out) == 1 and "message: err.message" in out[0][0]

    def test_allman_lone_brace_is_dropped_and_braced_statement_split(self):
        out = m._statements("", ["{", "_errors.Add(ex);", "return null;", "}"])
        assert [c for c, _ in out if c][:2] == ["_errors.Add(ex);", "return null;"]
        split = m._statements("{ _errors.Add(ex); return null; }", [])
        assert [c for c, _ in split] == ["_errors.Add(ex)", "return null"]

    def test_each_statement_is_capped(self):
        out = m._statements("", ["x(" + "a, " * 3000 + ")"])
        assert all(len(c) <= MAX_SCAN_CHARS and len(r) <= MAX_SCAN_CHARS for c, r in out)

    def test_allman_and_kr_twins_agree(self):
        body_allman = ["{", "    _errors.Add(ex);", "    return null;", "}"]
        body_kr = ["    _errors.Add(ex);", "    return null;", "}"]
        assert hands_on(body_allman, ("ex",)) == hands_on(body_kr, ("ex",)) is True


class TestCallChain:
    @pytest.mark.parametrize("expr", ["res.status(500).json(err)", "a.b(1) .c(2)", "f(x)(y).z()"])
    def test_chain(self, expr):
        assert m._is_call_chain(expr)

    @pytest.mark.parametrize("expr", ["wrap(err)", "{ ok: f(x) }", "f(g(x))", "f(x)[0]"])
    def test_not_chain(self, expr):
        assert not m._is_call_chain(expr)

    def test_statement_position_reads_a_bounded_look_behind(self):
        code = "x" * 500 + " ; report(e)"
        assert m._statement_position(code, code.index("report"))
        assert not m._statement_position("const v = report(e)", len("const v = "))


# ---------------------------------------------------------------- strategies

class TestStrategies:
    def test_return_with_evidence(self):
        assert hands_on(["return wrapUnknown(e);"])

    def test_return_without_evidence(self):
        assert not hands_on(["return null;"])

    def test_return_of_a_chain_is_judged_as_the_call(self):
        assert not hands_on(["return res.status(500).json(readable(e));"])

    @pytest.mark.parametrize("stmt", ["this.lastError = e;", "self._last = e", "@error = e", "errs[key] = e;"])
    def test_store_to_a_field(self, stmt):
        assert hands_on([stmt])

    def test_store_to_a_name_that_existed_before_the_try(self):
        assert hands_on(["lastError = e;"], prior={"lastError"})

    def test_store_to_a_fresh_name_is_not_a_hand_off(self):
        # RM-05: nothing reads it; the Python and TS twins agree.
        assert not hands_on(["lastError = e;"])
        assert not hands_on(["detail = str(e)", "return None"])

    def test_store_without_evidence_is_not_a_hand_off(self):
        assert not hands_on(["failed = true;"], prior={"failed"})

    def test_alias_carries_evidence(self):
        assert hands_on(["const msg = e.message;", "return { ok: false, error: msg };"])

    def test_append_operator(self):
        assert hands_on(["@errors << e"])

    @pytest.mark.parametrize("verb", ["push", "append", "add", "insert", "enqueue", "store"])
    def test_collect_verbs_need_evidence(self, verb):
        assert hands_on([f"results.{verb}(e);"])
        assert not hands_on([f"results.{verb}(1);"])

    def test_set_is_not_a_collect_verb(self):
        assert not hands_on(["res.set('X-Error', e.message);"])
        assert not hands_on(["setTimeout(() => reload(e), 1000);"])

    @pytest.mark.parametrize("call", ["report(e)", "recordMiss('op', x, e)", "notify(e)", "track(e)"])
    def test_report_verbs(self, call):
        assert hands_on([call + ";"])

    def test_failure_named_routine(self):
        assert hands_on(["onReloadFailure(e)"])
        assert hands_on(["showFailureToast('Failed', Level.ERROR);"])

    @pytest.mark.parametrize("call", ["swallowError(e)", "ignoreFailures()", "clearFailures()",
                                      "resetErrorState()", "cleanup(e)", "suppressFailures()"])
    def test_negating_verbs_never_hand_on(self, call):
        assert not hands_on([call + ";"])

    def test_predicate_verbs_never_hand_on(self):
        assert not hands_on(["isError(e);"])

    def test_callback_forwarding_is_decided_by_routine_parameters(self):
        assert hands_on(["cb(e);"], params={"cb"})
        assert not hands_on(["cb(e);"])
        assert not hands_on(["cb(null);"], params={"cb"})

    def test_a_consumed_call_is_not_a_statement(self):
        assert not hands_on(["res.json({ ...buildErrorPayload(Catalog.BAD) });"])

    def test_header_tail_is_part_of_the_body(self):
        assert hands_on([], tail=" this.lastError = e; }")


# ---------------------------------------------------------------- window

class TestWindow:
    def test_try_start_resolves(self):
        lines = ("def f():", "    try:", "        g()", "    except E as e:")
        assert m._try_start(lines, 3) == 1

    def test_try_start_beyond_80_lines_is_unresolved(self):
        lines = ("  try {", *["    x();"] * 85, "  } catch (e) {")
        assert m._try_start(lines, len(lines) - 1) == -1

    def test_ruby_method_level_rescue_resolves_to_def(self):
        lines = ("class A", "  def call", "    work", "  rescue X => e", "  end")
        assert m._try_start(lines, 3) == 1

    def test_ruby_rescue_without_def_is_unresolved(self):
        lines = ("class A", "  work", "  rescue X => e")
        assert m._try_start(lines, 2) == -1

    @pytest.mark.parametrize("line", ["if (x) {", "for (const t of a) {", "switch (x) {",
                                      "} catch (e) {", "while (x) {"])
    def test_control_openers_are_not_declarations(self, line):
        assert not m._is_decl_line(line)

    @pytest.mark.parametrize("line", ["def f(x):", "function f(a) {", "const f = async (a) => {",
                                      "public Foo bar(int x) {", "fun f(x: Int) {"])
    def test_declarations(self, line):
        assert m._is_decl_line(line)

    def test_enclosing_openers_follow_a_multiline_signature(self):
        lines = (
            "export async function load(",
            "  sessionToken: string,",
            ") {",
            "  try {",
            "    run();",
            "  } catch (e) {",
        )
        openers = m._enclosing_openers(lines, 3)
        assert openers[-1].startswith("export async function load(")

    def test_unresolved_routine_keeps_every_opener(self):
        # No declaration inside the 300-line bound: every opener met is guarded text.
        lines = ("  if (a) {", "    for (const x of y) {", *["      z();"] * 20,
                 "      try {", "        q();", "      } catch (e) {")
        openers = m._enclosing_openers(lines, len(lines) - 3)
        assert [o.strip() for o in openers] == ["for (const x of y) {", "if (a) {"]
        far = ("function f(t) {", *["  y();"] * 310, "  try {", "    q();", "  } catch (e) {")
        assert not any(m._is_decl_line(o) for o in m._enclosing_openers(far, len(far) - 3))

    def test_names_before_try_include_parameters_and_assignments(self):
        lines = ("function f(a, cb) {", "  let lastError = null;", "  try {", "    g();", "  } catch (e) {")
        ctx_ = m._handler_context(lines, 5)
        assert {"a", "cb", "lastError"} <= ctx_.prior
        assert {"a", "cb"} <= ctx_.params

    def test_unresolved_try_gives_no_context(self):
        lines = ("  x();", "  } catch (e) {")
        assert m._handler_context(lines, 2) is None


# ---------------------------------------------------------------- security gate

class TestSecurityGate:
    @pytest.mark.parametrize("ident", [
        "verifyToken", "bcrypt", "decryptBlob", "cryptoBox", "findByApiKey", "signingKeys",
        "passwordHash", "hash", "x509Cert", "oauth2Client", "sessionStore", "tokenizer",
    ])
    def test_security_identifiers(self, ident):
        assert m.guards_security_operation(m.identifier_words(ident))

    @pytest.mark.parametrize("ident", ["hashmap", "hashes", "publicKey", "loadRows", "readSheet"])
    def test_non_security_identifiers(self, ident):
        # `hash` is an exact word, not a prefix; `publicKey` is not a key compound.
        assert not m.guards_security_operation(m.identifier_words(ident))

    def test_a_content_hash_argument_is_not_a_credential(self):
        assert not m._text_is_security("store.save(recordHash, blobHash)")

    @pytest.mark.parametrize("ident", ["tokenizer", "authorName"])
    def test_over_match_is_by_design(self, ident):
        # Prefix roots over-match (`token`, `auth`): a precision cost, never a recall loss.
        assert m.guards_security_operation(m.identifier_words(ident))

    def test_object_keys_are_not_arguments(self):
        assert not m._text_is_security("contacts.save({ addressVerified: true, cachePolicy: 1 })")
        assert m._text_is_security("check(sessionToken)")

    def test_callee_chain_segments_count(self):
        assert m._text_is_security("Parser.builder().setSigningKey(k).build().parseClaimsJws(t)")

    def test_exception_type_in_the_handler_header_counts(self):
        lines = ("def f(raw):", "    try:", "        unpack(raw)", "    except (BadSignature, X) as e:")
        c = m._handler_context(lines, 4)
        assert m._window_is_security(lines, 4, lines[3], c)

    def test_neutral_window(self):
        lines = ("def f(raw):", "    try:", "        unpack(raw)", "    except ValueError as e:")
        c = m._handler_context(lines, 4)
        assert not m._window_is_security(lines, 4, lines[3], c)

    def test_unresolved_window_is_security(self):
        lines = ("    x()", "    except ValueError as e:")
        assert m._window_is_security(lines, 2, lines[1], None)


class TestExcusal:
    def test_handed_on_outside_security_is_excused(self):
        lines = ("function f(path) {", "  try {", "    read(path);", "  } catch (e) {", "    return wrap(e);", "  }")
        assert m._excused_as_handed_on(lines[3], "", list(lines[4:5]), lines, 4, ".ts")

    def test_handed_on_inside_security_is_reported(self):
        lines = ("function f(t) {", "  try {", "    verifyJwt(t);", "  } catch (e) {", "    return wrap(e);", "  }")
        assert not m._excused_as_handed_on(lines[3], "", list(lines[4:5]), lines, 4, ".ts")

    def test_swift_implicit_binding(self):
        lines = ("func f() {", "    do {", "        try read()", "    } catch {", "        self.last = error", "    }")
        assert m._excused_as_handed_on(lines[3], "", list(lines[4:5]), lines, 4, ".swift")

    @pytest.mark.parametrize("body, excused", [
        (["logger.error(e)"], True), (["throw e;"], True),
        (["handleApiError(error, res);"], True), (["return null;"], False),
    ])
    def test_handler_is_excused_unchanged(self, body, excused):
        assert m._handler_is_excused(body) is excused

    def test_metric_version(self):
        assert m._METRIC_VERSION == "0101.1"

    def test_guard_scope_knob_is_gone(self):
        assert not hasattr(m, "GUARD_SCOPE")
