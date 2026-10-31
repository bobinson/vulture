"""Feature 0101 -- unit contract of the CWE-209 value resolver (LLD 5.3.3, 5.3.4).

One class per helper. Each case is a synthetic one-liner; the E2E file
(`tests/e2e/test_0101_cwe209_error_disclosure.py`) carries the whole-file shapes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills import info_exposure_check as iec


def _scope(lines: list[str], line_num: int | None = None, prefix: str = "", suffix: str = ".ts") -> iec._Scope:
    return iec._Scope(lines, line_num or len(lines), prefix, suffix=suffix)


def _sink_peer(line: str) -> bool:
    sink = iec._RESPONSE_WRITE.search(line)
    assert sink, f"no sink in {line!r}"
    return iec._sink_is_peer(line, sink.start(), sink.end())


def _discloses(src: str, suffix: str = ".ts") -> bool:
    """Does the LAST line of ``src`` disclose an error (through the 209 entry)?"""
    lines = src.rstrip("\n").split("\n")
    return iec._discloses_error(Path(f"app/h{suffix}"), lines[-1], len(lines), lines)


class TestResponseWrite:
    @pytest.mark.parametrize("line", [
        "res.json(x)", "res.end(x)", "res.send(x)", "res.write(x)", "res.writeHead(500, x)",
        "res.sendStatus(500)", "call.respondText(x)", "ctx.Response.WriteAsJsonAsync(x)",
        "response.sendError(500, x)", "stream.write_all(x)", "self.send_error(500, x)", "$r->write($x)",
    ])
    def test_response_shaped_verbs_are_sinks(self, line: str) -> None:
        assert iec._RESPONSE_WRITE.search(line)

    @pytest.mark.parametrize("line", [
        "Fault.writeFailed(x)", "session.sendMessage(x)", "context.sendActivity(x)",
        "opts.sendInvokeResult(x)", "name.endsWith(x)", "fs.writeFileSync(p, x)", "mailer.sendMail(x)",
        "channel.sendToQueue(q, x)", "navigator.sendBeacon(u, x)",
    ])
    def test_other_suffixes_are_not_sinks(self, line: str) -> None:
        assert not iec._RESPONSE_WRITE.search(line)


class TestSinkIsPeer:
    @pytest.mark.parametrize("line", [
        "res.status(500).json(x)", "ws.send(x)", "c.JSON(500, x)", "Response.Write(x)",
        "await context.Response.WriteAsync(x)", "conn.write(x)",
    ])
    def test_peer_writes(self, line: str) -> None:
        assert _sink_peer(line)

    @pytest.mark.parametrize("line", [
        "process.stderr.write(x)", "sys.stdout.write(x)", "sb.WriteString(x)", "logger.write(x)",
        "process.send(x)", "Console.Error.WriteLine(x)".replace("WriteLine", "Write"),
        "fileBuffer.write(x)", "io.WriteString(os.Stderr, x)", "Pipeline.send(x)",
    ])
    def test_local_writes(self, line: str) -> None:
        assert not _sink_peer(line)


class TestPremask:
    @pytest.mark.parametrize(("text", "gone"), [
        ("PUBLIC[err.message]", "err"),
        ("{ ok: !err }", "err"),
        ("err.code === 'E1'", "err"),
        ("err instanceof HttpFault", "err"),
        ("err.message.includes('dup') ? a : b", "err"),
        ("err ? 'failed' : null", "err"),
        ("new { error = 'x' }", "error"),
    ])
    def test_read_not_written_tokens_are_removed(self, text: str, gone: str) -> None:
        assert gone not in iec._premask(text)

    def test_spread_becomes_the_bare_value(self) -> None:
        assert "...err" not in iec._premask("{ ...err }") and "err" in iec._premask("{ ...err }")
        assert "**exc" not in iec._premask("dict(**exc)") and "exc" in iec._premask("dict(**exc)")

    def test_elvis_default_is_a_value_not_a_condition(self) -> None:
        assert "e.message" in iec._premask('e.message ?: "x"')

    def test_array_literal_is_not_an_index(self) -> None:
        assert "err" in iec._premask("[err]")


class TestMethodStringifier:
    @pytest.mark.parametrize("call", [
        "err.toJSON()", "e.to_string()", "e.toString()", "ex.ToString()", "e.to_s()", "e.inspect()",
        "e.getMessage()", "e.getLocalizedMessage()", "e.stackTraceToString()", "e.getTraceAsString()",
        "err.Error()",
    ])
    def test_stringifier_is_replaced_by_its_receiver(self, call: str) -> None:
        scope = _scope(["try { run() } catch (e) {", "x"])
        out = iec._neutralise_calls(call, scope)
        assert out is not None and call.split(".")[0] in out.split()


class TestStringTransforms:
    @pytest.mark.parametrize("text", [
        "String(err).slice(0, 500)", "str(exc).encode()", "`${err}`.trim()", "String(err).toUpperCase()",
    ])
    def test_string_preserving_transform_keeps_the_error(self, text: str) -> None:
        lines = ["try { run() } catch (err) {", "except Exception as exc:", "x"]
        assert iec._args_disclose(iec._strip_literals_209(text), _scope(lines))


class TestCallReplacement:
    lines = ["try { run() } catch (e) {", "x"]

    def test_stringifier_of_an_error_discloses(self) -> None:
        assert iec._call_replacement("String", "e", _scope(self.lines)) is None

    def test_extractor_of_an_error_discloses(self) -> None:
        assert iec._call_replacement("getErrorMessage", "e", _scope(self.lines)) is None

    def test_stack_verb_noun_pair_is_an_extractor(self) -> None:
        assert iec._is_extractor("format_exception") and iec._is_extractor("dumpStack")
        assert not iec._is_extractor("formatQuotaError")

    def test_extractor_word_with_projection_last_word_is_not(self) -> None:
        assert not iec._is_extractor("getTraceId")

    def test_projection_role_is_opaque(self) -> None:
        assert iec._call_replacement("formatQuotaError", "e", _scope(self.lines)) == iec._OPAQUE
        assert iec._call_replacement("toSafeView", "e", _scope(self.lines)) == iec._OPAQUE

    def test_other_calls_pass_their_arguments_through(self) -> None:
        assert iec._call_replacement("Buffer.from", "e", _scope(self.lines)).split() == ["e"]

    def test_opaque_placeholder_can_never_resolve(self) -> None:
        assert iec._OPAQUE.strip() == "0"


class TestCaughtRootInversion:
    lines = ["try { run() } catch (problem) {", "x"]

    @pytest.mark.parametrize("member", ["response.data", "sqlDetail", "errors", "cause", "args", "localizedMessage"])
    def test_any_member_of_a_caught_root_is_detail(self, member: str) -> None:
        assert iec._member_chain_discloses(f"problem.{member}", _scope(self.lines))

    @pytest.mark.parametrize("member", ["code", "status", "statusCode", "name", "payload", "publicMessage", "expose"])
    def test_safe_projection_members(self, member: str) -> None:
        assert not iec._member_chain_discloses(f"problem.{member}", _scope(self.lines))


class TestErrorNamedChain:
    def test_unresolved_error_named_detail(self) -> None:
        assert iec._member_chain_discloses("uploadError.message", _scope(["x"]))

    def test_clean_root_is_not_an_error_by_name(self) -> None:
        lines = ["const err = Errors.TIMEOUT", "x"]
        assert not iec._member_chain_discloses("err.message", _scope(lines))

    def test_type_constant_member(self) -> None:
        assert not iec._member_chain_discloses("ValidationError.MISSING.message", _scope(["x"]))

    def test_non_detail_last_member(self) -> None:
        assert not iec._member_chain_discloses("uploadError.retryAfter", _scope(["x"]))


class TestBindingFacts:
    def test_caught_binding(self) -> None:
        assert "err" in iec._line_facts("} catch (err) {", ".ts").caught
        assert "e" in iec._line_facts("    except ValueError as e:", ".py").caught
        assert "t" in iec._line_facts("    case NonFatal(t) =>", ".scala").caught
        assert "err" in iec._line_facts("local ok, err = pcall(run)", ".lua").caught

    @pytest.mark.parametrize(("header", "suffix"), [
        ("} catch (err) {", ".ts"), ("} catch (e: unknown) {", ".ts"), ("catch (IOException e) {", ".java"),
        ("catch (A | B e) {", ".java"), ("catch (Exception ex) {", ".cs"), ("catch (Exception) {", ".cs"),
        ("} catch (\\Throwable $ex) {", ".php"), ("except ValueError as e:", ".py"), ("except:", ".py"),
        ("rescue StandardError => e", ".rb"), ("} catch let e {", ".swift"), ("} catch {", ".swift"),
        (".catch((e) => {", ".ts"), (".catch(e => fallback(e))", ".js"), ("case e: Exception =>", ".scala"),
        ("case NonFatal(t) =>", ".scala"), ("local ok, err = pcall(run)", ".lua"),
        ("} catch (_: Throwable) {", ".kt"), ("res.json(x)", ".ts"), ("const e = 1", ".ts"),
    ])
    def test_keyword_prefilter_agrees_with_catch_binding(self, header: str, suffix: str) -> None:
        from cwe_agent.skills._lexical import catch_binding

        assert iec._line_facts(header, suffix).caught == catch_binding(header, suffix)

    def test_discard_binding_binds_nothing(self) -> None:
        assert not iec._line_facts("} catch (_: Throwable) {", ".kt").caught

    def test_swift_implicit_binding(self) -> None:
        assert "error" in iec._line_facts("} catch {", ".swift").caught
        assert not iec._line_facts("} catch {", ".ts").caught

    def test_assignment_and_destructuring(self) -> None:
        facts = iec._line_facts("const why = problem.message", ".ts")
        assert facts.assigns["why"].startswith("problem.message")
        names, source = iec._line_facts("const { message, stack } = e", ".ts").destructure
        assert {"message", "stack"} <= names and source == "e"

    def test_destructured_from_a_caught_error_is_tainted(self) -> None:
        lines = ["try { run() } catch (e) {", "  const { message, stack } = e", "x"]
        assert iec._resolve("message", _scope(lines)) == "tainted"

    def test_self_wrap_inherits_the_older_binding(self) -> None:
        lines = ["try { run() } catch (err) {", "  err = coerceFault(err)", "x"]
        assert iec._resolve("err", _scope(lines)) == "caught"

    def test_literal_and_constant_are_clean(self) -> None:
        assert iec._resolve("msg", _scope(["const msg = 'nope'", "x"])) == "clean"
        assert iec._resolve("err", _scope(["const err = Errors.TIMEOUT", "x"])) == "clean"

    def test_go_short_declaration_from_a_call_is_unknown(self) -> None:
        assert iec._resolve("err", _scope(["\trows, err := db.Query(q)", "x"], suffix=".go")) == "unknown"

    def test_projection_of_an_error_is_clean(self) -> None:
        lines = ["try { run() } catch (err) {", "  const quotaFault = formatQuotaError(err)", "x"]
        assert iec._resolve("quotaFault", _scope(lines)) == "clean"

    def test_projection_named_call_without_an_error_argument_stays_unknown(self) -> None:
        lines = ["  const accountRes = await loadAccountById(uid)", "x"]
        assert iec._resolve("accountRes", _scope(lines)) == "unknown"

    def test_resolution_depth_is_bounded(self) -> None:
        lines = ["try { run() } catch (e) {", "const a = e.message", "const b = a", "const c = b",
                 "const d = c", "x"]
        assert iec._resolve("b", _scope(lines)) == "tainted"
        assert iec._resolve("d", _scope(lines)) == "unknown"

    def test_window_is_bounded(self) -> None:
        lines = ["try { run() } catch (problem) {", *["  step()"] * iec._BINDING_RADIUS, "x"]
        assert iec._resolve("problem", _scope(lines)) == "unknown"


class TestParamBinding:
    def test_error_first(self) -> None:
        assert iec._param_binding("app.use((err, req, res, next) => {", "err") == "caught"

    def test_untyped_error_named(self) -> None:
        assert iec._param_binding("function sendFailure(res, err) {", "err") == "caught"

    def test_base_error_typed(self) -> None:
        assert iec._param_binding("function f(res, error: Error) {", "error") == "caught"
        assert iec._param_binding("void f(Response res, Exception error) {", "error") == "caught"

    def test_scalar_typed(self) -> None:
        assert iec._param_binding("function f(res, error: string) {", "error") == "clean"

    def test_domain_typed(self) -> None:
        assert iec._param_binding("function f(res, err: HandlerFault) {", "err") == "clean"

    def test_non_error_named(self) -> None:
        assert iec._param_binding("function f(res, payload) {", "payload") == "clean"

    def test_not_a_parameter(self) -> None:
        assert iec._param_binding("function f(res, payload) {", "err") is None


class TestExactErrorName:
    @pytest.mark.parametrize("name", ["err", "error", "exc", "exception", "$err"])
    def test_conventional_names(self, name: str) -> None:
        assert iec._EXACT_ERROR_NAME.fullmatch(name)

    @pytest.mark.parametrize("name", ["e", "ex", "errors", "errMsg", "failure"])
    def test_other_names(self, name: str) -> None:
        assert not iec._EXACT_ERROR_NAME.fullmatch(name)


class TestStripLiterals209:
    def test_template_hole_is_kept(self) -> None:
        assert "err" in iec._strip_literals_209("`failed: ${err}`")

    def test_identifier_brace_hole_is_kept(self) -> None:
        assert "exc" in iec._strip_literals_209('f"failed: {exc}"')

    def test_json_text_in_a_raw_string_is_dropped(self) -> None:
        assert "error" not in iec._strip_literals_209('`{"error":"disabled"}`')


class TestTokenCap:
    def test_cap_value(self) -> None:
        assert iec._MAX_TOKENS == 32

    def test_past_the_cap_only_exact_names_count(self) -> None:
        lines = ["try { run() } catch (failure) {", "x"]
        filler = ", ".join(f"v{i}" for i in range(40))
        assert not iec._bare_error_reaches(f"{filler}, failure", _scope(lines))
        assert iec._bare_error_reaches(f"{filler}, err", _scope(lines))
        assert iec._bare_error_reaches("v1, failure", _scope(lines))


class TestLogSpan:
    def test_log_call_span_is_blanked(self) -> None:
        masked = iec._mask_log_calls("console.error(err); res.json(err)")
        assert "console" not in masked and "res.json(err)" in masked
        assert len(masked) == len("console.error(err); res.json(err)")

    def test_line_without_a_log_call_is_unchanged(self) -> None:
        line = "res.json(err)"
        assert iec._mask_log_calls(line) is line

    def test_write_on_a_log_line_is_still_judged(self) -> None:
        assert _discloses("try { run() } catch (err) { console.error(err); res.status(500).json({ error: err.message }) }")

    def test_error_inside_the_log_span_only_is_clean(self) -> None:
        assert not _discloses("try { run() } catch (err) { logger.error(err.stack); res.status(500).send('failed') }")


class TestStackArm:
    def test_stack_to_a_peer_reports(self) -> None:
        assert _discloses("function h(e, req, res) {\n  res.end(e.stack)")

    def test_stack_to_stderr_is_clean(self) -> None:
        assert not _discloses("try { run() } catch (err) {\n  process.stderr.write(err.stack)")


class TestProse:
    def test_prose_file_is_never_judged(self) -> None:
        assert not _discloses("try { run() } catch (err) { res.json({ error: err.message }) }", suffix=".md")
