"""Feature 0101 Phase 1 -- the shared lexical primitives (`skills/_lexical.py`).

The three 0101 rules (CWE-778, CWE-770, CWE-209) each carried a private copy of
word splitting, catch-binding extraction, call-argument slicing and routine
header recognition, and the copies had already diverged (three header regexes,
two binding regexes, two word splitters that disagreed on digits). This module
is the single copy. These cases are its contract; a track that needs a new form
asks the Phase 1 owner to add it here first.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import _lexical as lx
from shared.tools import pattern_matcher


class TestMaxScanChars:
    def test_is_the_pattern_matcher_cap_not_a_copy(self) -> None:
        # Identity, not equality: a literal 2000 in _lexical would be a second
        # source of truth that drifts the day the shared cap changes.
        assert lx.MAX_SCAN_CHARS is pattern_matcher._MAX_LINE_CHARS


class TestIdentifierWords:
    @pytest.mark.parametrize(
        ("ident", "words"),
        [
            ("MAX_BODY", ("max", "body")),
            ("maxItems", ("max", "items")),
            ("limit_bytes", ("limit", "bytes")),
            ("HTTPServerError", ("http", "server", "error")),
            ("$err", ("err",)),
            ("maybeAuthorize", ("maybe", "authorize")),
            # Digits stay attached to the letters before them (RM-14).
            ("oauth2Token", ("oauth2", "token")),
            ("loadX509Cert", ("load", "x509", "cert")),
            ("limit2Bytes", ("limit2", "bytes")),
            ("HTTP2Server", ("http2", "server")),
            ("kebab-case-name", ("kebab", "case", "name")),
            ("2fa", ("2fa",)),
            ("", ()),
        ],
    )
    def test_splits(self, ident: str, words: tuple[str, ...]) -> None:
        assert lx.identifier_words(ident) == words

    def test_returns_a_tuple(self) -> None:
        assert isinstance(lx.identifier_words("fooBar"), tuple)

    def test_input_is_capped(self) -> None:
        # A word past MAX_SCAN_CHARS is never seen: the cap is the bound.
        ident = "a" * lx.MAX_SCAN_CHARS + "Tail"
        assert "tail" not in lx.identifier_words(ident)


class TestCatchBinding:
    @pytest.mark.parametrize(
        ("header", "suffix", "names"),
        [
            # TS / JS
            ("} catch (err) {", "", {"err"}),
            ("} catch (e: unknown) {", "", {"e"}),
            # Kotlin
            ("} catch (e: IOException) {", ".kt", {"e"}),
            # Java, Java multi-catch, a modifier
            ("} catch (IOException e) {", ".java", {"e"}),
            ("} catch (IOException | SQLException ex) {", ".java", {"ex"}),
            ("} catch (final Exception e) {", ".java", {"e"}),
            # C# with and without a binding
            ("catch (Exception ex)", ".cs", {"ex"}),
            ("catch {", ".cs", set()),
            ("catch (Exception) {", ".cs", set()),
            ("catch (Exception) {", "", set()),
            # C++
            ("} catch (const std::exception& e) {", ".cpp", {"e"}),
            ("} catch (...) {", ".cpp", set()),
            ("} catch (const std::exception&) {", ".cpp", set()),
            # PHP: `$` stripped
            ("} catch (\\Exception $e) {", ".php", {"e"}),
            # Python
            ("except ValueError as exc:", ".py", {"exc"}),
            ("except (KeyError, IndexError) as e:", ".py", {"e"}),
            ("except:", ".py", set()),
            ("except ValueError:", ".py", set()),
            # Ruby
            ("rescue StandardError => e", ".rb", {"e"}),
            ("rescue => err", ".rb", {"err"}),
            # Swift: explicit and implicit
            ("} catch let e {", ".swift", {"e"}),
            ("} catch let error as NSError {", ".swift", {"error"}),
            ("} catch {", ".swift", {"error"}),
            # JS/TS promises: the identifier BEFORE `=>`
            ("load().catch((e) => {", ".ts", {"e"}),
            ("load().catch(e => null)", ".ts", {"e"}),
            ("load().catch(e => { return fallback(x) })", ".ts", {"e"}),
            ("load().catch((err: Error) => {", ".ts", {"err"}),
            ("load().catch(() => undefined)", ".ts", set()),
            # Scala
            ("case e: Exception =>", ".scala", {"e"}),
            ("case NonFatal(t) =>", ".scala", {"t"}),
            # Lua
            ("local ok, err = pcall(run)", ".lua", {"err"}),
            # The discard binding is never a binding (N-209-SINK).
            ("} catch (_: Throwable) {", ".kt", set()),
            ("case _ =>", ".scala", set()),
            ("case _: Throwable =>", ".scala", set()),
            ("except ValueError as _:", ".py", set()),
            # No handler clause at all.
            ("result = compute(value)", ".py", set()),
            ("", "", set()),
        ],
    )
    def test_forms(self, header: str, suffix: str, names: set[str]) -> None:
        assert lx.catch_binding(header, suffix) == frozenset(names)

    def test_swift_implicit_binding_needs_the_swift_suffix(self) -> None:
        assert lx.catch_binding("} catch {") == frozenset()
        assert lx.catch_binding("} catch {", ".kt") == frozenset()

    def test_returns_a_frozenset(self) -> None:
        assert isinstance(lx.catch_binding("} catch (e) {"), frozenset)

    def test_a_string_literal_is_not_a_clause(self) -> None:
        assert lx.catch_binding('log("catch (oops)")', ".ts") == frozenset()

    def test_header_is_capped(self) -> None:
        header = " " * lx.MAX_SCAN_CHARS + "} catch (late) {"
        assert lx.catch_binding(header) == frozenset()


class TestCallArgumentText:
    def test_balanced(self) -> None:
        assert lx.call_argument_text("f(a, b)", 1) == "a, b"

    def test_nested(self) -> None:
        text = "f(g(a), h(b, c)) + 1"
        assert lx.call_argument_text(text, 1) == "g(a), h(b, c)"

    def test_close_paren_inside_a_string(self) -> None:
        text = 'f("a)b", c) + tail'
        assert lx.call_argument_text(text, 1) == '"a)b", c'

    def test_close_paren_inside_single_quotes_and_backticks(self) -> None:
        text = "f('x)', `y)`, z)"
        assert lx.call_argument_text(text, 1) == "'x)', `y)`, z"

    def test_unterminated_is_cut_at_max_span(self) -> None:
        text = "f(" + "x" * 1000
        assert lx.call_argument_text(text, 1) == "x" * 400

    def test_custom_max_span(self) -> None:
        text = "f(" + "x" * 100
        assert lx.call_argument_text(text, 1, max_span=10) == "x" * 10

    def test_max_span_is_capped_at_max_scan_chars(self) -> None:
        text = "f(" + "x" * (lx.MAX_SCAN_CHARS * 3)
        out = lx.call_argument_text(text, 1, max_span=10**9)
        assert len(out) == lx.MAX_SCAN_CHARS

    def test_empty_call(self) -> None:
        assert lx.call_argument_text("f()", 1) == ""

    def test_open_at_not_a_paren(self) -> None:
        assert lx.call_argument_text("f(a)", 0) == ""
        assert lx.call_argument_text("f(a)", 99) == ""

    def test_returns_original_text_not_the_mask(self) -> None:
        text = "send(\"it's\", x)"
        assert lx.call_argument_text(text, 4) == "\"it's\", x"


class TestRoutineHeader:
    @pytest.mark.parametrize(
        "code",
        [
            "def f(x):",
            "    async def handler(req):",
            "function f(a) {",
            "const f = async (a) => {",
            "const g = x => {",
            "public Foo bar(int x) {",
            "fun f(x: Int) {",
            "suspend fun load(id: String): User {",
            "func run() error {",
            "fn main() {",
            "  handle(req, res) {",
        ],
    )
    def test_declarations(self, code: str) -> None:
        assert lx.routine_header(code) is True

    @pytest.mark.parametrize(
        "code",
        [
            "if (x) {",
            "for (const t of a) {",
            "switch (x) {",
            "} catch (e) {",
            "while (x) {",
            "else if (y) {",
            "return foo(x);",
            "foo(a, b);",
            "doThing(a,",
            "",
        ],
    )
    def test_not_declarations(self, code: str) -> None:
        assert lx.routine_header(code) is False

    def test_keyword_inside_a_string_is_not_a_declaration(self) -> None:
        assert lx.routine_header('msg = "def f(";') is False

    def test_header_is_capped(self) -> None:
        assert lx.routine_header(" " * lx.MAX_SCAN_CHARS + "def f(x):") is False
