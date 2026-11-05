"""Feature 0101 -- CWE-778 Concept B units: a keyword that NAMES an outcome is not
an authorization decision (LLD 5.1.3). Runs OUTSIDE the AUTH_STRIP branch (C13)."""
from __future__ import annotations

import pytest

from cwe_agent.skills import insufficient_logging_check as m
from shared.tools.line_context import strip_strings_and_comments


def is_decl(src: str, above: tuple[str, ...] = ()) -> bool:
    lines = (*above, src)
    return m._auth_line_is_declaration(strip_strings_and_comments(src), lines, len(lines))


class TestDeclarationLhs:
    @pytest.mark.parametrize("src", [
        "export const UNAUTHORIZED = 401;",
        "static readonly FORBIDDEN = 403;",
        "const val UNAUTHORIZED = 401",
        "  forbidden?: boolean;",
        "export const AUTH_DENIED = 'x';",
        "UNAUTHORIZED: { code: 401 },",
    ])
    def test_named(self, src):
        assert is_decl(src)

    def test_boolean_value_is_a_decision(self):
        assert not is_decl("  unauthorized: !session || session.expired,")

    def test_declared_local_is_skipped_and_its_use_is_judged(self):
        # LLD 5.1.3: a declared local is skipped only when its VALUE is not a
        # boolean expression. A local bound to a plain value names an outcome;
        # one bound to `!session` is the decision itself (R778-3 corrected the
        # earlier "observed" pin, which contradicted the LLD). The use is judged.
        assert is_decl("  const unauthorized = 401;")
        assert not is_decl("  const unauthorized = !session;")
        assert not is_decl("  if (unauthorized) { return deny(); }")


class TestEnums:
    def test_member_of_an_enum_body(self):
        assert is_decl("  Unauthorized = 401,", ("export enum Reason {",))

    def test_member_of_an_allman_enum_body(self):
        assert is_decl("    Unauthorized = 401,", ("public enum Reason", "{"))

    def test_one_line_enum(self):
        assert is_decl("enum class Reason { UNAUTHORIZED, FORBIDDEN }")

    def test_typed_constant_in_an_enum_body(self):
        assert is_decl("  public static final int FORBIDDEN = 403;", ("public enum Codes {", "  OTHER(500);"))

    def test_enum_constant_with_arguments(self):
        assert is_decl('  UNAUTHORIZED(401, "x"),')


class TestOtherNamingShapes:
    def test_kotlin_when_mapping(self):
        assert is_decl("    401 -> Reason.UNAUTHORIZED", ("fun f(c: Int) = when (c) {",))

    def test_pattern_alternation(self):
        assert is_decl("x = a|unauthorized|b")

    def test_logical_or_is_an_operator(self):
        assert not is_decl("  if (expired||forbidden) { return deny(); }")

    def test_type_query(self):
        assert is_decl("type T = typeof Codes.UNAUTHORIZED;")

    def test_parameter_of_a_declaration(self):
        assert is_decl("    forbidden: boolean,", ("export function make(",))

    def test_bare_case_label(self):
        assert is_decl("    case Codes.AUTH_DENIED:")

    @pytest.mark.parametrize("src", [
        "    case Role.Guest: return FORBIDDEN;",
        "    case _ => Forbidden",
        "    case .unauthorized: completion(false)",
    ])
    def test_case_arm_with_a_body_is_a_decision(self, src):
        assert not is_decl(src)


class TestListElements:
    def test_element_of_an_open_list(self):
        assert is_decl("  ...ERRORS.UNAUTHORIZED,", ("export const L = [",))

    def test_argument_of_a_multiline_call_is_a_decision(self):
        assert not is_decl("    Codes.FORBIDDEN,", ("  throw new HttpError(",))

    def test_lone_value_after_else_is_a_decision(self):
        assert not is_decl("      Forbidden", ("    if (isAdmin) Ok(form)", "    else"))

    def test_open_bracket_scan_is_bounded(self):
        above = ("export const L = [", *["  1,"] * 60)
        ch, _at, _opener = m._open_bracket_above((*above, "  ...ERRORS.UNAUTHORIZED,"), len(above) + 1)
        assert ch is None


class TestScanArm:
    def _scan(self, src: str, strip: bool) -> list[dict]:
        lines = ("export function f() {", "  return 1;", "}", src)
        out: list[dict] = []
        m._scan_auth_decision(src, len(lines), "a.ts", lines, out, set(), strip)
        return out

    def test_declaration_skipped(self):
        assert not self._scan("export const UNAUTHORIZED = 401;", True)

    def test_decision_reported(self):
        assert self._scan("if (unauthorized) { res.status(401).end(); }", True)

    def test_auth_strip_off_restores_raw_matching_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_CWE778_AUTH_STRIP", "false")
        # Concept B still applies with the strip off ...
        assert not self._scan("export const UNAUTHORIZED = 401;", False)
        # ... and raw matching (a keyword in a comment) is restored.
        assert self._scan("doThing(); // unauthorized users land here", False)
        assert not self._scan("doThing(); // unauthorized users land here", True)


class TestAuthHint:
    """The lower-cased hint is a strict necessary condition of `_AUTH_DECISION`."""

    @pytest.mark.parametrize("line", [
        "LOGIN_FAILED", "access-denied", "MfaInvalid", "token_expired", "Unauthorized",
        "FORBIDDEN", "invalid_credentials", "authReject",
    ])
    def test_every_alternative_passes_the_hint(self, line):
        assert m._AUTH_DECISION.search(line) and m._auth_candidate(line)

    def test_non_ascii_skips_the_hint(self):
        # IGNORECASE folds U+017F (long s) to `s`; `lower()` does not.
        line = "invalid_credentialſ"
        assert bool(m._AUTH_DECISION.search(line)) == m._auth_candidate(line)

    def test_unrelated_line(self):
        assert not m._auth_candidate("const total = items.length;")
