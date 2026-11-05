"""Feature 0101 -- CWE-778 revision-2 units (RED round 1: R778-1, -2, -3, -5).

R778-1  a call statement whose arguments open an anonymous callback is NOT a
        routine declaration (LLD 5.1.2(1): declaration syntax only), so the walk
        continues to the routine name above it.
R778-2  credential abbreviations and auth primitives are security roots.
R778-3  a declaration whose VALUE is a boolean expression is a decision (LLD 5.1.3).
R778-5  Concept C reads the chain head across a `.`-continuation line break.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import insufficient_logging_check as m
from shared.tools.line_context import strip_strings_and_comments


def is_decl(src: str, above: tuple[str, ...] = ()) -> bool:
    lines = (*above, src)
    return m._auth_line_is_declaration(strip_strings_and_comments(src), lines, len(lines))


class TestCallbackCallIsNotADeclaration:
    @pytest.mark.parametrize("line", [
        "  await withLock(id, async () => {",
        "  queue.run(function () {",
        "  return runInSpan('read', () => {",
        "  items.forEach((x) => {",
        "  scheduler.every(5, async function tick() {",
    ])
    def test_callback_call(self, line):
        assert not m._is_decl_line(line)

    @pytest.mark.parametrize("line", [
        "export async function rotateSigningKey(id: string) {",
        "  def bind_user(ldap, dn, pw)",
        "    fun checkPin(entered: String): Result<Unit> {",
        "  public void verify(String token) {",
        "export const verify = async (token: string) => {",
        "  async handle(req, res) {",
    ])
    def test_declaration(self, line):
        assert m._is_decl_line(line)

    def test_openers_walk_past_the_callback_to_the_routine(self):
        lines = (
            "export async function rotateSigningKey(id: string) {",
            "  await withLock(id, async () => {",
            "    try {",
            "      await vault.rotate(id);",
            "    } catch (err) {",
        )
        openers = m._opener_indices(lines, 2)
        assert openers == (1, 0)
        assert m._routine_line(lines, openers) == 0


class TestCredentialRoots:
    @pytest.mark.parametrize("ident", [
        "checkPin", "pinStore", "pw", "oldPwd", "passphrase", "compareSig", "parseBearer",
        "ldap", "bindLdapUser", "readKeychainItem", "unlockBiometric", "obtainKerberosTicket",
        "timingSafeEqual", "constantTimeCompare",
    ])
    def test_security(self, ident):
        assert m.guards_security_operation(m.identifier_words(ident)), ident

    @pytest.mark.parametrize("ident", ["pw", "pwd", "pin", "passphrase", "bearer", "newPwd"])
    def test_credential_argument(self, ident):
        assert m._names_credential(ident), ident

    @pytest.mark.parametrize("ident", [
        "loadSpinnerFrames", "pinnedTabs", "spinning", "sigma", "timing", "safeArea",
        "compileTime", "constantValue",
    ])
    def test_not_security(self, ident):
        assert not m.guards_security_operation(m.identifier_words(ident)), ident


class TestBooleanValuedDeclaration:
    @pytest.mark.parametrize("src", [
        "  const forbidden = !user.isAdmin;",
        "  const forbidden = user.role !== 'admin' && !user.owner;",
        "  let unauthorized = user.token == null || user.expired;",
        "  const forbidden = user.level < 3;",
        "  const unauthorized = !session;",
        "        val forbidden = !user.isAdmin",
        "    FORBIDDEN = not user.is_admin",
        "    UNAUTHORIZED = user.owner != req.owner",
        "    FORBIDDEN = user.banned or user.suspended",
    ])
    def test_decision(self, src):
        assert not is_decl(src)

    @pytest.mark.parametrize("src", [
        "export const FORBIDDEN = 403;",
        "        const val UNAUTHORIZED = \"reason.denied\"",
        "FORBIDDEN = 403",
        "export const UNAUTHORIZED = new HttpError<Body>(401);",
        "export const unauthorized = (res) => res.status(401);",
        "  const forbidden = denies(user, 'write');",
    ])
    def test_named(self, src):
        assert is_decl(src)


class TestPromiseHeadAcrossLines:
    def test_security_call_on_the_line_above_is_the_head(self):
        lines = (
            "export async function logout(t: string, sock: Sock) {",
            "  await authority.revokeRefreshToken(t)",
            "    .then(() => sock.close()).catch(() => {});",
        )
        assert not m._promise_swallow_excused(lines[2], lines, 3, False)

    def test_teardown_only_chain_split_is_still_excused(self):
        lines = (
            "export async function closeFeed(feed: Feed, sock: Sock) {",
            "  await feed.flush()",
            "    .then(() => sock.close()).catch(() => {});",
        )
        assert m._promise_swallow_excused(lines[2], lines, 3, False)

    def test_continuation_is_bounded(self):
        lines = ("  await authority.revokeRefreshToken(t)",) + ("    .then(() => step())",) * 40 + (
            "    .then(() => sock.close()).catch(() => {});",)
        head = m._chain_head_text(lines[-1], lines, len(lines))
        assert "revokeRefreshToken" not in head


class TestEnumBudgetSkipsComments:
    """R778-6: comment-only and blank lines do not spend the 40-line bracket budget."""

    def _documented_enum(self, members: int) -> tuple[str, ...]:
        body = []
        for k in range(members):
            body += ["  /**", f"   * Member {k}.", "   */", f"  Member{k} = {k},", ""]
        return ("export enum Reason {", *body)

    def test_member_far_below_a_documented_enum_line_is_a_name(self):
        assert is_decl("  Unauthorized = 401,", self._documented_enum(25))

    def test_code_lines_still_spend_the_budget(self):
        above = ("export enum Reason {", *(f"  Member{k} = {k}," for k in range(45)))
        assert not is_decl("  Unauthorized = 401,", above)

    @pytest.mark.parametrize("line", ["  // note", "  # note", "  /**", "   * text", "   *", "   */"])
    def test_comment_only(self, line):
        assert not m._is_code_line(line)

    @pytest.mark.parametrize("line", ["  *p = 0;", "  --count;", "  x = 1"])
    def test_code(self, line):
        assert m._is_code_line(line)

    def test_raw_scan_is_bounded(self):
        above = ("export enum Reason {", *(["  // c"] * 400))
        assert len(list(m._code_lines_above((*above, "  X = 1,"), len(above) + 1))) == 0
