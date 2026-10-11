"""Feature 0101 -- CWE-778 revision-3 units (RED round 2: R2-1 .. R2-10).

R2-1   an Allman `{` alone on its line was opened by the declaration above it, so
       the window reaches the routine name (LLD 5.1.2(1)); Allman and K&R agree.
R2-2   a block statement `name(...) {` with no keyword, modifier or return type
       (`synchronized (lock) {`, `lock (_sync)`, `withContext(..) {`) does not end
       the walk; a `() -> {` lambda is a callback like `=>`.
R2-3   only a LITERAL left-hand side makes a `X -> ...FORBIDDEN` line a mapping.
R2-4   privilege-change, credential-store, remote-login and secret-release roots.
R2-5   the bracket scan reads a memoised per-line summary (O(1) per line looked at).
R2-6   a chain whose call arguments break over lines keeps its head.
R2-7   only a teardown that is the last depth-0 call of the chain counts.
R2-8   an arrow inside a parameter type does not make a method a callback call.
R2-9   `$this->x = $e` is a field store.
R2-10  a try-with-resources opener resolves the window.
"""
from __future__ import annotations

import random
import re

import pytest

from cwe_agent.skills import insufficient_logging_check as m
from shared.tools.line_context import strip_strings_and_comments


def routine_of(lines: tuple[str, ...], start: int) -> int:
    return m._routine_line(lines, m._opener_indices(lines, start))


class TestAllmanDeclaration:
    CS = (
        "public class RecordStore",                       # 0
        "{",                                              # 1
        "    public void RevokeAllSessions(string id)",   # 2
        "    {",                                          # 3
        "        try",                                    # 4
        "        {",
        "            _store.DeleteAll(id);",
        "        }",
        "        catch (Exception ex)",
    )

    def test_declaration_above_a_lone_brace_is_the_routine(self):
        assert routine_of(self.CS, 4) == 2

    def test_window_holds_the_routine_name(self):
        assert any("RevokeAllSessions" in s for s in m._enclosing_openers(self.CS, 4))

    def test_class_line_is_not_in_the_window(self):
        assert not any("RecordStore" in s for s in m._enclosing_openers(self.CS, 4))

    def test_brace_with_a_comment(self):
        lines = ("    public void Rotate(string id)", "    { // keys", "        try")
        assert routine_of(lines, 2) == 0

    def test_php_psr12(self):
        lines = (
            "class RecordStore",
            "{",
            "    public function revokeAllSessions($userId)",
            "    {",
            "        try {",
        )
        assert routine_of(lines, 4) == 2


class TestBlockStatementIsNotTheRoutine:
    @pytest.mark.parametrize("wrapper", [
        "        synchronized (lock) {",
        "        withContext(Dispatchers.IO) {",
        "        synchronized(lock) {",
        "        with_lock(user_id) {",
        "        submit(() -> {",
    ])
    def test_kr_wrapper(self, wrapper):
        lines = (
            "    public void revokeAllGrants(String userId) {",
            wrapper,
            "            try {",
        )
        assert routine_of(lines, 2) == 0

    @pytest.mark.parametrize("wrapper", ["        lock (_sync)", "        using (var tx = _db.Begin())"])
    def test_allman_wrapper(self, wrapper):
        lines = (
            "    public void RevokeAllGrants(string userId)",
            "    {",
            wrapper,
            "        {",
            "            try",
        )
        assert routine_of(lines, 4) == 0

    def test_bare_method_in_a_class_is_the_routine(self):
        lines = (
            "export class SessionPanel {",
            "  repaint(onDone: OnDone) {",
            "    try {",
        )
        assert routine_of(lines, 2) == 1
        assert not any("SessionPanel" in s for s in m._enclosing_openers(lines, 2))

    def test_bare_method_in_an_object_literal_is_the_routine(self):
        lines = (
            "export const sessionApi = {",
            "  repaint(id) {",
            "    try {",
        )
        assert routine_of(lines, 2) == 1

    def test_lone_bare_opener_keeps_the_shipped_reading(self):
        lines = ("withContext(Dispatchers.IO) {", "    try {")
        assert routine_of(lines, 1) == 0

    def test_java_lambda_is_a_callback(self):
        assert not m._is_decl_line("        submit(() -> {")

    @pytest.mark.parametrize("line", [
        "        $this->db->transaction(function () use ($userId) {",
        "        Db::transaction(function () use ($userId) {",
    ])
    def test_php_member_call_taking_a_closure_is_a_callback(self, line):
        assert not m._is_decl_line(line)


class TestParameterTypeArrow:
    def test_method_with_a_function_typed_parameter_is_a_declaration(self):
        assert m._is_decl_line("  render(onDone: (r: Row) => void) {")

    @pytest.mark.parametrize("line", [
        "  await withLock(id, async () => {",
        "  items.forEach((x) => {",
        "  queue.run(function () {",
    ])
    def test_callback_call_still_detected(self, line):
        assert not m._is_decl_line(line)


def is_decl(src: str, above: tuple[str, ...] = ()) -> bool:
    lines = (*above, src)
    return m._auth_line_is_declaration(strip_strings_and_comments(src), lines, len(lines))


class TestWhenMappingNeedsALiteral:
    WHEN = ("    fun f(x: Int): Reason = when (x) {",)

    @pytest.mark.parametrize("src", [
        "        401 -> Reason.UNAUTHORIZED",
        "        401, 403 -> Reason.FORBIDDEN",
        '        "denied" -> Reason.FORBIDDEN',
    ])
    def test_literal_mapping_is_a_name(self, src):
        assert is_decl(src, self.WHEN)

    @pytest.mark.parametrize("src", [
        "        user.banned -> HttpStatusCode.Forbidden",
        "        Role.GUEST -> HttpStatusCode.Forbidden",
        "        else -> HttpStatusCode.Forbidden",
        "        default -> Status.FORBIDDEN;",
        "        isGuest -> Status.FORBIDDEN",
    ])
    def test_condition_is_a_decision(self, src):
        assert not is_decl(src, self.WHEN)


class TestPrivilegeAndSecretRoots:
    @pytest.mark.parametrize("ident", [
        "setuid", "setgid", "seteuid", "setegid", "setresuid", "setresgid", "setreuid", "setregid",
        "setgroups", "initgroups", "keyring", "get_keyring", "ssh", "sshConnect", "userauth_agent",
        "unseal", "unsealVault", "unlock", "seccomp", "sandbox", "SecItemCopyMatching", "SecureStore",
        "webauthn", "fido", "load_pkcs12", "lockout", "limiter", "ratelimit", "rateLimit", "pinning",
    ])
    def test_security(self, ident):
        assert m.guards_security_operation(m.identifier_words(ident)), ident

    @pytest.mark.parametrize("ident", [
        "setup", "settings", "set_title", "settle", "keyboard", "keyword", "unlocked_count",
        "secondItem", "secure", "storeItem", "rate", "limit", "pinnedTabs", "sshare_text",
    ])
    def test_not_security(self, ident):
        assert not m.guards_security_operation(m.identifier_words(ident)), ident


_OPEN_OF = {")": "(", "]": "[", "}": "{"}


def _reference_open_bracket_above(lines: tuple[str, ...], lineno: int):
    """The revision-2 backward walk (40 code lines within 160 raw, depth carried
    right to left per kind): the oracle the forward track must agree with."""
    depth = {"(": 0, "[": 0, "{": 0}
    raw = range(lineno - 2, max(-1, lineno - 2 - 160), -1)
    code_lines = [(i, m.stripped_code(lines[i])) for i in raw if m._is_code_line(lines[i])][:40]
    for i, code in code_lines:
        for b in reversed(re.findall(r"[()\[\]{}]", code)):
            opener = _OPEN_OF.get(b, b)
            if b != opener:
                depth[opener] += 1
            elif depth[b] == 0:
                return b, i, code
            else:
                depth[b] -= 1
    return None, -1, ""


class TestBracketTrack:
    def test_track_agrees_with_the_backward_walk(self):
        rng = random.Random(778)
        alphabet = ["(", ")", "[", "]", "{", "}", "a", " ", "// c(", "  * x(", "\n"]
        for _ in range(300):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
            lines = tuple(text.split("\n"))
            m._TRACKS.clear()
            for lineno in range(1, len(lines) + 1):  # forward, as the scan asks
                assert m._open_bracket_above(lines, lineno) == _reference_open_bracket_above(lines, lineno)

    def test_track_agrees_out_of_order_and_across_gaps(self):
        lines = tuple(("x(" if i % 7 == 0 else ")" if i % 11 == 0 else "a,") for i in range(900))
        for lineno in (850, 3, 600, 601, 899, 10, 400):
            assert m._open_bracket_above(lines, lineno) == _reference_open_bracket_above(lines, lineno)

    @pytest.mark.parametrize("code,may", [
        ("k: [scope(a), key(b)],", False), ("plain text", False), ("f(g(h(i(j(k)))))", True),
        ("x)", True), ("([)]", True), ("{(", True), ("a[0] = b(c);", False),
    ])
    def test_nested_line_shortcut(self, code, may):
        assert m._may_leave_open(code) is may

    def test_comment_lines_do_not_spend_the_budget(self):
        above = ("export enum Reason {", *["  /** doc */", "  // more", "  A = 1,"] * 30)
        lines = (*above, "  UNAUTHORIZED = 401,")
        assert m._open_bracket_above(lines, len(lines))[0] == "{"


class TestMultiLineChainHead:
    def _excused(self, src: tuple[str, ...]) -> bool:
        return m._promise_swallow_excused(src[-1], src, len(src), False)

    def test_teardown_after_a_security_call_split_over_lines(self):
        assert not self._excused(("  revokeAllTokens(", "    userId,", "  ).then(() => conn.close()).catch(() => {});"))

    def test_fallback_after_a_security_call_split_over_lines(self):
        assert not self._excused(("  const c = await verifySession(", "    userId,", "  ).catch(() => null) ?? GUEST;"))

    def test_ordinary_split_chain_is_still_excused(self):
        assert self._excused(("  flushFeed(", "    feedId,", "  ).then(() => conn.close()).catch(() => {});"))
        assert self._excused(("  const t = await loadTheme(", "    userId,", "  ).catch(() => null) ?? DEFAULTS;"))

    def test_prefix_reaches_the_opening_line(self):
        lines = ("  revokeAllTokens(", "    userId,", "  ).catch(() => {});")
        assert m._chain_prefix(lines, 3) == ["revokeAllTokens(", "userId,"]

    def test_prefix_is_bounded(self):
        lines = ("  revokeAllTokens(", *["    a,"] * 20, "  ).catch(() => {});")
        assert len(m._chain_prefix(lines, len(lines))) <= m._CHAIN_LOOKBACK


class TestTeardownIsTheLastCall:
    @pytest.mark.parametrize("code", [
        "loadCache().then(() => db.close()).then(render).catch(() => {});",
        "loadCache().finally(() => db.close()).catch(() => {});",
        "loadCache().then(() => { db.close(); return reload(); }).catch(() => {});",
    ])
    def test_earlier_teardown_does_not_count(self, code):
        assert not m._chain_tears_down(code)

    @pytest.mark.parametrize("code", [
        "stale.disconnect().catch(() => undefined);",
        "x.then(l => l.close()).catch(() => undefined);",
        "loadCache().then(() => db.close()).catch(() => {});",
    ])
    def test_last_call_teardown(self, code):
        assert m._chain_tears_down(code)


class TestPhpFieldStore:
    def test_arrow_member_is_a_field_target(self):
        asg = m._plain_assignment("$this->lastError = $e;")
        assert asg is not None and asg.group("lhs") == "$this->lastError"
        assert m._assign_hands_on(asg, "$this->lastError = $e;", frozenset({"e", "$e"}), frozenset())

    def test_nested_arrow_member(self):
        asg = m._plain_assignment("$this->state->error = $e;")
        assert asg is not None and asg.group("lhs") == "$this->state->error"

    def test_element_write_through_a_member_chain_stays_the_residual(self):
        # `$this->errors[] = $e` is pinned as residual R5 (fixtures/residual/residual.php).
        assert m._plain_assignment("$this->errors[] = $e;") is None

    def test_comparison_is_not_an_assignment(self):
        assert m._plain_assignment("$this->a == $e") is None


class TestTryWithResources:
    @pytest.mark.parametrize("line", [
        "        try (Reader r = open(id)) {",
        "        try (var in = Files.newInputStream(p); var out = sink(q)) {",
        "        try (Reader r = open(id))",
    ])
    def test_opens_try(self, line):
        assert m._opens_try(line, False)

    @pytest.mark.parametrize("line", ["        retry(x) {", "        tryParse(x) {", "        entry (a) {"])
    def test_not_a_try(self, line):
        assert not m._opens_try(line, False)
