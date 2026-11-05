"""Feature 0101 -- CWE-778 Concept C units (LLD 5.1.4): a promise swallow after a
teardown call, or whose fallback the code null-checks, is best effort, unless the
chain head is a security operation."""
from __future__ import annotations

import pytest

from cwe_agent.skills import insufficient_logging_check as m


class TestTeardown:
    @pytest.mark.parametrize("code", [
        "stale.disconnect().catch(() => undefined);",
        "x.then(l => l.close()).catch(() => undefined);",
        "sub.unsubscribe().catch(() => {});",
    ])
    def test_last_call_is_teardown(self, code):
        assert m._chain_tears_down(code)

    @pytest.mark.parametrize("code", [
        "revokeRefreshToken(id).finally(() => db.close()).catch(() => {});",  # teardown not last
        "req.session.destroy().catch(() => {});",                              # security receiver
        "revokeToken(t).then(() => session.destroy()).catch(() => {});",       # security head
        "api.get().then(setX).catch(() => {});",
    ])
    def test_not_excused(self, code):
        assert not m._chain_tears_down(code)


class TestNullGuard:
    def _checked(self, code, after=()):
        lines = (code, *after)
        return m._fallback_is_null_checked(code, lines, 1)

    def test_assigned_and_guarded_below(self):
        assert self._checked("const p = await r.json().catch(() => null);", ("const c = p?.code;",))
        assert self._checked("const p = await r.json().catch(() => null);", ("if (!p) return;",))

    def test_same_line_nullish(self):
        assert self._checked("return (await x.catch(() => null)) ?? DEFAULTS;")
        assert self._checked("const v = (await x.catch(() => null)) || {};")

    def test_unguarded(self):
        assert not self._checked("const v = await load().catch(() => null);", ("return render(v);",))

    def test_security_head_is_never_excused(self):
        assert not self._checked("const c = await verifyJwt(t).catch(() => null);", ("if (!c) return 401;",))
        assert not self._checked("const s = (await loadSessionFor(req).catch(() => null)) ?? GUEST;")

    def test_guard_window_is_three_lines(self):
        assert not self._checked("const p = await r.json().catch(() => null);", ("a();", "b();", "c();", "p?.x;"))

    def test_guard_pattern_is_cached(self):
        assert m._null_guard_re("p") is m._null_guard_re("p")
