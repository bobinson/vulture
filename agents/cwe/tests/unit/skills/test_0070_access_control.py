"""Feature 0070 — access_control_check precision (CWE-862) + CWE-863 JS/TS.

CWE-862 was a whole-FILE boolean: one `AUTHZ_PRESENT` hit anywhere in a file
exonerated every route in it, and a miss condemned every route in it. On
juice-shop that produced 109 identical rows out of a single `server.ts`,
because juice-shop's entire authz vocabulary (`security.isAuthorized()`,
`security.denyAll()`, `security.isAccounting()`) was unknown to the pattern.

Three layers are asserted here:
  (a) the `security.*` authz vocabulary is recognised, per route,
  (b) a route under a prefix mounted with `app.use('<prefix>', <authz>)`
      inherits that authz,
  (c) a file with many unprotected routes yields ONE rollup finding.

CWE-863 gains the JS/TS role-string idioms.
"""

import pytest

from cwe_agent.skills.access_control_check import (
    ROLE_STRING_CMP,
    check_access_control,
)


def _authz(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["category"] == "CWE-862"]


def _run(source_dir) -> list[dict]:
    return check_access_control(str(source_dir))["findings"]


# ---------------------------------------------------------------------------
# (a) per-route evaluation + the security.* vocabulary
# ---------------------------------------------------------------------------

class TestPerRouteAuthz:
    """The authz decision must be per-route, not per-file."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_guarded_route_in_unguarded_file_is_silent(self, source_dir):
        """A route carrying inline authz is not reported even though its
        neighbours in the same file are unprotected."""
        code = (
            "app.get('/api/Public', listPublic())\n"
            "app.get('/api/Users', security.isAuthorized())\n"
            "app.get('/api/Other', listOther())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        rows = _authz(_run(source_dir))
        reported = " ".join(r["description"] for r in rows)
        assert "/api/Users" not in reported

    def test_unguarded_route_in_guarded_file_reports(self, source_dir):
        """Impossible before 0070: the file has authz, so the whole-file
        boolean exonerated the one route that has none."""
        code = (
            "app.get('/api/Users', security.isAuthorized())\n"
            "app.post('/api/Complaints', security.isAuthorized())\n"
            "app.delete('/api/Secrets', dropEverything())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        rows = _authz(_run(source_dir))
        assert len(rows) == 1
        assert "/api/Secrets" in rows[0]["description"]

    @pytest.mark.parametrize("guard", [
        "security.isAuthorized()",
        "security.denyAll()",
        "security.isAccounting()",
        "security.isDeluxe()",
        "security.isCustomer()",
        "authz.requireRole('admin')",
    ])
    def test_security_family_counts_as_authz(self, source_dir, guard):
        (source_dir / "routes.ts").write_text(f"app.get('/api/X', {guard})\n")
        assert _authz(_run(source_dir)) == []

    @pytest.mark.parametrize("guard", [
        "this.security.isAuthorized()",
        "self.authz.require_role('admin')",
        "req.security.isAuthorized()",
    ])
    def test_dotted_owner_receiver_counts_as_authz(self, source_dir, guard):
        """`this.security.isAuthorized()` guards the route just as well as the
        module-scope `security.isAuthorized()`; a receiver-anchored pattern that
        only accepts the bare form reports a genuinely protected route."""
        (source_dir / "routes.ts").write_text(f"app.get('/api/X', {guard})\n")
        assert _authz(_run(source_dir)) == []

    @pytest.mark.parametrize("noise", [
        "dataSecurity.isEmpty()",
        "insecurity.isPresent()",
    ])
    def test_receiver_suffix_is_not_a_guard(self, source_dir, noise):
        """The receiver must be the whole identifier, not its tail — otherwise
        any `*security.is*()` helper silently exonerates a route."""
        (source_dir / "routes.ts").write_text(f"app.get('/api/X', {noise})\n")
        assert len(_authz(_run(source_dir))) == 1

    def test_dotted_owner_non_authz_helper_still_reports(self, source_dir):
        (source_dir / "routes.ts").write_text(
            "app.post('/api/Feedbacks', this.security.appendUserId())\n"
        )
        assert len(_authz(_run(source_dir))) == 1

    def test_non_authz_security_helper_is_not_a_guard(self, source_dir):
        """`security.appendUserId()` decorates the request; it authorises
        nothing, so the route stays reported."""
        code = "app.post('/api/Feedbacks', security.appendUserId())\n"
        (source_dir / "routes.ts").write_text(code)
        assert len(_authz(_run(source_dir))) == 1

    def test_flask_decorator_stack_counts_as_authz(self, source_dir):
        code = (
            "@app.route('/admin')\n"
            "@login_required\n"
            "def admin():\n"
            "    return 'ok'\n"
        )
        (source_dir / "views.py").write_text(code)
        assert _authz(_run(source_dir)) == []

    def test_flask_route_without_decorator_reports(self, source_dir):
        code = (
            "@app.route('/admin')\n"
            "@login_required\n"
            "def admin():\n"
            "    return 'ok'\n"
            "\n"
            "\n"
            "\n"
            "@app.route('/wide-open')\n"
            "def wide_open():\n"
            "    return dump_db()\n"
        )
        (source_dir / "views.py").write_text(code)
        rows = _authz(_run(source_dir))
        assert len(rows) == 1
        assert rows[0]["line_start"] == 8


# ---------------------------------------------------------------------------
# (b) mount inheritance
# ---------------------------------------------------------------------------

class TestMountInheritance:

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_route_under_guarded_mount_is_silent(self, source_dir):
        code = (
            "app.use('/api/BasketItems', security.isAuthorized())\n"
            "app.get('/api/BasketItems/:id', showBasketItem())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        assert _authz(_run(source_dir)) == []

    def test_param_segment_matches_concrete_segment(self, source_dir):
        code = (
            "app.use('/rest/basket/:id', security.isAuthorized())\n"
            "app.get('/rest/basket/42/order', showOrder())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        assert _authz(_run(source_dir)) == []

    def test_deeper_mount_does_not_cover_shallower_sibling(self, source_dir):
        """`app.use('/api/Feedbacks/:id', ...)` never runs for
        `POST /api/Feedbacks` — that route must stay reported."""
        code = (
            "app.use('/api/Feedbacks/:id', security.isAuthorized())\n"
            "app.post('/api/Feedbacks', createFeedback())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        rows = _authz(_run(source_dir))
        assert len(rows) == 1
        assert "/api/Feedbacks" in rows[0]["description"]

    def test_unguarded_mount_confers_nothing(self, source_dir):
        code = (
            "app.use('/api/Products', bodyParser.json())\n"
            "app.get('/api/Products/:id', showProduct())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        assert len(_authz(_run(source_dir))) == 1

    def test_sibling_prefix_is_not_a_segment_prefix(self, source_dir):
        code = (
            "app.use('/api/User', security.isAuthorized())\n"
            "app.get('/api/UserSecrets', dumpSecrets())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        assert len(_authz(_run(source_dir))) == 1


# ---------------------------------------------------------------------------
# (c) per-file rollup
# ---------------------------------------------------------------------------

class TestRollup:

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_many_unprotected_routes_collapse_to_one_finding(self, source_dir):
        code = "".join(
            f"app.get('/api/Thing{i}', handler{i}())\n" for i in range(12)
        )
        (source_dir / "routes.ts").write_text(code)
        rows = _authz(_run(source_dir))
        assert len(rows) == 1
        assert rows[0]["is_rollup"] is True
        assert rows[0]["instance_count"] == 12
        assert "/api/Thing0" in rows[0]["description"]
        assert "/api/Thing11" in rows[0]["description"]
        assert rows[0]["line_start"] == 1
        assert rows[0]["line_end"] == 12

    def test_few_routes_stay_individual(self, source_dir):
        code = (
            "app.get('/api/A', a())\n"
            "app.get('/api/B', b())\n"
        )
        (source_dir / "routes.ts").write_text(code)
        rows = _authz(_run(source_dir))
        assert len(rows) == 2
        assert all(not r.get("is_rollup") for r in rows)

    def test_rollup_is_per_file(self, source_dir):
        for name in ("routes_a.ts", "routes_b.ts"):
            (source_dir / name).write_text(
                "".join(f"app.get('/x{i}', h{i}())\n" for i in range(9))
            )
        rows = _authz(_run(source_dir))
        assert len(rows) == 2
        assert {r["instance_count"] for r in rows} == {9}


# ---------------------------------------------------------------------------
# CWE-863 — JS/TS role string comparison
# ---------------------------------------------------------------------------

class TestRoleStringComparisonJS:

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    @pytest.mark.parametrize("line", [
        "if (user.role === 'admin') {",
        'if (req.user.role == "admin") {',
        "if (role.includes('admin')) {",
        "const ok = currentUser.role !== 'admin'",
        'if (data.role === "superuser") {',
        "if (token.roles.includes('administrator')) {",
    ])
    def test_js_role_idioms_detected(self, line):
        assert any(p.search(line) for p in ROLE_STRING_CMP), line

    @pytest.mark.parametrize("line", [
        "if (user.role === 'customer') {",
        "const roleName = 'admin'",
        "logger.info('admin panel opened')",
        "if (user.name === 'admin_tools') {",
    ])
    def test_non_privileged_or_unrelated_not_flagged(self, line):
        assert not any(p.search(line) for p in ROLE_STRING_CMP), line

    def test_python_form_still_detected(self):
        assert any(p.search("if role == 'admin':") for p in ROLE_STRING_CMP)

    def test_skill_emits_863(self, source_dir):
        code = "function ok(user) {\n  return user.role === 'admin'\n}\n"
        (source_dir / "authz.ts").write_text(code)
        rows = [f for f in _run(source_dir) if f["category"] == "CWE-863"]
        assert len(rows) == 1
        assert rows[0]["check_id"] == "cwe.access_control.role_string_cmp"
