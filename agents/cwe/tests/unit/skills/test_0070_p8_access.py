"""Feature 0070 P8 — access-control group: two new deterministic detectors.

Written before the detectors. Both are deliberate *specialisations* of rules
that already fire, so most of what is asserted here is about what must NOT
change:

* **CWE-566** (Authorization Bypass Through User-Controlled SQL Primary Key)
  is a strict SUBSET of the CWE-639 rows. It only ever fires on a line CWE-639
  already matched, and it REPLACES that row rather than joining it — 639 is
  566's catalog parent, so two rows on one line would be a generalisation
  stack. The discriminators measured on real trees:

  - the request value must be bound to the PRIMARY KEY (`id`, `pk`, `_id`).
    `UserId: req.body.UserId` is a *scoping* column, not a primary key, and a
    naive `\\w*id` match treats the two as the same thing.
  - a lookup that also carries an owner/tenant column IS authorised
    (`where: { id: req.params.id, UserId: req.body.UserId }`) and must stay
    silent. This shape was the single most common one in the review corpus.
  - an ORM lookup context must be present. `get_user(request.args["id"])` is
    an IDOR (CWE-639) but says nothing about a SQL primary key, and a
    client-side router read (`route.snapshot.params['id']`) reaches no
    database at all.
  - raw string-concatenated SQL is deliberately out of scope: those lines are
    already claimed by the SQL-injection rule in another skill, and a second
    sibling row on the same line is a duplicate.

* **CWE-425** (Direct Request / Forced Browsing) reuses the existing per-route
  authz analysis — including `app.use('<prefix>', <authz>)` mount inheritance
  — and adds one discriminator: the route path names an administrative or
  diagnostic area. 425 is a CHILD of 862 in the catalog, so the two rows share
  a line and the platform's line-stack collapse keeps only the specific one;
  that invariant is asserted here rather than assumed.

  `/console` is explicitly NOT in the vocabulary: measured on a real tree it
  matched a browser-devtools proxy route, and a generic word that names a UI
  as often as an admin panel cannot carry a high-severity finding.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from shared.tools.finding_collapse import collapse_line_stacks

from cwe_agent.skills.access_control_check import check_access_control

SKILL_SRC = (
    Path(__file__).resolve().parents[3]
    / "cwe_agent" / "skills" / "access_control_check.py"
).read_text()


def _run(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for name, body in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return check_access_control(str(tmp_path))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# ---------------------------------------------------------------------------
# Attestation literals
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe", ["566", "425"])
def test_category_literal_is_present_in_source(cwe: str) -> None:
    """The coverage extractor reads `"category": "CWE-N"` literals out of the
    skill source; a category assembled with an f-string is invisible to it."""
    assert re.search(rf'"category"\s*:\s*"CWE-{cwe}"', SKILL_SRC)


# ---------------------------------------------------------------------------
# CWE-566 — user-controlled SQL primary key
# ---------------------------------------------------------------------------

class TestSqlPrimaryKeyBypass:

    def test_sequelize_pk_lookup_from_request_param(self, tmp_path: Path) -> None:
        code = (
            "export function getDeliveryMethod () {\n"
            "  return async (req, res) => {\n"
            "    const method = await DeliveryModel.findOne("
            "{ where: { id: req.params.id } })\n"
            "    res.json(method)\n"
            "  }\n"
            "}\n"
        )
        rows = _of(_run(tmp_path, {"delivery.ts": code}), "CWE-566")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 3
        assert rows[0]["severity"] == "high"

    def test_django_objects_get_pk_from_request(self, tmp_path: Path) -> None:
        code = (
            "def detail(request):\n"
            "    invoice = Invoice.objects.get(pk=request.GET['id'])\n"
            "    return render(request, 'detail.html', {'invoice': invoice})\n"
        )
        rows = _of(_run(tmp_path, {"views.py": code}), "CWE-566")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 2

    def test_find_by_pk_call_with_request_argument(self, tmp_path: Path) -> None:
        code = (
            "async function load (req, res) {\n"
            "  const row = await CardModel.findByPk(req.params.cardId)\n"
            "  res.json(row)\n"
            "}\n"
        )
        assert len(_of(_run(tmp_path, {"card.ts": code}), "CWE-566")) == 1

    def test_alias_local_named_id_reaching_a_where_clause(self, tmp_path: Path) -> None:
        """The pk arrives through a one-hop local: `const id = req.params.id`
        then `where: { id }`. Anchored on the assignment, which is where the
        parent CWE-639 row is anchored too."""
        code = (
            "export function retrieveBasket () {\n"
            "  return async (req, res) => {\n"
            "    const id = req.params.id\n"
            "    const basket = await BasketModel.findOne({ where: { id } })\n"
            "    res.json(basket)\n"
            "  }\n"
            "}\n"
        )
        rows = _of(_run(tmp_path, {"basket.ts": code}), "CWE-566")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 3

    def test_replaces_the_parent_row_rather_than_stacking(
        self, tmp_path: Path
    ) -> None:
        """One line, one row. CWE-639 is 566's catalog parent."""
        code = (
            "async function h (req, res) {\n"
            "  const row = await Model.findOne({ where: { id: req.params.id } })\n"
            "}\n"
        )
        findings = _run(tmp_path, {"h.ts": code})
        on_line_2 = [f for f in findings if f["line_start"] == 2]
        assert [f["category"] for f in on_line_2] == ["CWE-566"]

    def test_owner_scoped_lookup_is_silent(self, tmp_path: Path) -> None:
        """A composite key that pins the row to its owner IS the authorization
        check. This is the shape that dominates a correctly-written codebase."""
        code = (
            "async function h (req, res) {\n"
            "  const a = await AddressModel.findOne("
            "{ where: { id: req.params.id, UserId: req.body.UserId } })\n"
            "}\n"
        )
        assert _of(_run(tmp_path, {"address.ts": code}), "CWE-566") == []

    def test_scoping_column_alone_is_not_a_primary_key(self, tmp_path: Path) -> None:
        code = (
            "async function h (req, res) {\n"
            "  const w = await WalletModel.findOne({ where: { UserId: req.body.UserId } })\n"
            "}\n"
        )
        assert _of(_run(tmp_path, {"wallet.ts": code}), "CWE-566") == []

    def test_no_orm_context_stays_cwe_639(self, tmp_path: Path) -> None:
        """A plain IDOR with no database lookup in sight keeps the general id."""
        code = "def get():\n    user = get_user(request.args[\"id\"])\n    return user\n"
        findings = _run(tmp_path, {"views.py": code})
        assert _of(findings, "CWE-566") == []
        assert len(_of(findings, "CWE-639")) == 1

    def test_client_side_router_param_is_silent(self, tmp_path: Path) -> None:
        """A front-end route read reaches no database."""
        code = (
            "export class C {\n"
            "  ngOnInit () {\n"
            "    this.conversationId = this.route.snapshot.params['id']\n"
            "  }\n"
            "}\n"
        )
        assert _of(_run(tmp_path, {"c.component.ts": code}), "CWE-566") == []

    def test_concatenated_sql_is_left_to_the_injection_rule(
        self, tmp_path: Path
    ) -> None:
        """Raw string SQL is another skill's line; a sibling row there would be
        a duplicate."""
        code = (
            "def h(request):\n"
            "    cur.execute(\"SELECT * FROM orders WHERE id = \" + "
            "request.GET['id'])\n"
        )
        assert _of(_run(tmp_path, {"dao.py": code}), "CWE-566") == []

    def test_file_wide_ownership_check_still_suppresses_everything(
        self, tmp_path: Path
    ) -> None:
        code = (
            "async function h (req, res) {\n"
            "  if (!is_owner(req)) return res.sendStatus(403)\n"
            "  const row = await Model.findOne({ where: { id: req.params.id } })\n"
            "}\n"
        )
        findings = _run(tmp_path, {"h.ts": code})
        assert _of(findings, "CWE-566") == []
        assert _of(findings, "CWE-639") == []


# ---------------------------------------------------------------------------
# CWE-425 — direct request / forced browsing
# ---------------------------------------------------------------------------

class TestForcedBrowsing:

    def test_unguarded_admin_route(self, tmp_path: Path) -> None:
        code = "app.get('/rest/admin/application-configuration', serveConfig())\n"
        rows = _of(_run(tmp_path, {"server.ts": code}), "CWE-425")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 1
        assert rows[0]["severity"] == "high"
        assert "/rest/admin/application-configuration" in rows[0]["description"]

    def test_unguarded_diagnostic_route(self, tmp_path: Path) -> None:
        code = "app.get('/metrics', serveMetrics())\n"
        assert len(_of(_run(tmp_path, {"server.ts": code}), "CWE-425")) == 1

    def test_flask_decorator_admin_route(self, tmp_path: Path) -> None:
        code = "@app.route('/admin')\ndef admin_panel():\n    return dump()\n"
        assert len(_of(_run(tmp_path, {"views.py": code}), "CWE-425")) == 1

    def test_inline_guard_silences_it(self, tmp_path: Path) -> None:
        code = "app.get('/rest/admin/config', security.isAuthorized(), serveConfig())\n"
        assert _of(_run(tmp_path, {"server.ts": code}), "CWE-425") == []

    def test_mount_inherited_guard_silences_it(self, tmp_path: Path) -> None:
        """Reuses the existing `app.use('<prefix>', <authz>)` analysis."""
        code = (
            "app.use('/rest/admin', security.isAuthorized())\n"
            "app.get('/rest/admin/config', serveConfig())\n"
        )
        assert _of(_run(tmp_path, {"server.ts": code}), "CWE-425") == []

    def test_ordinary_route_is_not_forced_browsing(self, tmp_path: Path) -> None:
        code = "app.get('/rest/products/search', searchProducts())\n"
        findings = _run(tmp_path, {"server.ts": code})
        assert _of(findings, "CWE-425") == []
        assert len(_of(findings, "CWE-862")) == 1

    def test_console_is_not_in_the_vocabulary(self, tmp_path: Path) -> None:
        """Measured false positive: a browser-devtools proxy route."""
        code = "app.get('/console', readConsoleMessages())\n"
        assert _of(_run(tmp_path, {"routes.ts": code}), "CWE-425") == []

    def test_substring_of_a_longer_word_does_not_match(self, tmp_path: Path) -> None:
        code = "app.get('/badminton/courts', listCourts())\n"
        assert _of(_run(tmp_path, {"server.ts": code}), "CWE-425") == []

    def test_collapses_with_its_parent_to_one_row(self, tmp_path: Path) -> None:
        """425 is ChildOf 862. Both are emitted on the route line; the
        platform's line-stack collapse must leave exactly the specific one."""
        code = "app.get('/admin/users', listUsers())\n"
        findings = _run(tmp_path, {"server.ts": code})
        assert {f["category"] for f in findings} == {"CWE-425", "CWE-862"}
        kept, collapsed = collapse_line_stacks(findings)
        assert collapsed == 1
        assert [f["category"] for f in kept] == ["CWE-425"]

    def test_prose_mentioning_an_admin_route_is_silent(self, tmp_path: Path) -> None:
        doc = (
            "# Hardening\n\nNever register an admin route with no guard:\n\n"
            "    @app.route('/admin')\n"
            "    def admin_panel():\n"
            "        return dump()\n"
        )
        assert _of(_run(tmp_path, {"HARDENING.md": doc}), "CWE-425") == []
