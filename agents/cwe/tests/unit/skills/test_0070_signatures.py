"""Feature 0070 — signature-family precision + coverage (CWE-90, CWE-943).

Two items, both measured on a real application tree:

  1. **CWE-90 (LDAP injection) — narrow.** The interpolation branch of
     ``_LDAP_FILTER`` matched a bare ``(ident=...`` paren, so every JS arrow
     function (``prev => [...]``) and every ``===`` chain read as an LDAP
     filter: 4 rows in one measured sweep, 4 of them false (that tree has no LDAP at
     all). The filter literal must live *inside a string* to be an LDAP filter.
     Target 4 -> 0, with positive fixtures proving the branch is not simply
     dead.

  2. **CWE-943 (NoSQL injection) — extend.** Two gaps: mutating collection
     operations (``update``/``updateOne``/``deleteMany``/``findOneAndUpdate``…)
     were not sinks at all, and the JS-predicate operators (``$where`` /
     ``$function`` / ``mapReduce``) shared a sanitizer list with the
     selector-object branch — so a ``String(...)`` cast, which does NOT
     neutralise a ``$where`` JavaScript predicate, silently suppressed a real
     finding (``routes/trackOrder.ts``).

CWE-943 is **not mapped by any OWASP 2025 category** (asserted below against
``owasp_2025.json``), so the finding must say so rather than imply a category.

Deterministic — NO LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

from cwe_agent.skills.catalog_detector import check_catalog_generic
from cwe_agent.skills.signatures.detector import match_signatures
from cwe_agent.skills.signatures.registry import SIGNATURES

_OWASP_2025 = (
    Path(__file__).resolve().parents[4]
    / "shared"
    / "shared"
    / "owasp"
    / "editions"
    / "owasp_2025.json"
)


def _cats(lines, ext: str) -> list[str]:
    return [f["category"] for f in match_signatures(tuple(lines), ext)]


def _hits(lines, ext: str, category: str) -> list[dict]:
    return [f for f in match_signatures(tuple(lines), ext) if f["category"] == category]


# ── item 1: CWE-90 precision ──────────────────────────────────────────

class TestLdapFilterIsNotEveryParenthesis:
    """The four measured rows, verbatim. All four are false positives."""

    def test_arrow_function_with_default_object_arg_is_not_an_ldap_filter(self):
        # lib/insecurity.ts:54 — `(user = {}) =>` matched `(ident=` + `{`.
        lines = (
            "import jwt from 'jsonwebtoken'",
            "export const authorize = (user = {}) => jwt.sign(user, privateKey, "
            "{ expiresIn: '6h', algorithm: 'RS256' })",
        )
        assert "CWE-90" not in _cats(lines, ".ts")

    def test_arrow_function_body_brace_is_not_an_ldap_filter(self):
        # routes/payment.ts:22 and chat-conversation.component.ts:117.
        lines = (
            "const cards = await CardModel.findAll({ where: { UserId: user.id } })",
            "cards.forEach(card => {",
            "  this.messages.update(prev => [...prev, { role: 'user', content }])",
            "})",
        )
        assert "CWE-90" not in _cats(lines, ".ts")

    def test_strict_equality_chain_is_not_an_ldap_filter(self):
        # routes/fileUpload.ts:65 — a `===` chain read as `(attr=` + interpolation.
        lines = (
            "function isInvalid (fileType: string, user: string) {",
            "  return !(fileType === 'pdf' || fileType === 'xml' || "
            "fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')",
            "}",
        )
        assert "CWE-90" not in _cats(lines, ".ts")

    def test_dict_literal_with_equals_in_a_call_is_not_an_ldap_filter(self):
        lines = (
            "def handler(request):",
            "    return render(request, template, context={'user': request.user})",
        )
        assert "CWE-90" not in _cats(lines, ".py")


class TestGenuineLdapFiltersStillFire:
    """The narrowing must not kill the rule: a filter literal that really is a
    string, carrying an interpolation placeholder, still fires — including
    shapes with NO LDAP-specific receiver on the line, which only the
    interpolation branch can catch."""

    def test_python_fstring_filter_fires(self):
        lines = (
            "def lookup(conn, request):",
            "    name = request.args.get('name')",
            '    ldap_filter = f"(cn={name})"',
            "    return conn.search(BASE_DN, ldap_filter)",
        )
        assert _hits(lines, ".py", "CWE-90"), "f-string LDAP filter must fire"

    def test_js_template_literal_filter_fires(self):
        lines = (
            "function findUser (client, req) {",
            "  const opts = { filter: `(uid=${req.query.uid})`, scope: 'sub' };",
            "  return client.search('ou=people', opts);",
            "}",
        )
        assert _hits(lines, ".js", "CWE-90"), "template-literal LDAP filter must fire"

    def test_java_format_placeholder_filter_fires(self):
        lines = (
            "public Object find(HttpServletRequest request) {",
            '  String filter = String.format("(uid=%s)", request.getParameter("u"));',
            "  return doQuery(filter);",
            "}",
        )
        assert _hits(lines, ".java", "CWE-90"), "%s LDAP filter must fire"

    def test_python_percent_dict_filter_fires(self):
        lines = (
            "def lookup(conn, request):",
            "    user = request.args.get('u')",
            "    flt = '(uid=%(u)s)' % {'u': user}",
            "    return conn.search_s(BASE, flt)",
        )
        assert _hits(lines, ".py", "CWE-90")

    def test_concat_filter_regression_guard(self):
        # The pre-existing (a) branch — double AND single quoted concat.
        double = (
            "public void find(HttpServletRequest request) {",
            '  String user = request.getParameter("user");',
            '  String filter = "(uid=" + user + ")";',
            "}",
        )
        single = (
            "def find(conn, request):",
            "    user = request.args.get('u')",
            "    flt = '(uid=' + user + ')'",
            "    return conn.search_s(BASE, flt)",
        )
        assert _hits(double, ".java", "CWE-90")
        assert _hits(single, ".py", "CWE-90")

    def test_ldap_positive_fixture_detected_end_to_end(self, tmp_path):
        # Proves the rule is live through the real catalog entry point, not
        # just the matcher (the requirement: not simply dead).
        src = tmp_path / "app"
        src.mkdir()
        (src / "directory.py").write_text(
            "def lookup(conn, request):\n"
            "    name = request.args.get('name')\n"
            '    return conn.search_s("dc=example", f"(cn={name})")\n'
        )
        cats = {f["category"] for f in check_catalog_generic(str(src))["findings"]}
        assert "CWE-90" in cats

    def test_sanitized_ldap_filter_still_suppressed(self, tmp_path):
        lines = (
            "def lookup(conn, request):",
            "    name = escape_filter_chars(request.args.get('name'))",
            '    return conn.search_s("dc=example", f"(cn={name})")',
        )
        assert not _hits(lines, ".py", "CWE-90")


# ── item 2: CWE-943 coverage ──────────────────────────────────────────

class TestNoSqlMutatingCollectionOperations:
    """Gap 1: mutating collection operations were not sinks at all."""

    def test_collection_update_with_untrusted_selector_fires(self):
        # routes/updateProductReviews.ts — noSqlReviewsChallenge.
        lines = (
            "export function updateProductReviews () {",
            "  return (req: Request, res: Response) => {",
            "    db.reviewsCollection.update(",
            "      { _id: req.body.id },",
            "      { $set: { message: req.body.message } },",
            "      { multi: true }",
            "    ).then(",
        )
        assert _hits(lines, ".ts", "CWE-943"), (
            "a mutating collection op whose selector comes from req must fire"
        )

    def test_single_line_collection_update_fires(self):
        # routes/orderHistory.ts:36.
        lines = (
            "export function toggleDeliveryStatus () {",
            "  return async (req: Request, res: Response) => {",
            "    const deliveryStatus = !req.body.deliveryStatus",
            "    await ordersCollection.update({ _id: req.params.id }, "
            "{ $set: { delivered: deliveryStatus } })",
            "  }",
            "}",
        )
        assert _hits(lines, ".ts", "CWE-943")

    def test_pymongo_delete_many_fires(self):
        lines = (
            "def purge(db, request):",
            '    owner = request.args.get("owner")',
            "    return db.reviews.delete_many({'author': owner})",
        )
        assert _hits(lines, ".py", "CWE-943")

    def test_db_collection_call_receiver_fires(self):
        lines = (
            "app.post('/pw', (req, res) => {",
            "  db.collection('users').updateOne({ token: req.body.token }, "
            "{ $set: { pw: req.body.pw } });",
            "})",
        )
        assert _hits(lines, ".js", "CWE-943")

    def test_orm_model_and_crypto_update_do_not_fire(self):
        # Sequelize model instances / crypto streams / fs — NOT NoSQL sinks.
        for lines in (
            ("const user = await UserModel.findByPk(req.params.id)",
             "await user.update({ password: newPassword })"),
            ("await ChallengeModel.update({ codingChallengeStatus: 1 }, "
             "{ where: { key } })",
             "// req.body.key"),
            ("export const hash = (data: string) => "
             "crypto.createHash('md5').update(data).digest('hex')",
             "// data comes from req.body"),
            ("await fs.remove(filename)", "// filename from req.query.file"),
        ):
            assert not _hits(lines, ".ts", "CWE-943"), lines

    def test_cast_or_type_guard_suppresses_mutation(self):
        guarded = (
            "export function updateProductReviews () {",
            "  return (req: Request, res: Response) => {",
            "    if (typeof req.body.id !== 'string') { return res.status(400).send() }",
            "    db.reviewsCollection.update(",
            "      { _id: req.body.id },",
            "      { $set: { message: req.body.message } }",
            "    )",
        )
        assert not _hits(guarded, ".ts", "CWE-943")
        cast = (
            "app.post('/x', (req, res) => {",
            "  db.reviewsCollection.updateOne({ _id: ObjectId(req.body.id) }, "
            "{ $set: { m: 1 } });",
            "})",
        )
        assert not _hits(cast, ".ts", "CWE-943")

    def test_mutation_without_untrusted_source_does_not_fire(self):
        lines = (
            "async function seed () {",
            "  await ordersCollection.update({ _id: 1 }, { $set: { seeded: true } })",
            "}",
        )
        assert not _hits(lines, ".ts", "CWE-943")


class TestNoSqlWherePredicateSanitizerIsSpecific:
    """Gap 2: the ``$where`` JS-predicate shape shared the selector branch's
    sanitizer list. ``String(x)`` neutralises a *selector* (an object becomes
    ``"[object Object]"``) but NOT a ``$where`` JavaScript predicate."""

    def test_where_template_literal_with_string_cast_fires(self):
        # routes/trackOrder.ts:18 — noSqlOrdersChallenge. Real bug
        # that the shared `String(` sanitizer was hiding.
        lines = (
            "export function trackOrder () {",
            "  return (req: Request, res: Response) => {",
            "    const id = String(req.params.id).replace(/[^\\w-]+/g, '')",
            "    db.ordersCollection.find({ $where: `this.orderId === '${id}'` })",
            "  }",
            "}",
        )
        assert _hits(lines, ".ts", "CWE-943"), (
            "String() does not neutralise a $where JS predicate"
        )

    def test_where_concat_regression_guard(self):
        # routes/showProductReviews.ts:36 — already detected today.
        lines = (
            "  const id = req.params.id",
            "  db.reviewsCollection.find({ $where: 'this.product == ' + id })",
        )
        assert _hits(lines, ".ts", "CWE-943")

    def test_numeric_cast_still_suppresses_where(self):
        # routes/chat.ts:149 — Number() genuinely neutralises the
        # predicate, so this must stay suppressed (no over-correction).
        lines = (
            "execute: async ({ id }) => {",
            "  const productId = Number(id)",
            "  return await db.reviewsCollection.find("
            "{ $where: 'this.product == ' + productId }) as Review[]",
            "}",
        )
        assert not _hits(lines, ".ts", "CWE-943")

    def test_map_reduce_regression_guard(self):
        lines = (
            "function aggregate(req, collection) {",
            "  const groupBy = req.params.field",
            '  return collection.mapReduce("function(){ emit(this." + groupBy '
            '+ ", 1); }", reducer, {})',
            "}",
        )
        assert _hits(lines, ".js", "CWE-943")


class TestNoSqlFindingDoesNotImplyAnOwaspCategory:
    def test_cwe_943_is_unmapped_by_owasp_2025(self):
        edition = json.loads(_OWASP_2025.read_text())
        mapped = {
            int(cwe)
            for cat in edition["categories"]
            for cwe in cat.get("cwes", [])
        }
        assert 943 not in mapped, (
            "if a future edition maps CWE-943 the signature titles must drop "
            "the 'unmapped' note"
        )

    def test_nosql_signature_titles_state_the_owasp_gap(self):
        nosql = [s for s in SIGNATURES if s.cwe_id == "943"]
        assert len(nosql) >= 3, "expected the $where, selector and mutation rules"
        for sig in nosql:
            assert "OWASP 2025" in sig.title, (
                f"{sig.sig_id} must state that CWE-943 is unmapped by OWASP "
                f"2025 rather than implying a category (got {sig.title!r})"
            )

    def test_nosql_findings_carry_the_note_and_trusted_status(self):
        lines = (
            "  const id = req.params.id",
            "  db.reviewsCollection.find({ $where: 'this.product == ' + id })",
        )
        hits = _hits(lines, ".ts", "CWE-943")
        assert hits
        assert "OWASP 2025" in hits[0]["description"]
        # CWE-943 is corpus-VERIFIED, so its signatures ride as trusted.
        assert hits[0]["signature_status"] == "trusted"
