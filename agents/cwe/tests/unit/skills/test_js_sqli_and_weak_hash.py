"""JS/TS coverage for SQL injection (CWE-89) and weak hashes (CWE-327/328).

Both detectors were written against Python and Go and are blind to Node:

* Every SQL_INJECTION_PATTERN matched a Python f-string / .format() / %-format
  or a Go Sprintf. None matched a JS/TS template literal, so a scan of
  a real Node target whose flagship vulnerability is a template-literal SQL
  injection in the login route — produced zero CWE-89 findings, and
  `routes/search.ts` came back clean entirely.

* Every WEAK_HASH_PATTERN matched hashlib / MessageDigest / md5.New. None
  matched Node's `crypto.createHash('md5')`, which is how the measured app hashes
  passwords. CWE-327/328/916 were absent from the whole report, leaving
  OWASP A04 carried by a single unrelated CWE.

SAFE_HASH_CONTEXT additionally matched /hmac/i, which would have suppressed a
`createHmac('md5', ...)` finding as soon as one was detectable.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.crypto_check import check_cryptography
from cwe_agent.skills.injection_check import check_injection


def _run(check, files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check(str(root))["findings"]


def _of(findings, *cwes):
    want = {f"CWE-{c}" for c in cwes}
    return [f for f in findings if f.get("category") in want]


class TestTemplateLiteralSQLi:
    def test_login_shape_is_detected(self):
        # routes/login.ts:34 shape — the canonical template-literal auth bypass.
        body = (
            "import models from '../models/index'\n"
            "function login (req, res) {\n"
            "  models.sequelize.query(\n"
            "    `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND "
            "password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`\n"
            "  )\n"
            "}\n"
        )
        hits = _of(_run(check_injection, {"login.ts": body}), 89)
        assert hits, "template-literal SQL with an interpolated request value must be CWE-89"

    def test_search_shape_is_detected(self):
        # routes/search.ts:23 shape — returned zero findings of any category.
        body = (
            "function searchProducts (req, res) {\n"
            "  const criteria = req.query.q === 'undefined' ? '' : req.query.q\n"
            "  models.sequelize.query(\n"
            "    `SELECT * FROM Products WHERE name LIKE '%${criteria}%' OR "
            "description LIKE '%${criteria}%'`\n"
            "  )\n"
            "}\n"
        )
        hits = _of(_run(check_injection, {"search.ts": body}), 89)
        assert hits, "template-literal SQL in the search route must be CWE-89"

    def test_all_dml_verbs_and_js_extension(self):
        for verb in ("SELECT", "INSERT INTO", "UPDATE", "DELETE FROM"):
            body = f"db.query(`{verb} t WHERE id = ${{req.params.id}}`)\n"
            assert _of(_run(check_injection, {"r.js": body}), 89), f"{verb} not detected"

    def test_parameterised_query_is_not_flagged(self):
        body = (
            "db.query('SELECT * FROM Users WHERE email = ?', [req.body.email])\n"
            "models.sequelize.query('SELECT * FROM t WHERE id = :id', "
            "{ replacements: { id: req.params.id } })\n"
        )
        assert not _of(_run(check_injection, {"safe.ts": body}), 89), \
            "parameterised queries must not be flagged"

    def test_static_template_literal_is_not_flagged(self):
        # No interpolation => no injection.
        body = "db.query(`SELECT * FROM Products WHERE deletedAt IS NULL`)\n"
        assert not _of(_run(check_injection, {"static.ts": body}), 89), \
            "a template literal with no ${} must not be flagged"


class TestNodeWeakHash:
    def test_createhash_md5_is_detected(self):
        # a security helper's password hash.
        body = (
            "import crypto from 'crypto'\n"
            "export const hash = (data: string) => "
            "crypto.createHash('md5').update(data).digest('hex')\n"
        )
        hits = _of(_run(check_cryptography, {"security.ts": body}), 327, 328, 916)
        assert hits, "crypto.createHash('md5') must be reported as a weak hash"

    def test_createhash_sha1_is_detected(self):
        body = "const h = crypto.createHash(\"sha1\").update(x).digest('hex')\n"
        assert _of(_run(check_cryptography, {"a.js": body}), 327, 328, 916), \
            "createHash('sha1') must be reported"

    def test_createhmac_md5_is_detected_not_suppressed(self):
        # SAFE_HASH_CONTEXT matched /hmac/i and would swallow this.
        body = "const sig = crypto.createHmac('md5', key).update(body).digest('hex')\n"
        assert _of(_run(check_cryptography, {"sign.ts": body}), 327, 328, 916), \
            "createHmac with a weak digest must not be suppressed by HMAC context"

    def test_strong_hash_is_not_flagged(self):
        body = (
            "crypto.createHash('sha256').update(x).digest('hex')\n"
            "crypto.createHmac('sha512', k).update(x).digest('hex')\n"
        )
        assert not _of(_run(check_cryptography, {"ok.ts": body}), 327, 328, 916), \
            "sha256/sha512 must not be flagged as weak"
