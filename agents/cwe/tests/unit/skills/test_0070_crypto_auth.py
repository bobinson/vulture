"""Feature 0070 — crypto/auth precision (P2) and credential-lifecycle detectors (P3/P4).

Six changes, all measured on a real application tree:

1. CWE-326 — the weak-key patterns required a literal ``512|768|1024`` next to
   "RSA", so a key whose weakness lives in the PEM body was invisible.
   One measured app embedded a **1024-bit** RSA private key that signs every
   JWT, and it produced zero CWE-326 rows.

2. CWE-321 — ``HARDCODED_KEY_PATTERNS`` only knew ``encrypt|cipher|aes|secret``
   key names and never looked at a *positional* key argument, so
   ``crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')``
    and ``const privateKey = '-----BEGIN RSA ...'``
   were both missed.

3. CWE-521 — the weak-password-requirement patterns fired on *any*
   ``.length > 1-9`` comparison. 18 rows in one sweep, 15 of them array-length
   checks with nothing to do with passwords (``solves.length > 1``,
   ``match.length >= 1``, ``result.data.length > 1``). Password context is now
   required. ``'admin1'`` also used to satisfy ``password.*min.*[1-7]`` because
   "ad**min1**" contains "min" followed by a digit.

4. CWE-916/759 — a measured app stored md5 password hashes. That was reported only
   as CWE-328 "weak hash for integrity" at MEDIUM, which understates a password
   store. A password-context discriminator now adds CWE-916 (insufficient
   computational effort) and CWE-759 (no salt). CWE-328 is deliberately left
   in place: it is a policy CWE that must never be auto-suppressed.

5. CWE-620/640 — an authenticated password change whose current-password check
   is short-circuited by the value's own presence
   (``if (currentPassword && hash(currentPassword) !== stored)``, as seen in
   ``routes/changePassword.ts:39``) is an unverified password change; a reset
   flow gated only on a security answer (``routes/resetPassword.ts:41``) is a
   weak recovery mechanism.

6. CWE-287/347 — ``expressJwt({ secret: publicKey })`` and
   ``jws.verify(token, publicKey)`` verify tokens with the PUBLIC key and no
   algorithm allowlist (``expressJwt({ secret: publicKey })``): the
   canonical algorithm-confusion bypass, previously undetected.
"""

import base64
import tempfile
from pathlib import Path

from cwe_agent.skills.auth_check import check_authentication
from cwe_agent.skills.crypto_check import check_cryptography


def _run(check, files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check(str(root))["findings"]


def _of(findings: list[dict], *cwes: int) -> list[dict]:
    want = {f"CWE-{c}" for c in cwes}
    return [f for f in findings if f.get("category") in want]


# --------------------------------------------------------------------------
# PEM fixtures: a synthetic PKCS#1 RSAPrivateKey whose modulus has exactly
# `bits` bits. Small, deterministic, and no real key material.
# --------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _pkcs1_der(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1
    body = _der_int(0) + _der_int(modulus) + _der_int(65537)
    return b"\x30" + _der_len(len(body)) + body


def _pem_b64(bits: int) -> str:
    return base64.b64encode(_pkcs1_der(bits)).decode()


def _pem_one_line(bits: int) -> str:
    """The one-line shape: whole PEM in one JS string with \\r\\n escapes."""
    return (
        "const privateKey = '-----BEGIN RSA PRIVATE KEY-----\\r\\n"
        + _pem_b64(bits)
        + "\\r\\n-----END RSA PRIVATE KEY-----'"
    )


def _pem_multi_line(bits: int) -> str:
    b64 = _pem_b64(bits)
    chunks = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join(["-----BEGIN RSA PRIVATE KEY-----", *chunks,
                      "-----END RSA PRIVATE KEY-----"])


class TestWeakKeyFromPemBody:
    """(1) CWE-326 — modulus size read out of an inline PEM literal."""

    def test_inline_1024_bit_pem_is_flagged(self) -> None:
        hits = _of(_run(check_cryptography, {"security.ts": _pem_one_line(1024) + "\n"}), 326)
        assert hits, "a 1024-bit RSA key inlined as a PEM literal must be CWE-326"
        assert "1024" in hits[0]["description"], hits[0]["description"]

    def test_inline_2048_bit_pem_is_not_flagged(self) -> None:
        hits = _of(_run(check_cryptography, {"security.ts": _pem_one_line(2048) + "\n"}), 326)
        assert hits == [], "2048-bit keys are adequate and must not be flagged"

    def test_multi_line_pem_is_flagged_once(self) -> None:
        hits = _of(_run(check_cryptography, {"key.pem.ts": _pem_multi_line(1024) + "\n"}), 326)
        assert len(hits) == 1, f"expected exactly one row for one PEM, got {len(hits)}"

    def test_pgp_key_block_is_not_a_modulus(self) -> None:
        body = (
            "# Security policy\n"
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "mQINBFqZjM4BEADhy0h9EObNhpXCcVc6vJmM5FLbYFN5MJ6xLbcVFvR6zC1M2Kop\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        assert _of(_run(check_cryptography, {"SECURITY.md": body}), 326) == []

    def test_explicit_key_size_literal_still_works(self) -> None:
        body = "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        assert _of(_run(check_cryptography, {"gen.py": body}), 326), "regression: literal key_size"


class TestHardcodedKeyWidened:
    """(2) CWE-321 — widened key names + literal positional key arguments."""

    def test_create_hmac_literal_key(self) -> None:
        body = (
            "export const hmac = (data: string) => "
            "crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')"
            ".update(data).digest('hex')\n"
        )
        hits = _of(_run(check_cryptography, {"security.ts": body}), 321)
        assert hits, "a literal second argument to createHmac is a hardcoded key"

    def test_create_cipheriv_literal_key(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-cbc', 'k3y-material-32-bytes-long-abcd', iv)\n"
        assert _of(_run(check_cryptography, {"enc.js": body}), 321)

    def test_widened_key_names(self) -> None:
        for line in (
            "const signingKey = 'S1gn1ngK3yMaterial'",
            "jwt_key = 'jwtKeyMaterial12345'",
            "private_key = 'pr1v4t3K3yMaterial'",
            "hmacKey = 'hm4cK3yMaterial9876'",
            "masterKey = 'm4st3rK3yMaterial12'",
        ):
            assert _of(_run(check_cryptography, {"k.js": line + "\n"}), 321), line

    def test_session_and_cookie_keys_are_slot_names(self) -> None:
        """Measured: 57/57 `sessionKey`/`cookieKey` hits on a second corpus were
        routing identifiers, and both hits in one sweep were a cookie name. The
        two names are excluded rather than value-filtered, because the values
        (`"hook:gmail:{{id}}"`, `"agent:main:main"`) are indistinguishable from
        key material by shape."""
        for line in (
            "  private readonly welcomeBannerStatusCookieKey = 'welcomebanner_status'",
            '        sessionKey: "hook:gmail:{{messages[0].id}}",',
            '  export const MAIN_SESSION_KEY = "agent:main:main";',
        ):
            assert _of(_run(check_cryptography, {"k.ts": line + "\n"}), 321) == [], line

    def test_elided_documentation_value_is_not_a_key(self) -> None:
        for line in (
            'export NOSTR_PRIVATE_KEY="nsec1..."',
            "signing_key = 'xxxxxxxxxxxx'",
            'jwt_key = "<your-jwt-key-here>"',
        ):
            assert _of(_run(check_cryptography, {"README.md": line + "\n"}), 321) == [], line

    def test_inline_pem_literal_is_a_hardcoded_key(self) -> None:
        hits = _of(_run(check_cryptography, {"security.ts": _pem_one_line(1024) + "\n"}), 321)
        assert hits, "an inline PEM private key literal is a hardcoded key"

    def test_env_indirection_still_suppressed(self) -> None:
        for line in (
            "const signingKey = process.env.SIGNING_KEY",
            "private_key = os.environ['PRIVATE_KEY']",
            'signing_key = "${SIGNING_KEY}"',
        ):
            assert _of(_run(check_cryptography, {"k.js": line + "\n"}), 321) == [], line

    def test_hmac_algorithm_arg_alone_is_not_a_key(self) -> None:
        body = "const h = crypto.createHmac('sha256', keyFromVault).update(x).digest('hex')\n"
        assert _of(_run(check_cryptography, {"h.js": body}), 321) == []


# the 15 array-length false positives, verbatim.
_ARRAY_LENGTH_LINES = [
    "  return solves.length > 1 ? median(solves.map(({ cheatScore }) => cheatScore)) : 0",
    "  return match !== null && match.length >= 1",
    "    } else if (matchingProducts.length > 1) {",
    "    if (appliedSpecials.length > 1) {",
    "      @if (message.tool_calls.length > 1) {",
    "      @if ((reviews$| async)?.length >= 1) {",
    "  challengeUtils.solveIf(challenges.c, () => { return Array.isArray(data) && data.length > 1 })",
    "  challengeUtils.solveIf(challenges.n, () => { return result.data.length > 1 })",
]


class TestWeakPasswordRequirementsNarrowed:
    """(3) CWE-521 — password context required."""

    def test_array_length_checks_are_not_password_policy(self) -> None:
        for line in _ARRAY_LENGTH_LINES:
            hits = _of(_run(check_authentication, {"antiCheat.ts": line + "\n"}), 521)
            assert hits == [], f"array length check must not be CWE-521: {line!r}"

    def test_admin1_is_not_a_minimum_length(self) -> None:
        body = "      resolved: waitForInputToHaveValue('#password', 'admin1')\n"
        assert _of(_run(check_authentication, {"passwordStrength.ts": body}), 521) == [], (
            "'admin1' contains 'min1' but declares no minimum length"
        )

    def test_angular_password_min_length_still_flagged(self) -> None:
        for line in (
            "  public passwordControl = new UntypedFormControl('', "
            "[Validators.required, Validators.minLength(1)])",
            "  public passwordControl: UntypedFormControl = new UntypedFormControl('', "
            "[Validators.required, Validators.minLength(5), Validators.maxLength(40)])",
        ):
            hits = _of(_run(check_authentication, {"login.component.ts": line + "\n"}), 521)
            assert hits, f"a weak password minLength must stay CWE-521: {line!r}"

    def test_generic_min_length_needs_password_context(self) -> None:
        with_ctx = "password_policy = {\n    'min_length': 6,\n}\n"
        assert _of(_run(check_authentication, {"policy.py": with_ctx}), 521), (
            "min_length inside a password policy block must be flagged"
        )
        without = "pagination = {\n    'min_length': 6,\n}\n"
        assert _of(_run(check_authentication, {"policy.py": without}), 521) == []

    def test_explicit_password_length_checks_still_flagged(self) -> None:
        for line in (
            "if len(password) < 6:",
            "if (password.length < 6) {",
            "if len(password) >= 6:",
        ):
            assert _of(_run(check_authentication, {"v.py": line + "\n"}), 521), line


class TestPasswordHashLifecycle:
    """(4) CWE-916/759 — a password stored through a bare digest."""

    def test_md5_password_store_emits_916_and_759(self) -> None:
        body = (
            "export const UserModel = {\n"
            "  set (clearTextPassword) {\n"
            "    this.setDataValue('password', security.hash(clearTextPassword))\n"
            "  }\n"
            "}\n"
        )
        findings = _run(check_authentication, {"user.ts": body})
        assert _of(findings, 916), "a password stored through a bare digest is CWE-916"
        assert _of(findings, 759), "an unsalted password digest is CWE-759"
        assert _of(findings, 916)[0]["severity"] in ("high", "critical")

    def test_sql_password_comparison_against_digest(self) -> None:
        body = (
            "function login (req, res) {\n"
            "  models.sequelize.query(`SELECT * FROM Users WHERE email = "
            "'${req.body.email}' AND password = '${security.hash(req.body.password)}'`)\n"
            "}\n"
        )
        assert _of(_run(check_authentication, {"login.ts": body}), 916)

    def test_kdf_password_store_is_not_916(self) -> None:
        body = (
            "async function save (user, password) {\n"
            "  user.password = await bcrypt.hash(password, 12)\n"
            "}\n"
        )
        findings = _run(check_authentication, {"save.ts": body})
        assert _of(findings, 916, 759) == [], "bcrypt is a KDF, not a bare digest"

    def test_salted_digest_is_not_759(self) -> None:
        body = (
            "def store(password, salt):\n"
            "    user.password = pbkdf2_hmac('sha256', password, salt, 200000)\n"
        )
        assert _of(_run(check_authentication, {"store.py": body}), 759) == []

    def test_one_row_per_file_per_cwe(self) -> None:
        body = (
            "function a (req) { const password = security.hash(req.body.password) }\n"
            "function b (req) { user.password = security.hash(req.body.password) }\n"
            "function c (req) { row.password = security.hash(req.body.password) }\n"
        )
        assert len(_of(_run(check_authentication, {"login.ts": body}), 916)) == 1


class TestPasswordChangeAndRecovery:
    """(5) CWE-620 unverified password change / CWE-640 weak recovery."""

    def test_optional_current_password_check_is_620(self) -> None:
        body = (
            "export function changePassword () {\n"
            "  return async ({ query, headers }, res, next) => {\n"
            "    const currentPassword = query.current\n"
            "    const newPassword = query.new\n"
            "    if (currentPassword && security.hash(currentPassword) !== "
            "loggedInUser.data.password) {\n"
            "      res.status(401).send('Current password is not correct.')\n"
            "      return\n"
            "    }\n"
            "    await user.update({ password: newPassword })\n"
            "  }\n"
            "}\n"
        )
        hits = _of(_run(check_authentication, {"changePassword.ts": body}), 620)
        assert hits, "a current-password check gated on the value's presence is CWE-620"
        assert len(hits) == 1

    def test_missing_current_password_check_is_620(self) -> None:
        body = (
            "export function changePassword (req, res) {\n"
            "  const newPassword = req.body.new\n"
            "  await user.update({ password: newPassword })\n"
            "  res.json({ user })\n"
            "}\n"
        )
        assert _of(_run(check_authentication, {"changePassword.ts": body}), 620)

    def test_mandatory_current_password_check_is_clean(self) -> None:
        body = (
            "export function changePassword (req, res) {\n"
            "  const currentPassword = req.body.current\n"
            "  const newPassword = req.body.new\n"
            "  if (!verifyPassword(currentPassword, user.hash)) {\n"
            "    res.status(401).send('wrong')\n"
            "    return\n"
            "  }\n"
            "  await user.update({ password: newPassword })\n"
            "}\n"
        )
        assert _of(_run(check_authentication, {"changePassword.ts": body}), 620) == []

    def test_security_answer_reset_is_640(self) -> None:
        body = (
            "export function resetPassword () {\n"
            "  return async ({ body }, res, next) => {\n"
            "    const answer = body.answer\n"
            "    const newPassword = body.new\n"
            "    const data = await SecurityAnswerModel.findOne({ include: [] })\n"
            "    if ((data != null) && security.hmac(answer) === data.answer) {\n"
            "      const updatedUser = await user.update({ password: newPassword })\n"
            "      res.json({ user: updatedUser })\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        hits = _of(_run(check_authentication, {"resetPassword.ts": body}), 640)
        assert hits, "a security-answer-only reset flow is CWE-640"
        assert len(hits) == 1
        # A recovery flow is not also reported as an unverified change.
        assert _of(_run(check_authentication, {"resetPassword.ts": body}), 620) == []

    def test_token_based_reset_is_not_640(self) -> None:
        body = (
            "export function resetPassword (req, res) {\n"
            "  const newPassword = req.body.new\n"
            "  const record = await ResetToken.findOne({ where: { resetToken: req.body.token } })\n"
            "  if (!record || record.expiresAt < Date.now()) { res.status(401).end(); return }\n"
            "  await user.update({ password: newPassword })\n"
            "}\n"
        )
        assert _of(_run(check_authentication, {"resetPassword.ts": body}), 640) == []


class TestJwtVerificationConfusion:
    """(6) CWE-287/347 — verification with a public key and no allowlist."""

    def test_express_jwt_public_key_secret(self) -> None:
        body = "export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)\n"
        findings = _run(check_authentication, {"security.ts": body})
        assert _of(findings, 347), "JWT verification without an algorithms allowlist is CWE-347"
        assert _of(findings, 287), "verifying with a public key is CWE-287"

    def test_jws_verify_with_public_key(self) -> None:
        body = (
            "export const verify = (token: string) => token ? "
            "(jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) "
            ": false\n"
        )
        findings = _run(check_authentication, {"security.ts": body})
        assert _of(findings, 287), "jws.verify with publicKey must be CWE-287"

    def test_jwt_verify_namespaced_public_key(self) -> None:
        body = "    jwt.verify(token, security.publicKey, (err) => {\n"
        assert _of(_run(check_authentication, {"verify.ts": body}), 287)

    def test_algorithms_allowlist_clears_347(self) -> None:
        body = (
            "const mw = expressJwt({ secret: signingSecret, algorithms: ['RS256'] })\n"
        )
        assert _of(_run(check_authentication, {"mw.ts": body}), 347) == []

    def test_signing_is_not_verification(self) -> None:
        body = (
            "export const authorize = (user = {}) => "
            "jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })\n"
        )
        assert _of(_run(check_authentication, {"sign.ts": body}), 287, 347) == []

    def test_random_secret_deny_all_is_not_347(self) -> None:
        body = "export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)\n"
        assert _of(_run(check_authentication, {"security.ts": body}), 347) == []

    def test_one_row_per_file_per_cwe(self) -> None:
        body = (
            "export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)\n"
            "export const verify = (token) => jws.verify(token, publicKey)\n"
            "const other = () => jwt.verify(token, publicKey, cb)\n"
        )
        findings = _run(check_authentication, {"security.ts": body})
        assert len(_of(findings, 347)) == 1
        assert len(_of(findings, 287)) == 1
