"""Feature 0070 P7 — crypto detection backlog (group `crypto`, synthesis §1.2).

Five reviewed items, all implemented in ``cwe_agent/skills/crypto_check.py``:

* **CWE-322** Key exchange without entity authentication — anonymous
  key-agreement suites in a cipher list, plus host-key verification disabled
  for SSH. Restricted to executable/config dialects: the measured baseline's
  only non-test hits outside real config were a markdown security advisory
  *condemning* the flags and a guard that string-matches them in order to
  reject them, i.e. 2 of 3 surviving rows were false.
* **CWE-780** RSA without OAEP — PKCS#1 v1.5 encryption padding. Lands with
  the mandatory CWE-327 amendment: ``RSA/ECB/PKCS1Padding`` is *one* row (780),
  not 780 + a spurious 327, and ``RSA/ECB/OAEP…`` is correct code and must be
  silent (ECB is meaningless for RSA, so the bare-ECB 327 path is wrong there).
* **CWE-338** Cryptographically weak PRNG — a *conditional* re-tag of the
  existing CWE-330 row when a line-local security token names the consumed
  value. Never both labels on one line, and never a third synonym on a line
  where ``weak_entropy_check`` already emits CWE-331 + CWE-332.
* **CWE-329** Predictable IV with CBC and **CWE-323** nonce/key-pair reuse with
  an AEAD/stream mode — both driven by a depth-aware *argument tokeniser* and a
  positional slot test. The ``[^,]+`` argument stand-in is a proven defect:
  ``createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv)`` matches it
  because the IV group slides onto the ``'hex'`` literal inside the key
  expression, and that is how most Node code materialises a key. Bare
  ``Buffer.alloc(n)`` / ``make([]byte, n)`` tokens hit 41 benign lines on the
  baseline, so they are admissible only as a positional test.

Every rule has at least one clean twin that differs minimally from its
positive, and the row-stacking invariants (P5: skill findings are not
deduplicated against each other) are asserted, not assumed.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.crypto_check import check_cryptography
from cwe_agent.skills.weak_entropy_check import check_weak_entropy


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


def _crypto(name: str, body: str) -> list[dict]:
    return _run(check_cryptography, {name: body})


# ── CWE-322 — key exchange without entity authentication ──────────────


class TestAnonymousKeyExchange:
    """Family (a): anonymous key-agreement suites in a cipher list."""

    def test_anon_suite_in_cipher_list(self) -> None:
        body = "ssl_ciphers 'ALL:aNULL:!MD5:!3DES';\n"
        assert _of(_crypto("tls.conf", body), 322), "aNULL is an anonymous suite"

    def test_adh_suite_in_cipher_list(self) -> None:
        body = 'SSLCipherSuite = "ADH-AES256-SHA:DH_anon-AES128-SHA"\n'
        assert _of(_crypto("proxy.conf", body), 322)

    def test_go_cipher_suite_constant(self) -> None:
        body = "\tCipherSuites: []uint16{tls.TLS_ECDH_anon_WITH_AES_128_CBC_SHA},\n"
        assert _of(_crypto("tlsconf.go", body), 322)

    def test_excluded_anon_suite_is_a_hardening_measure(self) -> None:
        """The clean twin differs by one character class: `!aNULL` EXCLUDES the
        anonymous suites, which is exactly the recommended configuration."""
        body = "ssl_ciphers 'HIGH:!aNULL:!ADH:!MD5';\n"
        assert _of(_crypto("tls.conf", body), 322) == []

    def test_cipher_list_context_is_required(self) -> None:
        body = "const ADH = readAdherenceReport();\n"
        assert _of(_crypto("report.ts", body), 322) == []


class TestSshHostKeyVerificationDisabled:
    """Family (b): the SSH arm, and the guards the reviewer made mandatory."""

    def test_shell_ssh_options(self) -> None:
        body = "ssh -o StrictHostKeyChecking=no -i key deploy@$HOST 'true'\n"
        assert _of(_crypto("deploy.sh", body), 322)

    def test_known_hosts_dev_null(self) -> None:
        body = "scp -o UserKnownHostsFile=/dev/null artifact.tgz $HOST:/tmp/\n"
        assert _of(_crypto("upload.sh", body), 322)

    def test_go_insecure_ignore_host_key(self) -> None:
        body = "\tcfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()\n"
        assert _of(_crypto("client.go", body), 322)

    def test_accept_new_is_not_a_finding(self) -> None:
        body = "ssh -o StrictHostKeyChecking=accept-new -i key deploy@$HOST 'true'\n"
        assert _of(_crypto("deploy.sh", body), 322) == []

    def test_prose_naming_the_option_is_not_setting_it(self) -> None:
        """Measured: 2 of 3 surviving baseline rows were a markdown advisory
        that names both flags in order to condemn them. COMMENT_INDICATORS
        cannot help — markdown body text carries no comment marker."""
        body = (
            "# Hardening\n"
            "\n"
            "Never pass `StrictHostKeyChecking=no` or "
            "`UserKnownHostsFile=/dev/null` to ssh in CI.\n"
        )
        assert _of(_crypto("SECURITY.md", body), 322) == []

    def test_matcher_context_is_a_guard_not_a_finding(self) -> None:
        body = (
            "func audit(cmd string) bool {\n"
            '\treturn strings.Contains(cmd, "StrictHostKeyChecking=no")\n'
            "}\n"
        )
        assert _of(_crypto("guard.go", body), 322) == []

    def test_adjacent_known_hosts_callback_suppresses(self) -> None:
        body = (
            "\tif insecure {\n"
            "\t\tcb = ssh.InsecureIgnoreHostKey()\n"
            "\t} else {\n"
            "\t\tcb, err = knownhosts.New(hostsFile)\n"
            "\t}\n"
        )
        assert _of(_crypto("dial.go", body), 322) == []


# ── CWE-780 — RSA without OAEP ────────────────────────────────────────


class TestRsaWithoutOaep:
    def test_jce_pkcs1_transformation(self) -> None:
        body = 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n'
        assert _of(_crypto("Enc.java", body), 780)

    def test_jce_pkcs1_transformation_is_exactly_one_row(self) -> None:
        """P5 row stacking: ECB is not a mode choice for RSA, so the bare-name
        CWE-327 path must not stack a second row on this line."""
        rows = _of(_crypto("Enc.java", 'Cipher.getInstance("RSA/ECB/PKCS1Padding");\n'), 327, 780)
        assert [r["category"] for r in rows] == ["CWE-780"], rows

    def test_jce_oaep_transformation_is_silent(self) -> None:
        body = 'Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\n'
        assert _of(_crypto("Enc.java", body), 327, 780) == []

    def test_bare_ecb_for_a_symmetric_cipher_still_reports_327(self) -> None:
        body = 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        assert _of(_crypto("Sym.java", body), 327), "regression: symmetric ECB is CWE-327"

    def test_pycryptodome_cipher_pkcs1_v1_5(self) -> None:
        body = (
            "from Crypto.Cipher import PKCS1_v1_5\n"
            "\n"
            "def seal(pub, msg):\n"
            "    return PKCS1_v1_5.new(pub).encrypt(msg)\n"
        )
        assert _of(_crypto("seal.py", body), 780)

    def test_signature_pkcs1_v1_5_is_not_an_encryption_padding(self) -> None:
        """The clean twin imports the SIGNATURE module of the same name — RSA
        PKCS#1 v1.5 *signatures* are not CWE-780."""
        body = (
            "from Crypto.Signature import PKCS1_v1_5\n"
            "\n"
            "def sign(priv, h):\n"
            "    return PKCS1_v1_5.new(priv).sign(h)\n"
        )
        assert _of(_crypto("sign.py", body), 780) == []

    def test_cryptography_pkcs1v15_encrypt(self) -> None:
        body = "ct = public_key.encrypt(msg, padding.PKCS1v15())\n"
        assert _of(_crypto("seal.py", body), 780)

    def test_cryptography_oaep_encrypt(self) -> None:
        body = "ct = public_key.encrypt(msg, padding.OAEP(mgf=mgf, algorithm=sha, label=None))\n"
        assert _of(_crypto("seal.py", body), 780) == []

    def test_node_rsa_pkcs1_padding_constant(self) -> None:
        body = (
            "const ct = crypto.publicEncrypt("
            "{ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, buf);\n"
        )
        assert _of(_crypto("seal.js", body), 780)

    def test_node_rsa_oaep_padding_constant(self) -> None:
        body = (
            "const ct = crypto.publicEncrypt("
            "{ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf);\n"
        )
        assert _of(_crypto("seal.js", body), 780) == []

    def test_dotnet_foaep_false_with_rsa_receiver(self) -> None:
        body = "var ct = rsaProvider.Encrypt(data, false);\n"
        assert _of(_crypto("Seal.cs", body), 780)

    def test_dotnet_encryption_padding_pkcs1(self) -> None:
        body = "var ct = key.Encrypt(data, RSAEncryptionPadding.Pkcs1);\n"
        assert _of(_crypto("Seal.cs", body), 780)

    def test_dotnet_encryption_padding_oaep(self) -> None:
        body = "var ct = key.Encrypt(data, RSAEncryptionPadding.OaepSHA256);\n"
        assert _of(_crypto("Seal.cs", body), 780) == []

    def test_generic_two_arg_encrypt_helper_is_not_rsa(self) -> None:
        """The reviewer's break of arm (f): a bare `.Encrypt(x, false)` carries
        no RSA anchor and matches any two-argument encrypt helper."""
        body = "var ct = vault.Encrypt(payload, false);\n"
        assert _of(_crypto("Vault.cs", body), 780) == []

    def test_generic_two_arg_encrypt_fires_when_file_names_rsa(self) -> None:
        body = (
            "using System.Security.Cryptography;\n"
            "\n"
            "var ct = cipher.Encrypt(payload, false);\n"
        )
        assert _of(_crypto("Vault.cs", body), 780)


# ── CWE-338 — cryptographically weak PRNG for a security value ────────


class TestWeakPrngForSecurityValue:
    def test_one_time_code_from_math_random(self) -> None:
        body = "const otp = Math.random().toString().slice(2, 8);\n"
        assert _of(_crypto("otp.js", body), 338)

    def test_verification_code_from_randint(self) -> None:
        body = "verification_code = random.randint(100000, 999999)\n"
        assert _of(_crypto("reset.py", body), 338)

    def test_csrf_value_from_math_random(self) -> None:
        body = "res.locals.csrfValue = String(Math.random());\n"
        assert _of(_crypto("csrf.js", body), 338)

    def test_relabel_never_stacks_330_and_338(self) -> None:
        rows = _of(_crypto("otp.js", "const otp = Math.random().toString(36);\n"), 330, 338)
        assert [r["category"] for r in rows] == ["CWE-338"], rows

    def test_jitter_is_not_a_security_value(self) -> None:
        body = "const wait = base * policy.jitter * Math.random();\n"
        assert _of(_crypto("backoff.js", body), 338) == []

    def test_author_picker_is_not_an_auth_token(self) -> None:
        """`auth\\w*` was dropped from the token set: it matches `authors`."""
        body = "const author = authors[Math.floor(Math.random() * authors.length)];\n"
        assert _of(_crypto("pick.js", body), 338) == []

    def test_display_uuid_is_not_a_security_value(self) -> None:
        body = "const uuid = 'id-' + Math.random().toString(36).slice(2);\n"
        assert _of(_crypto("id.js", body), 338) == []

    def test_no_third_synonym_where_331_and_332_already_fire(self) -> None:
        """Cross-skill exclusivity: `token = random.random()` already carries
        CWE-331 + CWE-332 from weak_entropy_check, so the generic CWE-330 row
        stays as-is rather than becoming a third synonymous label."""
        files = {"tok.py": "token = random.random()\n"}
        entropy = _of(_run(check_weak_entropy, files), 331, 332)
        crypto = _of(_run(check_cryptography, files), 330, 338)
        assert {r["category"] for r in entropy} == {"CWE-331", "CWE-332"}
        assert [r["category"] for r in crypto] == ["CWE-330"], crypto


# ── CWE-329 / CWE-323 — IV and nonce slots ────────────────────────────


class TestPredictableIvWithCbc:
    def test_zero_filled_iv_node(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));\n"
        assert _of(_crypto("enc.js", body), 329)

    def test_literal_iv_node(self) -> None:
        body = "const c = crypto.createCipheriv('aes-128-cbc', key, '1234567890123456');\n"
        assert _of(_crypto("enc.js", body), 329)

    def test_iv_equal_to_key_node(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-cbc', keyBuf, keyBuf);\n"
        assert _of(_crypto("enc.js", body), 329)

    def test_hex_key_buffer_is_not_a_static_iv(self) -> None:
        """The measured `[^,]+` false positive, verbatim: the IV group slides
        onto the `'hex'` literal inside the key expression."""
        body = "const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);\n"
        assert _of(_crypto("enc.js", body), 329, 323) == []

    def test_derived_key_with_salt_literal_is_not_a_static_iv(self) -> None:
        body = "const d = crypto.createDecipheriv('aes-128-cbc', deriveKey(pw, 'salty'), iv);\n"
        assert _of(_crypto("dec.js", body), 329, 323) == []

    def test_literal_iv_python_keyword_slot(self) -> None:
        body = 'cipher = AES.new(key, AES.MODE_CBC, iv="0123456789abcdef")\n'
        assert _of(_crypto("enc.py", body), 329)

    def test_python_keyword_iv_is_exactly_one_row(self) -> None:
        """P5: crypto_check's CWE-321 `(?:iv|nonce)\\s*[:=]` arm owns literal-IV
        lines today. The specialisation replaces it; it must not stack."""
        body = 'cipher = AES.new(key, AES.MODE_CBC, iv="0123456789abcdef")\n'
        rows = _of(_crypto("enc.py", body), 321, 323, 329)
        assert [r["category"] for r in rows] == ["CWE-329"], rows

    def test_csprng_iv_python(self) -> None:
        body = "cipher = AES.new(key, AES.MODE_CBC, get_random_bytes(16))\n"
        assert _of(_crypto("enc.py", body), 329) == []

    def test_go_cbc_encrypter_zero_iv(self) -> None:
        body = "\tmode := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))\n"
        assert _of(_crypto("enc.go", body), 329)

    def test_go_cbc_encrypter_with_random_iv(self) -> None:
        body = "\tmode := cipher.NewCBCEncrypter(block, iv)\n"
        assert _of(_crypto("enc.go", body), 329) == []

    def test_bare_allocation_is_not_an_iv(self) -> None:
        """`Buffer.alloc(n)` / `make([]byte, n)` as bare tokens matched 41
        benign baseline lines; they are only admissible positionally."""
        for name, line in (
            ("io.go", "\tbuf := make([]byte, 4096)"),
            ("wav.js", "const header = Buffer.alloc(44);"),
            ("empty.js", "const nothing = Buffer.alloc(0);"),
        ):
            assert _of(_crypto(name, line + "\n"), 329, 323) == [], line

    def test_java_iv_parameter_spec_needs_a_cbc_transformation(self) -> None:
        vulnerable = (
            'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
            "c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(new byte[16]));\n"
        )
        assert _of(_crypto("Enc.java", vulnerable), 329)
        clean = "c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(randomIv));\n"
        assert _of(_crypto("Enc.java", clean), 329) == []


class TestNonceReuseWithAead:
    def test_zero_filled_nonce_node_gcm(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-gcm', key, Buffer.alloc(12));\n"
        assert _of(_crypto("enc.js", body), 323)

    def test_literal_nonce_python_gcm(self) -> None:
        body = 'cipher = AES.new(key, AES.MODE_GCM, nonce=b"fixednonce12")\n'
        assert _of(_crypto("enc.py", body), 323)

    def test_go_aead_seal_zero_nonce(self) -> None:
        body = "\tct := aesgcm.Seal(nil, make([]byte, 12), plaintext, nil)\n"
        assert _of(_crypto("enc.go", body), 323)

    def test_go_aead_seal_with_random_nonce(self) -> None:
        body = "\tct := aesgcm.Seal(nil, nonce, plaintext, nil)\n"
        assert _of(_crypto("enc.go", body), 323) == []

    def test_random_nonce_node_gcm(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));\n"
        assert _of(_crypto("enc.js", body), 323) == []

    def test_integer_nonce_clause_is_dropped(self) -> None:
        """`nonce = 0` matched 3 baseline lines (two Ethereum transaction
        nonces, one bundle) and has no AEAD recall — AEAD nonces are buffers."""
        body = "const tx = { to, value, nonce: 0 };\n"
        assert _of(_crypto("tx.js", body), 323) == []

    def test_mode_partition_is_mutually_exclusive(self) -> None:
        gcm = _of(_crypto("a.js", "createCipheriv('aes-256-gcm', k, Buffer.alloc(12));\n"), 323, 329)
        cbc = _of(_crypto("b.js", "createCipheriv('aes-256-cbc', k, Buffer.alloc(16));\n"), 323, 329)
        assert [r["category"] for r in gcm] == ["CWE-323"], gcm
        assert [r["category"] for r in cbc] == ["CWE-329"], cbc

    def test_variable_algorithm_argument_does_not_fire(self) -> None:
        """The mode gate reads the constructor's OWN algorithm argument; a
        variable there is not evidence of an AEAD or CBC mode."""
        body = "const c = crypto.createCipheriv(algorithm, key, Buffer.alloc(16));\n"
        assert _of(_crypto("enc.js", body), 323, 329) == []


class TestProseGuard:
    def test_documentation_is_not_scanned_for_code_patterns(self) -> None:
        body = (
            "# Encryption notes\n"
            "\n"
            "The legacy exporter called "
            "`crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16))`.\n"
        )
        assert _crypto("NOTES.md", body) == []
