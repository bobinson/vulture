"""Feature 0070 P7 — `plaintext_transmission_check` detection backlog (§1.3).

Items implemented here (reviewer verdicts are authoritative — every one is
`REVISE`, so these tests pin the REVISED predicate, not the proposed one):

  15  CWE-295  Improper Certificate Validation      (relabel of the
               `disabled_tls_verification` arm off CWE-319 + the wholesale
               verification-off arms routed here from the CWE-296 candidate)
  16  CWE-297  Certificate Host Mismatch
  17  CWE-298  Certificate Expiration not checked
  18  CWE-523  Unprotected Transport of Credentials (relabel of the
               userinfo-URL arm off CWE-319 + two new conjunctions)
  19  CWE-299  Certificate Revocation not checked
  67  CWE-296  Certificate Chain of Trust (P3: must land WITH item 15 so the
               `SSL_VERIFY_NONE` token MOVES rather than being duplicated)

Every rule carries a positive and a minimally-different clean twin. The
`one row per line` invariant (§6 P5 — skill findings are NOT deduplicated
against each other) is asserted explicitly for the lines where a child and its
parent both match.
"""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.plaintext_transmission_check import (
    check_plaintext_transmission,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _scan(tmp_path: Path, name: str, body: str) -> list[dict]:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return check_plaintext_transmission(str(tmp_path))["findings"]


def _cats(findings: list[dict]) -> list[str]:
    return [f["category"] for f in findings]


def _ids(findings: list[dict]) -> list[str]:
    return [f["check_id"] for f in findings]


# ---------------------------------------------------------------------------
# Item 15 — CWE-295 Improper Certificate Validation
# ---------------------------------------------------------------------------

class TestCwe295ImproperCertificateValidation:
    def test_requests_verify_false_is_295_not_319(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "client.py",
                  'r = requests.get("https://api.example.com", verify=False)\n')
        assert _cats(f) == ["CWE-295"]
        assert any("disabled_tls_verification" in i for i in _ids(f))

    def test_verify_true_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "client.py",
                     'r = requests.get("https://api.example.com", verify=True)\n') == []

    def test_verify_false_needs_a_tls_client_token(self, tmp_path: Path) -> None:
        """A bare `verify=False` kwarg with no TLS client on the line is not
        evidence of a disabled certificate check (form validators, schema
        options)."""
        assert _scan(tmp_path, "form.py", 'opts = dict(verify=False)\n') == []

    def test_reject_unauthorized_equals_form(self, tmp_path: Path) -> None:
        """Arm (c) widened from `:` to `[:=]` — the real occurrence is an
        assignment (`wsOptions.rejectUnauthorized = false`)."""
        f = _scan(tmp_path, "wsclient.ts", "wsOptions.rejectUnauthorized = false;\n")
        assert _cats(f) == ["CWE-295"]

    def test_reject_unauthorized_true_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "wsclient.ts",
                     "wsOptions.rejectUnauthorized = true;\n") == []

    def test_go_insecure_skip_verify(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "transport.go",
                  "cfg := &tls.Config{InsecureSkipVerify: true}\n")
        assert _cats(f) == ["CWE-295"]

    def test_go_insecure_skip_verify_false_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "transport.go",
                     "cfg := &tls.Config{InsecureSkipVerify: false}\n") == []

    def test_python_cert_none_is_295(self, tmp_path: Path) -> None:
        """Routed off the CWE-296 candidate (P3): CERT_NONE disables
        verification wholesale, which is 295, not a chain-of-trust defect."""
        f = _scan(tmp_path, "ctx.py", "ctx.verify_mode = ssl.CERT_NONE\n")
        assert _cats(f) == ["CWE-295"]

    def test_python_cert_required_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "ctx.py",
                     "ctx.verify_mode = ssl.CERT_REQUIRED\n") == []

    def test_unverified_context_is_295(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "ctx.py", "ctx = ssl._create_unverified_context()\n")
        assert _cats(f) == ["CWE-295"]

    def test_default_context_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "ctx.py",
                     "ctx = ssl.create_default_context()\n") == []

    def test_csharp_validation_callback_true_is_295(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Http.cs",
                  "ServicePointManager.ServerCertificateValidationCallback "
                  "= (s, c, ch, e) => true;\n")
        assert _cats(f) == ["CWE-295"]

    def test_csharp_validation_callback_delegating_clean_twin(
        self, tmp_path: Path
    ) -> None:
        assert _scan(tmp_path, "Http.cs",
                     "ServicePointManager.ServerCertificateValidationCallback "
                     "= (s, c, ch, e) => e == SslPolicyErrors.None;\n") == []

    def test_ssl_verify_none_moved_to_295(self, tmp_path: Path) -> None:
        """P3: the token MOVES out of `_INSECURE_TRANSPORT` (it reported
        CWE-319) instead of being registered in a second place, and it is
        receiver-anchored on the `SSL_CTX_set_verify` call."""
        f = _scan(tmp_path, "tls.c",
                  "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);\n")
        assert _cats(f) == ["CWE-295"]

    def test_ssl_verify_peer_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "tls.c",
                     "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);\n") == []

    def test_bare_ssl_verify_none_mention_does_not_fire(self, tmp_path: Path) -> None:
        """The bare token used to emit CWE-319; unanchored it also matches a
        constant table or a mode enumeration."""
        assert _scan(tmp_path, "modes.c",
                     "static const int kModes[] = { SSL_VERIFY_NONE };\n") == []

    def test_curl_verifypeer_zero(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "client.php",
                  "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);\n")
        assert _cats(f) == ["CWE-295"]

    def test_curl_verifypeer_one_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "client.php",
                     "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);\n") == []


class TestPinningSuppression:
    """MANDATORY (both real occurrences in the reviewed baseline disable CA
    validation *in order to* pin a fingerprint — flagging them is false)."""

    def test_fingerprint_pinning_within_window_suppresses(
        self, tmp_path: Path
    ) -> None:
        body = (
            "const wsOptions = buildOptions();\n"
            "wsOptions.rejectUnauthorized = false;\n"
            "wsOptions.checkServerIdentity = (host, cert) => {\n"
            "  if (cert.fingerprint256 !== expected) throw new Error('pin');\n"
            "};\n"
        )
        assert _scan(tmp_path, "wsclient.ts", body) == []

    def test_pinning_token_beyond_window_still_fires(self, tmp_path: Path) -> None:
        body = (
            "wsOptions.rejectUnauthorized = false;\n"
            + "// unrelated\n" * 8
            + "const expected = cert.fingerprint256;\n"
        )
        assert _cats(_scan(tmp_path, "wsclient.ts", body)) == ["CWE-295"]

    def test_suppresslint_marker_suppresses(self, tmp_path: Path) -> None:
        body = (
            '@SuppressLint("TrustAllX509TrustManager")\n'
            "fun unsafeCtx(): SSLContext {\n"
            "    ctx.verify_mode = ssl.CERT_NONE\n"
            "}\n"
        )
        assert _scan(tmp_path, "TlsFactory.kt", body) == []

    def test_nosec_marker_suppresses(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "client.py",
                     'requests.get(u, verify=False)  # nosec B501\n') == []


class TestCwe347Retained:
    """Item 15 regression guard: requiring a TLS-client token on the
    `verify=False` arm would take `jwt.decode(..., verify=False)` from two rows
    to zero, silencing a genuine CWE-347 defect."""

    def test_jwt_decode_verify_false_is_347(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "auth.py",
                  'claims = jwt.decode(token, None, verify=False)\n')
        assert _cats(f) == ["CWE-347"]

    def test_jwt_decode_verified_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "auth.py",
                     'claims = jwt.decode(token, key, algorithms=["RS256"])\n') == []


# ---------------------------------------------------------------------------
# Item 16 — CWE-297 Certificate Host Mismatch
# ---------------------------------------------------------------------------

class TestCwe297HostMismatch:
    def test_check_hostname_false(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "ctx.py", "ctx.check_hostname = False\n")
        assert _cats(f) == ["CWE-297"]

    def test_check_hostname_true_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "ctx.py", "ctx.check_hostname = True\n") == []

    def test_noop_hostname_verifier(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Client.java",
                  "builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);\n")
        assert _cats(f) == ["CWE-297"]

    def test_default_hostname_verifier_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(
            tmp_path, "Client.java",
            "builder.setSSLHostnameVerifier(new DefaultHostnameVerifier());\n"
        ) == []

    def test_empty_check_server_identity(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "agent.js",
                  "const opts = { checkServerIdentity: () => {} };\n")
        assert _cats(f) == ["CWE-297"]

    def test_nonempty_check_server_identity_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(
            tmp_path, "agent.js",
            "const opts = { checkServerIdentity: (h, c) => verifyPin(h, c) };\n"
        ) == []

    def test_verifyhost_zero(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "client.php",
                  "curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);\n")
        assert _cats(f) == ["CWE-297"]

    def test_verifyhost_one_is_not_flagged(self, tmp_path: Path) -> None:
        """Since libcurl 7.28.1 the value 1 is treated as 2 (full
        verification) — flagging it reports a secure configuration."""
        assert _scan(tmp_path, "client.php",
                     "curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);\n") == []

    def test_verifyhost_two_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "client.php",
                     "curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);\n") == []

    def test_297_wins_over_295_on_one_line(self, tmp_path: Path) -> None:
        """Row-stacking invariant (§6 P5): one row per line, and the more
        precise host-mismatch id wins."""
        f = _scan(tmp_path, "ctx.py",
                  "ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE\n")
        assert _cats(f) == ["CWE-297"]

    def test_pinning_suppression_applies_to_297(self, tmp_path: Path) -> None:
        body = (
            "// When pinning we intentionally ignore hostname mismatch\n"
            "val expected = pinnedFingerprint\n"
            "ctx.check_hostname = False\n"
        )
        assert _scan(tmp_path, "TlsFactory.kt", body) == []


# ---------------------------------------------------------------------------
# Item 17 — CWE-298 Certificate Expiration
# ---------------------------------------------------------------------------

class TestCwe298Expiration:
    def test_openssl_no_check_time(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "verify.c",
                  "X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_NO_CHECK_TIME);\n")
        assert _cats(f) == ["CWE-298"]

    def test_openssl_crl_check_clean_twin_for_298(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "verify.c",
                  "X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_X509_STRICT);\n")
        assert f == []

    def test_dotnet_ignore_not_time_valid(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Chain.cs",
                  "chain.ChainPolicy.VerificationFlags = "
                  "X509VerificationFlags.IgnoreNotTimeValid;\n")
        assert _cats(f) == ["CWE-298"]

    def test_dotnet_no_flag_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Chain.cs",
                     "chain.ChainPolicy.VerificationFlags = "
                     "X509VerificationFlags.NoFlag;\n") == []

    def test_all_flags_arm_deleted(self, tmp_path: Path) -> None:
        """`AllFlags` is not expiry-specific (it disables every check, which is
        CWE-295 territory) and matches flag-table declarations."""
        assert _scan(tmp_path, "Chain.cs",
                     "chain.ChainPolicy.VerificationFlags = "
                     "X509VerificationFlags.AllFlags;\n") == []

    def test_go_zero_current_time_arm_deleted(self, tmp_path: Path) -> None:
        """`CurrentTime: time.Time{}` is the *secure default* — crypto/x509
        substitutes time.Now() when the value is zero."""
        assert _scan(tmp_path, "verify.go",
                     "opts := x509.VerifyOptions{CurrentTime: time.Time{}}\n") == []

    def test_empty_expired_catch(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Verify.java",
                  "        catch (CertificateExpiredException e) {}\n")
        assert _cats(f) == ["CWE-298"]

    def test_handled_expired_catch_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Verify.java",
                     "        catch (CertificateExpiredException e) "
                     "{ throw new SecurityException(e); }\n") == []

    def test_archival_window_suppresses(self, tmp_path: Path) -> None:
        body = (
            "// Long-term archival signature validation uses the timestamp\n"
            "flags |= X509VerificationFlags.IgnoreNotTimeValid;\n"
        )
        assert _scan(tmp_path, "Archive.cs", body) == []


# ---------------------------------------------------------------------------
# Item 19 — CWE-299 Certificate Revocation
# ---------------------------------------------------------------------------

class TestCwe299Revocation:
    def test_java_revocation_disabled(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Pkix.java", "params.setRevocationEnabled(false);\n")
        assert _cats(f) == ["CWE-299"]

    def test_java_revocation_enabled_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Pkix.java",
                     "params.setRevocationEnabled(true);\n") == []

    def test_dotnet_revocation_no_check(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Chain.cs",
                  "chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;\n")
        assert _cats(f) == ["CWE-299"]

    def test_dotnet_revocation_online_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Chain.cs",
                     "chain.ChainPolicy.RevocationMode = "
                     "X509RevocationMode.Online;\n") == []

    def test_dotnet_check_crl_false(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "Handler.cs",
                  "handler.CheckCertificateRevocationList = false;\n")
        assert _cats(f) == ["CWE-299"]

    def test_dotnet_check_crl_true_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Handler.cs",
                     "handler.CheckCertificateRevocationList = true;\n") == []

    def test_openssl_crl_flag_cleared(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "verify.c",
                  "X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_CRL_CHECK);\n")
        assert _cats(f) == ["CWE-299"]

    def test_openssl_crl_flag_set_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "verify.c",
                     "X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_CRL_CHECK);\n") == []

    def test_cli_arms_are_not_shipped_here(self, tmp_path: Path) -> None:
        """`--ssl-no-revoke` / `-Dcom.sun.net.ssl.checkRevocation=false` live in
        shell / gradle / Dockerfile lines, which this skill does not scan; the
        arms were dropped rather than shipped as dead code."""
        assert _scan(tmp_path, "run.py",
                     'subprocess.run(["curl", "--ssl-no-revoke", url])\n') == []


# ---------------------------------------------------------------------------
# Item 67 — CWE-296 Certificate Chain of Trust (P3 co-landing)
# ---------------------------------------------------------------------------

class TestCwe296ChainOfTrust:
    def test_empty_check_server_trusted_kotlin(self, tmp_path: Path) -> None:
        f = _scan(
            tmp_path, "TlsFactory.kt",
            "override fun checkServerTrusted(chain: Array<X509Certificate>, "
            "authType: String) {}\n",
        )
        assert _cats(f) == ["CWE-296"]

    def test_delegating_check_server_trusted_clean_twin(self, tmp_path: Path) -> None:
        body = (
            "override fun checkServerTrusted(chain: Array<X509Certificate>, "
            "authType: String) {\n"
            "    defaultTrust.checkServerTrusted(chain, authType)\n"
            "}\n"
        )
        assert _scan(tmp_path, "TlsFactory.kt", body) == []

    def test_empty_body_across_lines(self, tmp_path: Path) -> None:
        body = (
            "public void checkServerTrusted(X509Certificate[] chain, String a)\n"
            "        throws CertificateException {\n"
            "}\n"
        )
        assert _cats(_scan(tmp_path, "TrustAll.java", body)) == ["CWE-296"]

    def test_check_client_trusted_never_fires(self, tmp_path: Path) -> None:
        """Server-side method ONLY — an empty `checkClientTrusted` is the
        ordinary case for a client that presents no certificate."""
        assert _scan(
            tmp_path, "TrustAll.java",
            "public void checkClientTrusted(X509Certificate[] c, String a) {}\n",
        ) == []

    def test_null_accepted_issuers_java(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "TrustAll.java",
                  "public X509Certificate[] getAcceptedIssuers() { return null; }\n")
        assert _cats(f) == ["CWE-296"]

    def test_empty_array_accepted_issuers_kotlin(self, tmp_path: Path) -> None:
        f = _scan(
            tmp_path, "TlsFactory.kt",
            "override fun getAcceptedIssuers(): Array<X509Certificate> = "
            "emptyArray()\n",
        )
        assert _cats(f) == ["CWE-296"]

    def test_real_accepted_issuers_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(
            tmp_path, "TrustAll.java",
            "public X509Certificate[] getAcceptedIssuers() "
            "{ return delegate.getAcceptedIssuers(); }\n",
        ) == []

    def test_partial_chain_flag(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "verify.c",
                  "X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_PARTIAL_CHAIN);\n")
        assert _cats(f) == ["CWE-296"]


# ---------------------------------------------------------------------------
# Item 18 — CWE-523 Unprotected Transport of Credentials
# ---------------------------------------------------------------------------

class TestCwe523Credentials:
    def test_userinfo_url_is_523_not_319(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "db.py",
                  'URL = "http://admin:hunter2@db.example.net:5432/data"\n')
        assert _cats(f) == ["CWE-523"]
        assert any("plaintext_http_credentials" in i for i in _ids(f))

    def test_https_userinfo_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "db.py",
                     'URL = "https://admin:hunter2@db.example.net:5432/data"\n') == []

    def test_basic_auth_over_http(self, tmp_path: Path) -> None:
        f = _scan(
            tmp_path, "client.py",
            'requests.get("http://api.corp.net/v1", '
            'headers={"Authorization": "Basic " + blob})\n',
        )
        assert _cats(f) == ["CWE-523"]

    def test_basic_auth_over_https_clean_twin(self, tmp_path: Path) -> None:
        assert _scan(
            tmp_path, "client.py",
            'requests.get("https://api.corp.net/v1", '
            'headers={"Authorization": "Basic " + blob})\n',
        ) == []

    def test_credential_proximity_conjunction(self, tmp_path: Path) -> None:
        body = (
            'endpoint = "http://api.corp.net/login"\n'
            'payload = {"username": user, "password": secret}\n'
            "resp = requests.post(endpoint, json=payload)\n"
        )
        f = _scan(tmp_path, "login.py", body)
        assert _cats(f) == ["CWE-523"]

    def test_credential_proximity_https_clean_twin(self, tmp_path: Path) -> None:
        body = (
            'endpoint = "https://api.corp.net/login"\n'
            'payload = {"username": user, "password": secret}\n'
            "resp = requests.post(endpoint, json=payload)\n"
        )
        assert _scan(tmp_path, "login.py", body) == []

    def test_http_without_request_idiom_keeps_319(self, tmp_path: Path) -> None:
        """The 523/319 partition: credential-bearing request → 523, every other
        plaintext-scheme line keeps CWE-319."""
        body = (
            'DOCS = "http://wiki.corp.net/password-policy"\n'
        )
        assert _cats(_scan(tmp_path, "docs.py", body)) == ["CWE-319"]

    def test_form_action_over_http_with_password_field(self, tmp_path: Path) -> None:
        """Per-RULE extension scoping: the template arm reaches `.html` without
        widening the module-wide set (which would expose `_PLAINTEXT_SCHEME` to
        every asset/CDN/namespace URL in the tree)."""
        body = (
            '<form action="http://portal.corp.net/login" method="post">\n'
            '  <input type="password" name="pw">\n'
            "</form>\n"
        )
        f = _scan(tmp_path, "login.html", body)
        assert _cats(f) == ["CWE-523"]

    def test_form_action_https_clean_twin(self, tmp_path: Path) -> None:
        body = (
            '<form action="https://portal.corp.net/login" method="post">\n'
            '  <input type="password" name="pw">\n'
            "</form>\n"
        )
        assert _scan(tmp_path, "login.html", body) == []

    def test_form_without_password_field_clean_twin(self, tmp_path: Path) -> None:
        body = (
            '<form action="http://portal.corp.net/search" method="get">\n'
            '  <input type="text" name="q">\n'
            "</form>\n"
        )
        assert _scan(tmp_path, "search.html", body) == []

    def test_module_wide_extension_set_not_widened(self, tmp_path: Path) -> None:
        """`_PLAINTEXT_SCHEME` must NOT start firing on templates."""
        assert _scan(tmp_path, "page.html",
                     '<img src="http://cdn.example.net/logo.png">\n') == []


class TestNonEndpointUrlVeto:
    """Applied module-wide: `_PLAINTEXT_SCHEME` already fires on namespace and
    spec URLs in `.java` sources today."""

    def test_xml_namespace_is_not_a_transport(self, tmp_path: Path) -> None:
        assert _scan(
            tmp_path, "Marshal.java",
            'String NS = "http://www.w3.org/2001/XMLSchema-instance";\n',
        ) == []

    def test_license_url_is_not_a_transport(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "Header.java",
                     'static final String L = "http://apache.org/licenses/LICENSE-2.0";\n'
                     ) == []

    def test_real_endpoint_still_flagged(self, tmp_path: Path) -> None:
        assert _cats(_scan(tmp_path, "Client.java",
                           'String url = "http://broker.corp.net/queue";\n')
                     ) == ["CWE-319"]


# ---------------------------------------------------------------------------
# CWE-319 regression — the parent detector must keep its own rows
# ---------------------------------------------------------------------------

class TestCwe319Retained:
    def test_plaintext_scheme_still_319(self, tmp_path: Path) -> None:
        f = _scan(tmp_path, "app.py", 'REDIS = "redis://cache.corp.net:6379/0"\n')
        assert _cats(f) == ["CWE-319"]

    def test_loopback_still_suppressed(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "app.py",
                     'REDIS = "redis://127.0.0.1:6379/0"\n') == []


# ---------------------------------------------------------------------------
# Shared guards
# ---------------------------------------------------------------------------

class TestGuards:
    def test_scanner_definition_line_suppressed(self, tmp_path: Path) -> None:
        """A sibling tool's own pattern table is not a vulnerability."""
        assert _scan(
            tmp_path, "rules.py",
            'PAT = re.compile(r"rejectUnauthorized\\s*[:=]\\s*false")\n',
        ) == []

    def test_comment_line_suppressed(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "ctx.py",
                     "# never set ctx.check_hostname = False in production\n") == []

    def test_minified_bundle_line_skipped(self, tmp_path: Path) -> None:
        """§6 P8: `_MINIFIED_RE` is filename-only, so a bundler chunk under a
        non-canonical build directory is scanned in full. The single CWE-523 row
        this skill produced on the measured baseline was a 127KB one-line
        webpack chunk — false. A length cap, not a filename, is the defence."""
        bundle = (
            "(self.webpackChunk=self.webpackChunk||[]).push([" + "0," * 400
            + 'e="http://api.corp.net/login",t={password:p},r=fetch(e,t)]);\n'
        )
        assert _scan(tmp_path, "main-4dac33c5289d.js", bundle) == []

    def test_short_line_with_same_content_still_fires(self, tmp_path: Path) -> None:
        assert _cats(_scan(
            tmp_path, "login.js",
            'const r = fetch("http://api.corp.net/login", {password: p});\n',
        )) == ["CWE-523"]

    def test_prose_file_not_scanned(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "SECURITY.md",
                     "Never pass `verify=False` to requests.get().\n") == []

    def test_test_file_suppressed(self, tmp_path: Path) -> None:
        assert _scan(tmp_path, "test_client.py",
                     'requests.get(u, verify=False)\n') == []

    def test_every_finding_is_enriched_and_single_row(self, tmp_path: Path) -> None:
        body = (
            "ctx.check_hostname = False\n"
            "handler.CheckCertificateRevocationList = false;\n"
        )
        f = _scan(tmp_path, "mixed.cs", body)
        # one row per line, never two
        assert len(f) == 2
        assert {x["line_start"] for x in f} == {1, 2}
        for finding in f:
            assert finding["check_id"].startswith("cwe.plaintext_transmission.")
            # every id this skill emits must be enrichable from the catalog
            assert finding["cwe_name"]


class TestCategoryLiteralsAreExtractable:
    """§6 P0 / rule 8: the coverage extractor only sees a physical
    ``"category": "CWE-N"`` or ``category="CWE-N"`` literal — a category built
    with an f-string detects while the attestation denies it."""

    def test_all_new_ids_present_as_literals(self) -> None:
        import re

        from cwe_agent.skills import plaintext_transmission_check as mod

        text = Path(mod.__file__).read_text(encoding="utf-8")
        found = set(
            re.findall(r'(?:"category"\s*:|\bcategory\s*=)\s*"CWE-(\d+)"', text)
        )
        assert {"295", "296", "297", "298", "299", "319", "347", "523"} <= found
