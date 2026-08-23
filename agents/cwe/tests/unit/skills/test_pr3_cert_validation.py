"""PR3 — the wholesale certificate-verification-off family is ONE weakness.

Disabling verification entirely is the same defect in every dialect:
``verify=False``, ``rejectUnauthorized: false``, ``InsecureSkipVerify: true``,
``verify_mode = …CERT_NONE`` / ``…VERIFY_NONE``, ``_create_unverified_context``,
a ``=> true`` validation callback, ``set_verify(…, …VERIFY_NONE)`` and
``CURLOPT_SSL_VERIFYPEER, 0``. All of them must be filed under CWE-295.

Filing the C / .NET / Python spellings under CWE-296 would split one weakness
across two ids BY LANGUAGE and pad 296's count. CWE-296 is the narrower
"chain of trust not followed" — an empty ``checkServerTrusted``, absent trust
anchors, a partial chain — and this module keeps it to exactly that.

The ``VERIFY_NONE`` token must live in ONE arm: registered twice it would
double-report the same line. These tests pin the routing, the single
registration, and the two forms the receiver anchor must still reach
(per-connection ``SSL_set_verify`` and the pyOpenSSL ``ctx.set_verify``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.plaintext_transmission_check import (
    _SPECS,
    check_plaintext_transmission,
)

WHOLESALE_ARMS: tuple[tuple[str, str, str], ...] = (
    ("verify_false", "client.py",
     'r = requests.get("https://svc.example/api", verify=False)\n'),
    ("reject_unauthorized", "wsclient.ts",
     "wsOptions.rejectUnauthorized = false;\n"),
    ("insecure_skip_verify", "transport.go",
     "cfg := &tls.Config{InsecureSkipVerify: true}\n"),
    ("cert_none", "ctx.py", "ctx.verify_mode = ssl.CERT_NONE\n"),
    ("namespaced_verify_none", "http.rb",
     "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"),
    ("unverified_context", "ctx.py", "ctx = ssl._create_unverified_context()\n"),
    ("validation_callback_true", "Http.cs",
     "ServicePointManager.ServerCertificateValidationCallback "
     "= (s, c, ch, e) => true;\n"),
    ("openssl_context", "tls.c", "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);\n"),
    ("openssl_connection", "tls.c", "SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);\n"),
    ("pyopenssl_context", "tls_client.py",
     "ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)\n"),
    ("curl_verifypeer", "client.php",
     "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);\n"),
)

CHAIN_ARMS: tuple[tuple[str, str, str], ...] = (
    ("empty_server_trust", "TrustAll.java",
     "public void checkServerTrusted(X509Certificate[] c, String a)\n"
     "        throws CertificateException {\n"
     "}\n"),
    ("null_trust_anchors", "TrustAll.java",
     "public X509Certificate[] getAcceptedIssuers() { return null; }\n"),
    ("partial_chain", "verify.c",
     "X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_PARTIAL_CHAIN);\n"),
)

CLEAN_TWINS: tuple[tuple[str, str, str], ...] = (
    ("mode_table", "modes.c", "static const int kModes[] = { SSL_VERIFY_NONE };\n"),
    ("verify_peer", "tls.c", "SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_cb);\n"),
    ("cert_required", "ctx.py", "ctx.verify_mode = ssl.CERT_REQUIRED\n"),
    ("namespaced_verify_peer", "http.rb",
     "http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n"),
    ("commented_out", "tls.c",
     "/* SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL) is forbidden here */\n"),
)


def _scan(tmp_path: Path, name: str, body: str) -> list[dict]:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return check_plaintext_transmission(str(tmp_path))["findings"]


def _ids(case: tuple[tuple[str, str, str], ...]) -> list[str]:
    return [row[0] for row in case]


class TestWholesaleArmsAreCwe295:
    @pytest.mark.parametrize(
        ("name", "body"),
        [(n, b) for _, n, b in WHOLESALE_ARMS],
        ids=_ids(WHOLESALE_ARMS),
    )
    def test_wholesale_arm_files_under_295(
        self, tmp_path: Path, name: str, body: str
    ) -> None:
        findings = _scan(tmp_path, name, body)
        assert [f["category"] for f in findings] == ["CWE-295"]

    @pytest.mark.parametrize(
        ("name", "body"),
        [(n, b) for _, n, b in WHOLESALE_ARMS],
        ids=_ids(WHOLESALE_ARMS),
    )
    def test_wholesale_arm_never_files_under_296(
        self, tmp_path: Path, name: str, body: str
    ) -> None:
        """A language-specific spelling of "verification off" must not be
        filed as a chain-of-trust defect — that splits one weakness by
        language."""
        assert "CWE-296" not in {f["category"] for f in _scan(tmp_path, name, body)}


class TestChainArmsStayCwe296:
    @pytest.mark.parametrize(
        ("name", "body"),
        [(n, b) for _, n, b in CHAIN_ARMS],
        ids=_ids(CHAIN_ARMS),
    )
    def test_chain_arm_files_under_296(
        self, tmp_path: Path, name: str, body: str
    ) -> None:
        assert [f["category"] for f in _scan(tmp_path, name, body)] == ["CWE-296"]

    def test_296_is_emitted_by_chain_rules_only(self) -> None:
        """CWE-296 keeps its reachability claim because genuine chain-of-trust
        rules remain — and ONLY those."""
        emitters = {s.rule_id for s in _SPECS if s.category == "CWE-296"}
        assert emitters == {"empty_trust_manager", "missing_trust_anchors"}


class TestVerifyNoneRegisteredOnce:
    def test_two_set_verify_calls_on_one_line_yield_one_row(
        self, tmp_path: Path
    ) -> None:
        """A token registered in two arms would report the same line twice."""
        findings = _scan(
            tmp_path, "tls.c",
            "SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL); "
            "SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);\n",
        )
        assert len(findings) == 1
        assert findings[0]["line_start"] == 1

    def test_verify_none_line_with_a_url_still_yields_one_row(
        self, tmp_path: Path
    ) -> None:
        """The plaintext-scheme arm must not stack a second row on a line the
        certificate arm already owns."""
        findings = _scan(
            tmp_path, "tls_client.py",
            'ctx.set_verify(SSL.VERIFY_NONE, cb)  # peer http://svc.example/api\n',
        )
        assert [f["category"] for f in findings] == ["CWE-295"]


class TestCleanTwins:
    @pytest.mark.parametrize(
        ("name", "body"),
        [(n, b) for _, n, b in CLEAN_TWINS],
        ids=_ids(CLEAN_TWINS),
    )
    def test_clean_twin_is_silent(
        self, tmp_path: Path, name: str, body: str
    ) -> None:
        assert _scan(tmp_path, name, body) == []
