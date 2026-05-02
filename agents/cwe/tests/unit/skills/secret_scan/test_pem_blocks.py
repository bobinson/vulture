"""Phase 1 — PEM block detector tests.

8 positive (one per kind, with line-ending variants) + 4 negative
(public certs + truncated/garbled blocks)."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import pem_blocks


def _block(kind: str, body_lines: int = 4) -> str:
    """Render a fake PEM block for tests."""
    body = "\n".join("A" * 64 for _ in range(body_lines))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


# ---------------------------------------------------------------------------
# Positive cases (8)
# ---------------------------------------------------------------------------

class TestPositiveDetection:
    def test_rsa_private_key(self):
        block = _block("RSA PRIVATE KEY")
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), block)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["category"] == "CWE-798"
        assert "RSA PRIVATE KEY" in findings[0]["title"]
        # Check redaction
        assert "AAAA" not in findings[0]["code_snippet"]
        assert "REDACTED" in findings[0]["code_snippet"]

    def test_ec_private_key(self):
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), _block("EC PRIVATE KEY"))
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_dsa_private_key(self):
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), _block("DSA PRIVATE KEY"))
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_openssh_private_key(self):
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), _block("OPENSSH PRIVATE KEY"))
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_pkcs8_generic_private_key(self):
        # Plain PKCS#8: -----BEGIN PRIVATE KEY-----
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), _block("PRIVATE KEY"))
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert "PRIVATE KEY" in findings[0]["title"]

    def test_encrypted_pkcs8_drops_to_high(self):
        findings = pem_blocks.find_pem_blocks(
            Path("a.pem"), _block("ENCRYPTED PRIVATE KEY")
        )
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_legacy_encrypted_rsa_drops_to_high(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,1234ABCD\n"
            "\n"
            "AAAAAAAA\nBBBBBBBB\n"
            "-----END RSA PRIVATE KEY-----"
        )
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), block)
        assert len(findings) == 1
        # Legacy Proc-Type marker → encrypted → severity high
        assert findings[0]["severity"] == "high"

    def test_crlf_line_endings(self):
        block = _block("RSA PRIVATE KEY").replace("\n", "\r\n")
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), block)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Negative cases (4)
# ---------------------------------------------------------------------------

class TestNegativeDetection:
    def test_public_certificate_not_flagged(self):
        cert = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDXTCCAkWgAwIBAgIJ...\n"
            "-----END CERTIFICATE-----"
        )
        findings = pem_blocks.find_pem_blocks(Path("server.crt"), cert)
        assert findings == []

    def test_public_key_not_flagged(self):
        pubkey = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n"
            "-----END PUBLIC KEY-----"
        )
        findings = pem_blocks.find_pem_blocks(Path("public.pem"), pubkey)
        assert findings == []

    def test_truncated_block_no_end_marker(self):
        truncated = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "AAAAAAAAAA\n"
            "BBBBBBBBBB\n"
            # missing END
        )
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), truncated)
        assert findings == []

    def test_mismatched_kind_no_match(self):
        # BEGIN says RSA, END says EC — backreference (?P=kind) must reject.
        garbled = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "AAAAAAAAAA\n"
            "-----END EC PRIVATE KEY-----"
        )
        findings = pem_blocks.find_pem_blocks(Path("a.pem"), garbled)
        assert findings == []
