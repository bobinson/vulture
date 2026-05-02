"""Phase 3 — Cryptocurrency wallet detection tests.

12 positive (BIP-39 ×3, BIP-32 ×2, WIF ×2, ETH ×2, Solana ×3) +
8 negative."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import crypto_wallets


def _scan(content: str, path: str = "src/wallet.py") -> list[dict]:
    return crypto_wallets.find_crypto_secrets(Path(path), content)


def _has_check(findings: list[dict], substr: str) -> bool:
    return any(substr in f["check_id"] for f in findings)


# ---------------------------------------------------------------------------
# BIP-39 mnemonic
# ---------------------------------------------------------------------------

class TestBIP39:
    # The canonical BIP-39 zero-entropy 24-word phrase.
    ALL_ABANDON_24 = " ".join(["abandon"] * 23 + ["art"])

    # 12 valid words.
    SAMPLE_12 = (
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )

    def test_24_word_mnemonic_detected(self):
        findings = _scan(self.ALL_ABANDON_24)
        assert _has_check(findings, "bip39_mnemonic")
        f = findings[0]
        assert f["severity"] == "critical"
        assert "24" in f["title"]

    def test_12_word_mnemonic_detected(self):
        findings = _scan(self.SAMPLE_12)
        assert _has_check(findings, "bip39_mnemonic")
        assert "12" in findings[0]["title"]

    def test_mnemonic_redaction(self):
        # Phrase content must not appear in the snippet.
        findings = _scan(self.SAMPLE_12)
        f = findings[0]
        assert "abandon" not in f["code_snippet"].lower()
        assert "REDACTED" in f["code_snippet"]


# ---------------------------------------------------------------------------
# BIP-32 extended keys
# ---------------------------------------------------------------------------

class TestBIP32:
    XPRV = "xprv" + "1" * 107  # 111 chars total — minimal valid-shape pattern
    XPUB = "xpub" + "1" * 107

    def test_xprv_critical(self):
        findings = _scan(f'k = "{self.XPRV}"')
        assert _has_check(findings, "bip32_xprv")
        assert findings[0]["severity"] == "critical"

    def test_xpub_info(self):
        findings = _scan(f'k = "{self.XPUB}"')
        assert _has_check(findings, "bip32_xpub")
        assert findings[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Bitcoin WIF
# ---------------------------------------------------------------------------

class TestWIF:
    # A real (publicly-known) WIF: corresponds to private key 0x01.
    REAL_WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"

    def test_real_wif_with_valid_checksum(self):
        # Without context, just place it in the content. The WIF detector
        # is not gated by context (unlike ETH hex).
        findings = _scan(f'priv = "{self.REAL_WIF}"')
        assert _has_check(findings, "bitcoin_wif")
        assert findings[0]["severity"] == "critical"

    def test_invalid_checksum_rejected(self):
        # Same length / alphabet but checksum will be wrong.
        bad = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDX"
        findings = _scan(f'priv = "{bad}"')
        assert not _has_check(findings, "bitcoin_wif")


# ---------------------------------------------------------------------------
# Ethereum private key
# ---------------------------------------------------------------------------

class TestEth:
    # A 64-hex value with deliberate context — Hardhat default account 0.
    REAL_ETH = (
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )

    def test_eth_with_context_detected(self):
        line = f'private_key = "0x{self.REAL_ETH}"'
        findings = _scan(line)
        assert _has_check(findings, "eth_private_key")
        assert findings[0]["severity"] == "critical"

    def test_eth_without_context_skipped(self):
        # Same hex value with no key/wallet/signer context word nearby —
        # could be a SHA-256 hash. Should NOT fire.
        line = f'commit_hash = "0x{self.REAL_ETH}"'
        findings = _scan(line)
        assert not _has_check(findings, "eth_private_key")


# ---------------------------------------------------------------------------
# Solana keypair JSON
# ---------------------------------------------------------------------------

class TestSolana:
    # 64 zero bytes — valid shape, all values in 0..255.
    KEYPAIR = "[" + ",".join(["0"] * 64) + "]"
    KEYPAIR_REAL = "[" + ",".join(str(i % 256) for i in range(64)) + "]"

    def test_keypair_zero_bytes(self):
        findings = _scan(f'kp = {self.KEYPAIR}')
        assert _has_check(findings, "solana_keypair")
        assert findings[0]["severity"] == "critical"

    def test_keypair_with_real_bytes(self):
        findings = _scan(f'kp = {self.KEYPAIR_REAL}')
        assert _has_check(findings, "solana_keypair")

    def test_array_with_out_of_range_byte_rejected(self):
        # 999 is out of byte range → not a Solana keypair.
        bad = "[" + ",".join(["999"] * 64) + "]"
        findings = _scan(f'arr = {bad}')
        assert not _has_check(findings, "solana_keypair")

    def test_array_wrong_length_rejected(self):
        # 32 elements, not 64 — not a keypair.
        short = "[" + ",".join(["0"] * 32) + "]"
        findings = _scan(f'arr = {short}')
        assert not _has_check(findings, "solana_keypair")


# ---------------------------------------------------------------------------
# Generic negatives
# ---------------------------------------------------------------------------

class TestNegativesGeneric:
    def test_random_english_text_no_mnemonic(self):
        # English text that intentionally is NOT BIP-39 — almost no
        # consecutive BIP-39 words. The wordlist excludes common prose
        # words like "the", "and", "of".
        findings = _scan(
            "the quick brown fox jumps over the lazy dog several times today and tomorrow"
        )
        assert not _has_check(findings, "bip39_mnemonic")

    def test_partial_mnemonic_run_not_flagged(self):
        # 11 BIP-39 words — below the minimum of 12.
        findings = _scan(
            "abandon ability able about above absent absorb abstract absurd abuse access"
        )
        assert not _has_check(findings, "bip39_mnemonic")

    def test_safe_context_marker_skips_mnemonic(self):
        # Place an obvious test/example marker on the line.
        line = "# example mnemonic for tests: " + " ".join(["abandon"] * 11) + " art"
        findings = _scan(line)
        assert not _has_check(findings, "bip39_mnemonic")
