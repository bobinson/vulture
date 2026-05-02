"""Phase 4 — Substrate detection tests."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import substrate


def _scan(content: str, path: str = "src/runtime.rs") -> list[dict]:
    return substrate.find_substrate_secrets(Path(path), content)


def _has(findings: list[dict], substr: str) -> bool:
    return any(substr in f["check_id"] for f in findings)


class TestPositive:
    def test_polkadot_js_keystore_detected(self):
        keystore = (
            '{"encoded":"abc123","encoding":{"content":["pkcs8","sr25519"],'
            '"type":["scrypt","xsalsa20-poly1305"],"version":"3"},'
            '"address":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}'
        )
        findings = _scan(keystore, "wallet.json")
        assert _has(findings, "polkadot_keystore")
        # Encrypted (scrypt + xsalsa20-poly1305) → high
        assert findings[0]["severity"] == "high"

    def test_alice_dev_uri_in_production_path(self):
        # Path is "src/runtime.rs" — production-ish, not under /tests/.
        line = 'keyring.addFromUri("//Alice")'
        findings = _scan(line)
        assert _has(findings, "dev_uri")
        # Production path → medium.
        assert findings[0]["severity"] == "medium"

    def test_alice_in_test_path_is_info(self):
        line = 'keyring.addFromUri("//Alice")'
        findings = _scan(line, path="tests/setup.rs")
        assert _has(findings, "dev_uri")
        # /tests/ path → info.
        assert findings[0]["severity"] == "info"

    def test_subkey_secret_seed_output(self):
        line = "  Secret seed: 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        findings = _scan(line)
        assert _has(findings, "subkey_output")
        assert findings[0]["severity"] == "critical"

    def test_subkey_secret_phrase_output(self):
        # Multi-line subkey output snippet.
        block = (
            "Secret phrase: bottom drive obey lake curtain smoke basket hold race lonely fit walk\n"
            "  Network ID: substrate\n"
            "  Secret seed: 0xfac7959dbfe72f052e5a0715d1e8a16b6a73e36a17b5f3df7d6d2716e7d04a55\n"
        )
        findings = _scan(block)
        # Both Secret phrase and Secret seed lines should fire.
        subkey_findings = [f for f in findings if "subkey_output" in f["check_id"]]
        assert len(subkey_findings) >= 2

    def test_ss58_address_in_substrate_context(self):
        # Triggered only when the file has substrate context.
        content = (
            "use substrate::keyring;\n"
            "let alice = '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY';\n"
        )
        findings = _scan(content)
        assert _has(findings, "ss58_substrate")
        ss58 = next(f for f in findings if "ss58" in f["check_id"])
        assert ss58["severity"] == "info"


class TestNegative:
    def test_ss58_without_substrate_context_skipped(self):
        # No substrate / polkadot / kusama hint in the file → skip
        # informational SS58 detection (avoids matching unrelated base58).
        content = "let s = '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY';"
        findings = _scan(content)
        assert not _has(findings, "ss58")

    def test_polkadot_js_keystore_missing_encoding_skipped(self):
        # Only "encoded" present, no "encoding" — three-fact match fails.
        partial = '{"encoded":"abc123","address":"5..."}'
        findings = _scan(partial, "wallet.json")
        assert not _has(findings, "polkadot_keystore")

    def test_safe_context_skips_subkey_output(self):
        line = "# example: Secret seed: 0xabc # changeme"
        findings = _scan(line)
        assert not _has(findings, "subkey_output")

    def test_alice_in_string_not_keyring_call_no_finding(self):
        # The strict DEV_URI_RE requires keyring.* prefix. A bare
        # "//Alice" string in unrelated code shouldn't be flagged.
        line = 'comment = "no Alice here, just a comment"'
        findings = _scan(line)
        assert not _has(findings, "dev_uri")
