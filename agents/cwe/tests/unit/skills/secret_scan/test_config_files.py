"""Phase 5 — Config-file (JSON / YAML / .env) extraction tests."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import config_files


def _scan(content: str, path: str) -> list[dict]:
    return config_files.find_config_secrets(Path(path), content)


def _has(findings: list[dict], substr: str) -> bool:
    return any(substr in f["check_id"] for f in findings)


class TestPositive:
    def test_json_with_aws_key(self):
        # No "EXAMPLE" in the value (would trip SAFE_CONTEXT regex).
        content = '{"aws_access_key": "AKIAJABCDEFGHIJKLMN0"}'
        findings = _scan(content, "config.json")
        assert _has(findings, "aws_access_key_id")

    def test_yaml_with_stripe_live(self):
        content = 'stripe_secret: "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'
        findings = _scan(content, "config.yaml")
        assert _has(findings, "stripe_live_secret")

    def test_env_file_with_github_pat(self):
        content = 'GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n'
        findings = _scan(content, ".env.production")
        assert _has(findings, "github_pat")

    def test_suspicious_key_name_with_literal(self):
        # Key name suggests secret, value isn't a placeholder, no cloud
        # pattern matches → name-shape suspicion at medium severity.
        content = '{"my_internal_secret": "internal-system-9f8e7d6c5b4a3210"}'
        findings = _scan(content, "config.json")
        assert _has(findings, "suspicious_key_name")
        assert findings[0]["severity"] == "medium"

    def test_json_walks_nested(self):
        content = '{"db": {"primary": {"password": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}}}'
        findings = _scan(content, "config.json")
        assert _has(findings, "github_pat")


class TestNegative:
    def test_placeholder_value_skipped(self):
        content = '{"api_key": "<your-key-here>"}'
        findings = _scan(content, "config.json")
        assert not findings

    def test_changeme_marker_skipped(self):
        content = '{"password": "changeme"}'
        findings = _scan(content, "config.json")
        assert not findings

    def test_short_value_for_suspicious_name_skipped(self):
        # Suspicious name but value < 8 chars → not a real secret.
        content = '{"password": "abc"}'
        findings = _scan(content, "config.json")
        assert not findings
