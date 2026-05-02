"""Phase 2 — Cloud / SaaS provider pattern tests."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import cloud_providers


def _scan(content: str, path: str = "src/app.py") -> list[dict]:
    return cloud_providers.find_cloud_secrets(Path(path), content)


def _has_rule(findings: list[dict], rule_id: str) -> bool:
    return any(f["check_id"].endswith(rule_id) for f in findings)


# ---------------------------------------------------------------------------
# Positive cases — one per provider
# ---------------------------------------------------------------------------

class TestPositive:
    def test_aws_access_key_id(self):
        # 16 uppercase alphanumeric after AKIA, no "example" word
        # (which would trigger SAFE_CONTEXT).
        findings = _scan('aws_key = "AKIAJABCDEFGHIJKLMN0"')
        assert _has_rule(findings, "aws_access_key_id")
        assert findings[0]["severity"] == "critical"

    def test_aws_temp_access_key(self):
        findings = _scan('temp = "ASIA1234567890ABCDEF"')
        assert _has_rule(findings, "aws_temp_access_key")
        assert findings[0]["severity"] == "high"

    def test_aws_secret_access_key_in_context(self):
        # 40-char base64-ish value, no "example" / placeholder marker
        line = (
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRfiCYABCDEFGHIJKL"'
        )
        findings = _scan(line)
        assert _has_rule(findings, "aws_secret_access_key")

    def test_github_pat(self):
        findings = _scan('token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"')
        assert _has_rule(findings, "github_pat")
        assert findings[0]["severity"] == "critical"

    def test_github_app_token(self):
        findings = _scan('t = "ghs_abcdefghijklmnopqrstuvwxyz0123456789"')
        assert _has_rule(findings, "github_app_token")

    def test_gitlab_pat(self):
        findings = _scan('t = "glpat-1234567890abcdef_ghi"')
        assert _has_rule(findings, "gitlab_pat")

    def test_stripe_live_secret(self):
        findings = _scan(
            'stripe_key = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'
        )
        assert _has_rule(findings, "stripe_live_secret")
        assert findings[0]["severity"] == "critical"

    def test_stripe_test_is_low_severity(self):
        findings = _scan(
            'k = "sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'
        )
        assert _has_rule(findings, "stripe_test_secret")
        assert findings[0]["severity"] == "low"

    def test_slack_bot_token(self):
        findings = _scan(
            'tok = "xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"'
        )
        assert _has_rule(findings, "slack_bot_token")

    def test_slack_webhook_url(self):
        findings = _scan(
            'WEBHOOK = "https://hooks.slack.com/services/T01ABCDEFGH/B01ABCDEFGH/abcdefghijklmnopqrstuvwx"'
        )
        assert _has_rule(findings, "slack_webhook")

    def test_google_api_key(self):
        # AIza + exactly 35 chars
        findings = _scan('K = "AIzaSyD1aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"')
        assert _has_rule(findings, "google_api_key")

    def test_google_oauth_client_secret(self):
        # GOCSPX- + exactly 28 chars
        findings = _scan('s = "GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ12"')
        assert _has_rule(findings, "google_oauth_client_secret")

    def test_sendgrid(self):
        # SG. + 22 chars + . + 43 chars
        findings = _scan(
            'k = "SG.aBcDeFgHiJkLmNoPqRsTuV.WxYz012345678901234567890123456789012345678"'
        )
        assert _has_rule(findings, "sendgrid_api_key")

    def test_npm_token(self):
        findings = _scan('NPM = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"')
        assert _has_rule(findings, "npm_token")

    def test_anthropic(self):
        # Realistic-shape key
        body = "a" * 95
        findings = _scan(f'key = "sk-ant-api03-{body}"')
        assert _has_rule(findings, "anthropic_api_key")

    def test_huggingface(self):
        # hf_ + exactly 34 alphanumeric chars
        findings = _scan('hf = "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"')
        assert _has_rule(findings, "huggingface_token")

    def test_jwt_medium_severity(self):
        # Three-segment base64-ish token
        findings = _scan(
            'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
            '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        )
        assert _has_rule(findings, "jwt")
        # JWT severity is medium because the payload isn't always secret.
        jwt_finding = next(f for f in findings if f["check_id"].endswith("jwt"))
        assert jwt_finding["severity"] == "medium"


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

class TestNegative:
    def test_safe_context_skipped(self):
        # 'example' in the line should suppress the finding.
        findings = _scan('aws_key = "AKIAIOSFODNN7EXAMPLE"  # example value')
        assert not findings

    def test_placeholder_skipped(self):
        findings = _scan('aws_key = "AKIA<your-key-here>1234"')
        assert not findings

    def test_random_alphanumeric_not_aws(self):
        # 20 lowercase chars — doesn't match AKIA pattern.
        findings = _scan('id = "abcdefghij1234567890"')
        assert not _has_rule(findings, "aws_access_key_id")

    def test_short_string_not_github(self):
        # Too short to match ghp_ + 36 chars.
        findings = _scan('token = "ghp_short"')
        assert not _has_rule(findings, "github_pat")

    def test_changeme_marker_skipped(self):
        findings = _scan('token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # changeme')
        assert not findings

    def test_redaction_in_snippet(self):
        # Verify the output's code_snippet has redaction applied.
        findings = _scan('k = "AIzaSyD1aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"')
        assert findings
        assert "AIzaSyD1aBcDeFgHiJkLmNoPqRsTuVwXyZ01234" not in findings[0]["code_snippet"]
        assert "REDACTED" in findings[0]["code_snippet"]
