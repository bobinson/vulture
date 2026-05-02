"""Phase 5 — Shannon-entropy fallback tests."""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import entropy


def _scan(content: str) -> list[dict]:
    return entropy.find_high_entropy(Path("src/app.py"), content)


class TestPositive:
    def test_high_entropy_alphanumeric(self):
        # 50-char base64-shaped string with high entropy.
        token = "K3yX9mP2qR7nF4tH8wL5sB6vC1jZ0aE2dGhJkMnOpQrStUv"
        findings = _scan(f'k = "{token}"')
        assert findings
        assert findings[0]["severity"] == "low"
        assert "entropy_generic" in findings[0]["check_id"]


class TestNegative:
    def test_short_string_below_threshold(self):
        # 16 chars — below MIN_LENGTH (32).
        findings = _scan('id = "abc123def456ghi7"')
        assert not findings

    def test_low_entropy_repeated(self):
        # Long but low entropy (all 'a's).
        findings = _scan('s = "' + "a" * 50 + '"')
        assert not findings

    def test_safe_context_marker_skips(self):
        token = "K3yX9mP2qR7nF4tH8wL5sB6vC1jZ0aE2dGhJkMnOpQrStUv"
        findings = _scan(f'# example: k = "{token}"')
        assert not findings

    def test_comment_only_line_skipped(self):
        token = "K3yX9mP2qR7nF4tH8wL5sB6vC1jZ0aE2dGhJkMnOpQrStUv"
        findings = _scan(f'// just a comment with token {token}')
        assert not findings

    def test_natural_text_below_entropy_threshold(self):
        # Long natural English text — entropy ~3.5-4.0 bits/char,
        # below threshold of 4.5.
        text = "This is a sentence with plenty of words but the entropy is low because English text has predictable letter frequencies."
        findings = _scan(text)
        assert not findings

    def test_punctuation_heavy_string_skipped(self):
        # Long but mostly non-alphanumeric — fails the safe-char ratio.
        s = "!@#$%^&*()" * 4
        findings = _scan(f'x = "{s}"')
        assert not findings


def test_shannon_entropy_value():
    # Sanity-check the entropy calculation
    assert entropy.shannon_entropy("") == 0.0
    assert entropy.shannon_entropy("a" * 100) == 0.0
    # Two distinct chars equally distributed → 1.0 bit/char
    assert abs(entropy.shannon_entropy("ab" * 50) - 1.0) < 0.01
