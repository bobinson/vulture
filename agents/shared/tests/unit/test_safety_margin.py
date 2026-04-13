"""Unit tests for safe_estimate_tokens, _SAFETY_MARGIN, build_prior_context truncation, and port filtering."""

from unittest.mock import patch

import pytest

from shared.tools.memory_client import (
    _SAFETY_MARGIN,
    build_prior_context,
    estimate_tokens,
    safe_estimate_tokens,
)
from shared.tools.snippet import STANDARD_PORTS, is_standard_port


# ---------------------------------------------------------------------------
# safe_estimate_tokens returns value > estimate_tokens for same input
# ---------------------------------------------------------------------------

class TestSafeEstimateTokens:
    """Test that safe_estimate_tokens is strictly greater than estimate_tokens."""

    def test_safe_greater_than_basic_for_normal_text(self):
        text = "This is a normal sentence with some words in it."
        basic = estimate_tokens(text)
        safe = safe_estimate_tokens(text)
        assert safe > basic

    def test_safe_greater_than_basic_for_code(self):
        text = "def foo(x):\n    return x + 1\n\nresult = foo(42)"
        basic = estimate_tokens(text)
        safe = safe_estimate_tokens(text)
        assert safe > basic

    def test_safe_greater_than_basic_for_long_text(self):
        text = "x" * 10000
        basic = estimate_tokens(text)
        safe = safe_estimate_tokens(text)
        assert safe > basic

    def test_safe_estimate_ratio_has_margin(self):
        text = "a" * 1000  # known length for predictable results
        basic = estimate_tokens(text)
        safe = safe_estimate_tokens(text)
        # safe / basic should exceed 1.0 (safety margin applied)
        ratio = safe / basic
        # tiktoken uses 1.1x margin, heuristic uses _SAFETY_MARGIN (1.2x)
        assert 1.05 < ratio <= _SAFETY_MARGIN + 0.05

    def test_safe_estimate_minimum_is_1(self):
        assert safe_estimate_tokens("") >= 1
        assert safe_estimate_tokens("a") >= 1

    def test_estimate_tokens_minimum_is_1(self):
        assert estimate_tokens("") >= 1
        assert estimate_tokens("x") >= 1


# ---------------------------------------------------------------------------
# _SAFETY_MARGIN constant
# ---------------------------------------------------------------------------

class TestSafetyMarginConstant:
    """Test that the default safety margin is 1.2."""

    def test_default_value_is_1_2(self):
        assert _SAFETY_MARGIN == pytest.approx(1.2)

    def test_margin_is_float(self):
        assert isinstance(_SAFETY_MARGIN, float)

    def test_margin_greater_than_1(self):
        assert _SAFETY_MARGIN > 1.0


# ---------------------------------------------------------------------------
# build_prior_context truncation when max_chars is exceeded
# ---------------------------------------------------------------------------

class TestBuildPriorContextTruncation:
    """Test that build_prior_context respects the max_chars budget."""

    @staticmethod
    def _make_preloaded(count: int) -> list[dict]:
        """Create preloaded findings for testing."""
        findings = []
        for i in range(count):
            findings.append({
                "title": f"Finding number {i} with a medium-length title for testing",
                "severity": "high" if i % 3 == 0 else "medium",
                "category": "security",
                "file_path": f"src/module_{i}.py",
                "remediation_status": "open",
                "confidence_score": 0.8,
                "created_at": "2026-01-15T10:00:00Z",
            })
        return findings

    @patch("shared.tools.memory_client.memory_get_context")
    def test_truncation_respects_max_chars(self, mock_ctx):
        """When max_chars is small, output should be truncated."""
        preloaded = self._make_preloaded(20)
        result = build_prior_context(
            "/some/path",
            "cwe",
            preloaded=preloaded,
            max_chars=200,
        )
        assert len(result) <= 200 + 80  # allow for footer line slack

    @patch("shared.tools.memory_client.memory_get_context")
    def test_full_output_when_max_chars_large(self, mock_ctx):
        """When max_chars is large, all findings should be included."""
        preloaded = self._make_preloaded(5)
        result = build_prior_context(
            "/some/path",
            "cwe",
            preloaded=preloaded,
            max_chars=50000,
        )
        assert "Known issues" in result
        # Should contain at least some findings
        assert result.count("\n") >= 2

    @patch("shared.tools.memory_client.memory_get_context")
    def test_truncated_output_includes_header(self, mock_ctx):
        """Even truncated output should include the header line."""
        preloaded = self._make_preloaded(20)
        result = build_prior_context(
            "/some/path",
            "cwe",
            preloaded=preloaded,
            max_chars=100,
        )
        assert result.startswith("Known issues")

    @patch("shared.tools.memory_client.memory_get_context")
    def test_truncated_output_includes_footer(self, mock_ctx):
        """Truncated output should indicate remaining findings."""
        preloaded = self._make_preloaded(20)
        result = build_prior_context(
            "/some/path",
            "cwe",
            preloaded=preloaded,
            max_chars=300,
        )
        # Should have either "...and N more" or "Skip known issues"
        assert "Skip known issues" in result or "more" in result

    @patch("shared.tools.memory_client.memory_get_context")
    def test_empty_preloaded_returns_empty_string(self, mock_ctx):
        result = build_prior_context("/some/path", "cwe", preloaded=[])
        assert result == ""

    @patch("shared.tools.memory_client.memory_get_context")
    def test_none_preloaded_calls_api(self, mock_ctx):
        mock_ctx.return_value = []
        result = build_prior_context("/some/path", "cwe", preloaded=None, max_chars=5000)
        assert result == ""
        mock_ctx.assert_called_once()


# ---------------------------------------------------------------------------
# Port-aware filtering: is_standard_port
# ---------------------------------------------------------------------------

class TestIsStandardPort:
    """Test is_standard_port returns True for well-known ports."""

    @pytest.mark.parametrize("port", [80, 443, 8080, 8443, 3000, 3001, 5000, 8000, 8888])
    def test_standard_ports_return_true(self, port):
        assert is_standard_port(port) is True

    @pytest.mark.parametrize("port", [9999, 1234, 4567, 31337, 6666, 12345, 22, 21])
    def test_non_standard_ports_return_false(self, port):
        assert is_standard_port(port) is False

    def test_standard_ports_set_has_expected_members(self):
        assert 80 in STANDARD_PORTS
        assert 443 in STANDARD_PORTS
        assert 8080 in STANDARD_PORTS
        assert 9999 not in STANDARD_PORTS

    def test_port_zero_is_not_standard(self):
        assert is_standard_port(0) is False

    def test_negative_port_is_not_standard(self):
        assert is_standard_port(-1) is False
