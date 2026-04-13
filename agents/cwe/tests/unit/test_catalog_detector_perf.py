"""Performance-focused unit tests for catalog_detector.

Verifies:
- Issue #6: Regex patterns are pre-compiled at module level (not re-compiled per call).
"""

import re

from cwe_agent.skills.catalog_detector import (
    _extract_line_keywords,
    _LINE_KEYWORD_RE,
)


class TestPrecompiledRegex:
    """Issue #6: Verify regex is pre-compiled at module level."""

    def test_line_keyword_re_is_compiled_pattern(self):
        """_LINE_KEYWORD_RE must be a compiled re.Pattern, not a raw string."""
        assert isinstance(_LINE_KEYWORD_RE, re.Pattern), (
            f"Expected compiled re.Pattern, got {type(_LINE_KEYWORD_RE)}"
        )

    def test_line_keyword_re_pattern_matches_identifiers(self):
        """Compiled pattern must match 3+ char identifiers starting with letter or _."""
        matches = _LINE_KEYWORD_RE.findall("def authenticate_user(username, pw):")
        assert "def" in matches
        assert "authenticate_user" in matches
        assert "username" in matches
        # "pw" is only 2 chars, should NOT match
        assert "pw" not in matches

    def test_extract_line_keywords_uses_compiled_regex(self):
        """_extract_line_keywords must produce correct results from the compiled regex."""
        result = _extract_line_keywords("def validate_input(user_data, token):")
        assert "validate_input" in result
        assert "user_data" in result
        assert "token" in result
        # "def" is 3 chars but is not in _GENERIC_TOKENS, so it stays
        # Short words like "if" (2 chars) should not appear
        assert len(result) > 0

    def test_extract_line_keywords_excludes_generic_tokens(self):
        """Generic tokens like 'error', 'value', 'return' must be excluded."""
        result = _extract_line_keywords("return error value function string type")
        # All these are in _GENERIC_TOKENS and should be excluded
        assert "error" not in result
        assert "value" not in result
        assert "return" not in result
        assert "function" not in result
        assert "string" not in result
        assert "type" not in result

    def test_extract_line_keywords_empty_line(self):
        """Empty line produces empty set."""
        assert _extract_line_keywords("") == set()

    def test_extract_line_keywords_only_short_tokens(self):
        """Line with only short tokens (< 3 chars) produces empty set."""
        assert _extract_line_keywords("if x == y:") == set()
