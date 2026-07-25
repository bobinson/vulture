"""Unit tests for shared.tools.suppression — false positive suppression lists."""

import re
from pathlib import Path


from shared.tools.suppression import (
    AUTH_CHECK_SUPPRESSIONS,
    INFO_EXPOSURE_SUPPRESSIONS,
    MAX_SUPPRESSIONS_PER_RULE,
    SuppressionRule,
    should_suppress,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(title_re: str, file_glob: str = "", line_re: str | None = None) -> SuppressionRule:
    """Create a SuppressionRule with compiled patterns."""
    return SuppressionRule(
        title_pattern=re.compile(title_re, re.I),
        file_glob=file_glob,
        line_pattern=re.compile(line_re, re.I) if line_re else None,
    )


# ---------------------------------------------------------------------------
# Basic suppression matching
# ---------------------------------------------------------------------------

class TestBasicSuppression:
    """Test core should_suppress logic with title, file_glob, and line_pattern."""

    def test_title_match_only(self):
        rules = [_rule(r"SQL Injection")]
        counts: dict[int, int] = {}
        result = should_suppress("SQL Injection in login", Path("src/db.py"), "query = ...", rules, counts)
        assert result is True
        assert counts[0] == 1

    def test_title_no_match(self):
        rules = [_rule(r"SQL Injection")]
        counts: dict[int, int] = {}
        result = should_suppress("XSS in template", Path("src/db.py"), "query = ...", rules, counts)
        assert result is False
        assert len(counts) == 0

    def test_title_and_file_glob_match(self):
        rules = [_rule(r"Hardcoded", "*/test*")]
        counts: dict[int, int] = {}
        result = should_suppress("Hardcoded password", Path("src/test_auth.py"), "pass = ...", rules, counts)
        assert result is True

    def test_title_matches_but_file_glob_does_not(self):
        rules = [_rule(r"Hardcoded", "*/test*")]
        counts: dict[int, int] = {}
        result = should_suppress("Hardcoded password", Path("src/auth.py"), "pass = ...", rules, counts)
        assert result is False

    def test_title_and_file_and_line_all_match(self):
        rules = [_rule(r"Sensitive data", "*/test*", r"test_|mock_")]
        counts: dict[int, int] = {}
        result = should_suppress(
            "Sensitive data written to log",
            Path("src/test_logging.py"),
            "test_password = 'fake'",
            rules,
            counts,
        )
        assert result is True

    def test_title_and_file_match_but_line_does_not(self):
        rules = [_rule(r"Sensitive data", "*/test*", r"test_|mock_")]
        counts: dict[int, int] = {}
        result = should_suppress(
            "Sensitive data written to log",
            Path("src/test_logging.py"),
            "real_password = 'secret'",
            rules,
            counts,
        )
        assert result is False

    def test_empty_file_glob_matches_any_path(self):
        rules = [_rule(r"Hardcoded", "")]
        counts: dict[int, int] = {}
        # Empty file_glob means the rule.file_glob is falsy, so glob check is skipped
        result = should_suppress("Hardcoded key", Path("any/path.py"), "key = ...", rules, counts)
        assert result is True

    def test_none_line_pattern_matches_any_line(self):
        rules = [_rule(r"Cleartext", "*/docs/*", None)]
        counts: dict[int, int] = {}
        result = should_suppress("Cleartext storage", Path("src/docs/readme.md"), "anything", rules, counts)
        assert result is True


# ---------------------------------------------------------------------------
# MAX_SUPPRESSIONS_PER_RULE limit
# ---------------------------------------------------------------------------

class TestMaxSuppressionsPerRule:
    """Test that the per-rule suppression count cap works correctly."""

    def test_suppression_stops_at_limit(self):
        rules = [_rule(r"SQL Injection")]
        counts: dict[int, int] = {}

        # Fire the rule MAX_SUPPRESSIONS_PER_RULE times
        for i in range(MAX_SUPPRESSIONS_PER_RULE):
            result = should_suppress(
                "SQL Injection in handler",
                Path(f"src/handler_{i}.py"),
                "query = ...",
                rules,
                counts,
            )
            assert result is True, f"Should suppress on iteration {i}"
        assert counts[0] == MAX_SUPPRESSIONS_PER_RULE

        # The (MAX+1)th time, suppression should be refused
        result = should_suppress(
            "SQL Injection in handler",
            Path("src/handler_extra.py"),
            "query = ...",
            rules,
            counts,
        )
        assert result is False
        # Count should remain at MAX (not incremented)
        assert counts[0] == MAX_SUPPRESSIONS_PER_RULE

    def test_max_suppressions_constant_is_50(self):
        assert MAX_SUPPRESSIONS_PER_RULE == 50

    def test_different_rules_have_independent_counts(self):
        rules = [_rule(r"SQL Injection"), _rule(r"XSS")]
        counts: dict[int, int] = {}

        # Fire rule 0 once
        should_suppress("SQL Injection", Path("a.py"), "", rules, counts)
        # Fire rule 1 once
        should_suppress("XSS attack", Path("b.py"), "", rules, counts)

        assert counts[0] == 1
        assert counts[1] == 1


# ---------------------------------------------------------------------------
# Non-matching rules
# ---------------------------------------------------------------------------

class TestNonMatchingRules:
    """Test that unrelated rules do not suppress findings."""

    def test_no_rules_means_no_suppression(self):
        counts: dict[int, int] = {}
        result = should_suppress("Anything", Path("src/file.py"), "code", [], counts)
        assert result is False

    def test_unrelated_rules_do_not_suppress(self):
        rules = [
            _rule(r"Buffer overflow"),
            _rule(r"Memory leak"),
        ]
        counts: dict[int, int] = {}
        result = should_suppress("SQL Injection", Path("src/db.py"), "query", rules, counts)
        assert result is False
        assert len(counts) == 0

    def test_first_matching_rule_wins(self):
        rules = [
            _rule(r"Hardcoded"),  # rule 0 - matches
            _rule(r"Hardcoded"),  # rule 1 - also matches but won't fire
        ]
        counts: dict[int, int] = {}
        should_suppress("Hardcoded secret", Path("src/config.py"), "", rules, counts)
        assert counts.get(0) == 1
        assert counts.get(1) is None  # second rule was never reached


# ---------------------------------------------------------------------------
# Pre-built INFO_EXPOSURE_SUPPRESSIONS
# ---------------------------------------------------------------------------

class TestInfoExposureSuppressions:
    """Test the pre-built INFO_EXPOSURE_SUPPRESSIONS list."""

    def test_has_rules(self):
        assert len(INFO_EXPOSURE_SUPPRESSIONS) >= 1

    def test_sensitive_log_in_test_file_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Sensitive data written to log output",
            Path("src/tests/test_auth.py"),
            "test_password = 'fake'",
            INFO_EXPOSURE_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_sensitive_log_in_production_file_not_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Sensitive data written to log output",
            Path("src/auth.py"),
            "logger.info(password)",
            INFO_EXPOSURE_SUPPRESSIONS,
            counts,
        )
        assert result is False

    def test_cleartext_in_example_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Cleartext storage of secrets",
            Path("src/examples/config.py"),
            "api_key = 'demo'",
            INFO_EXPOSURE_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_cleartext_in_docs_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Cleartext storage detected",
            Path("project/docs/guide.md"),
            "api_key = 'example'",
            INFO_EXPOSURE_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_cleartext_in_production_not_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Cleartext storage of secrets",
            Path("src/config.py"),
            "api_key = 'real-secret'",
            INFO_EXPOSURE_SUPPRESSIONS,
            counts,
        )
        assert result is False


# ---------------------------------------------------------------------------
# Pre-built AUTH_CHECK_SUPPRESSIONS
# ---------------------------------------------------------------------------

class TestAuthCheckSuppressions:
    """Test the pre-built AUTH_CHECK_SUPPRESSIONS list."""

    def test_has_rules(self):
        assert len(AUTH_CHECK_SUPPRESSIONS) >= 1

    def test_hardcoded_creds_in_test_with_test_prefix(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials in source",
            Path("src/tests/test_login.py"),
            "test_password = 'fake123'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_hardcoded_creds_in_test_with_mock_prefix(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials detected",
            Path("src/tests/test_auth.py"),
            "mock_secret = 'test'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_hardcoded_creds_in_production_not_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials in source",
            Path("src/auth.py"),
            "password = 'admin123'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is False

    def test_example_annotation_suppresses_anywhere(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials in config",
            Path("src/config.py"),
            "example: password = 'demo'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_sample_annotation_suppresses(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials found",
            Path("src/settings.py"),
            "sample = 'test-key-123'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is True

    def test_non_annotated_production_creds_not_suppressed(self):
        counts: dict[int, int] = {}
        result = should_suppress(
            "Hardcoded credentials in source",
            Path("src/config.py"),
            "api_key = 'sk-live-real-key'",
            AUTH_CHECK_SUPPRESSIONS,
            counts,
        )
        assert result is False
