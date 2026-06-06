"""Performance-focused unit tests for audit_runner.

Verifies:
- Issue #18: _safe_stat_size uses single syscall (try/except) instead of exists()+stat().
- Issue #19: _collect_llm_findings uses asyncio.run() instead of new_event_loop().
- Issue #21: _emit_token_savings accepts pre-split lines to avoid redundant splitting.
"""

from pathlib import Path
from unittest.mock import MagicMock


from shared.audit_runner import (
    _emit_token_savings,
    _parse_known_titles,
    _prioritize_files,
    _safe_stat_size,
)
from shared.transport.event_emitter import AgUiEventEmitter


class TestSafeStatSize:
    """Issue #18: Single syscall for file size via try/except."""

    def test_returns_size_for_existing_file(self, tmp_path):
        """_safe_stat_size returns actual size for a real file."""
        f = tmp_path / "test.py"
        f.write_text("hello world")
        size = _safe_stat_size(f)
        assert size == len("hello world")

    def test_returns_zero_for_missing_file(self, tmp_path):
        """_safe_stat_size returns 0 for a nonexistent path (no crash)."""
        missing = tmp_path / "nonexistent.py"
        assert _safe_stat_size(missing) == 0

    def test_single_syscall_not_two(self, tmp_path):
        """_safe_stat_size must NOT call both .exists() and .stat()."""
        f = tmp_path / "test.py"
        f.write_text("data")
        mock_path = MagicMock(spec=Path)
        mock_path.stat.return_value = MagicMock(st_size=42)
        result = _safe_stat_size(mock_path)
        assert result == 42
        mock_path.stat.assert_called_once()
        # exists() must NOT be called -- that was the redundant second syscall
        mock_path.exists.assert_not_called()

    def test_handles_oserror_gracefully(self):
        """_safe_stat_size catches OSError and returns 0."""
        mock_path = MagicMock(spec=Path)
        mock_path.stat.side_effect = OSError("permission denied")
        assert _safe_stat_size(mock_path) == 0


class TestPrioritizeFilesStatEfficiency:
    """Issue #18: _prioritize_files uses _safe_stat_size (one syscall per file)."""

    def test_tier3_sorted_by_size(self, tmp_path):
        """tier3 files are sorted ascending by size."""
        big = tmp_path / "big.py"
        big.write_text("x" * 1000)
        small = tmp_path / "small.py"
        small.write_text("x" * 10)
        medium = tmp_path / "medium.py"
        medium.write_text("x" * 100)

        result = _prioritize_files([big, small, medium], str(tmp_path))
        # All three are tier3 (no findings, not entry/config)
        assert result == [small, medium, big]

    def test_missing_files_sorted_first(self, tmp_path):
        """Files that don't exist (size 0) sort before real files."""
        real = tmp_path / "real.py"
        real.write_text("some content here")
        missing = tmp_path / "gone.py"
        # gone.py does not exist on disk

        result = _prioritize_files([real, missing], str(tmp_path))
        assert result[0] == missing  # size 0 sorts first
        assert result[1] == real


class TestCollectLlmFindingsAsyncioRun:
    """Issue #19: _collect_llm_findings uses asyncio.run() not new_event_loop()."""

    def test_no_new_event_loop_call(self):
        """The _collect_llm_findings function must not call asyncio.new_event_loop()."""
        import inspect
        from shared.audit_runner import _collect_llm_findings
        source = inspect.getsource(_collect_llm_findings)
        assert "new_event_loop" not in source, (
            "_collect_llm_findings still uses asyncio.new_event_loop() -- "
            "should use asyncio.run()"
        )

    def test_uses_asyncio_run(self):
        """The _collect_llm_findings function must use asyncio.run()."""
        import inspect
        from shared.audit_runner import _collect_llm_findings
        source = inspect.getsource(_collect_llm_findings)
        assert "asyncio.run(" in source, (
            "_collect_llm_findings does not use asyncio.run()"
        )


class TestEmitTokenSavingsPreSplitLines:
    """Issue #21: _emit_token_savings accepts pre-split lines."""

    def test_accepts_pre_split_lines(self):
        """_emit_token_savings must accept a prior_lines parameter (list[str])."""
        emitter = AgUiEventEmitter("test-run")
        context = " H:[auth] Weak Auth @auth.py\n H:[crypto] Weak Crypto @crypto.py"
        lines = context.split("\n")
        # Should work with prior_lines kwarg to avoid re-splitting
        result = _emit_token_savings(emitter, context, prior_lines=lines)
        assert result is not None

    def test_prior_lines_none_still_works(self):
        """When prior_lines is None, function splits context internally."""
        emitter = AgUiEventEmitter("test-run")
        context = " H:[auth] Weak Auth @auth.py"
        result = _emit_token_savings(emitter, context)
        assert result is not None

    def test_empty_context_returns_none(self):
        """Empty context returns None regardless of prior_lines."""
        emitter = AgUiEventEmitter("test-run")
        assert _emit_token_savings(emitter, "") is None
        assert _emit_token_savings(emitter, "", prior_lines=[]) is None


class TestParseKnownTitlesPreSplitLines:
    """Issue #21: _parse_known_titles accepts pre-split lines."""

    def test_accepts_prior_lines_parameter(self):
        """_parse_known_titles must accept a prior_lines parameter."""
        context = " C:[injection] SQL Injection @db.py\n H:[auth] Weak Auth @auth.py"
        lines = context.split("\n")
        result = _parse_known_titles(prior_context=context, prior_lines=lines)
        assert "sql injection" in result

    def test_prior_lines_none_still_works(self):
        """When prior_lines is None, function splits context internally."""
        context = " C:[injection] SQL Injection @db.py"
        result = _parse_known_titles(prior_context=context)
        assert "sql injection" in result

    def test_empty_returns_empty_set(self):
        """Empty prior_context returns empty set."""
        assert _parse_known_titles("") == set()
        assert _parse_known_titles("", prior_lines=[]) == set()
