"""Unit tests for snippet extraction and context corroboration."""

import re

from shared.tools.snippet import check_context, extract_snippet


class TestExtractSnippet:
    def test_middle_of_file(self):
        lines = ["a", "b", "c", "d", "e"]
        result = extract_snippet(lines, 3, context=1)
        assert "2: b" in result
        assert "3: c" in result
        assert "4: d" in result

    def test_start_of_file(self):
        lines = ["first", "second", "third"]
        result = extract_snippet(lines, 1, context=2)
        assert "1: first" in result
        assert "2: second" in result
        assert "3: third" in result

    def test_end_of_file(self):
        lines = ["a", "b", "c"]
        result = extract_snippet(lines, 3, context=2)
        assert "1: a" in result
        assert "3: c" in result

    def test_truncates_to_200_chars(self):
        lines = ["x" * 50 for _ in range(10)]
        result = extract_snippet(lines, 5, context=4)
        assert len(result) <= 200

    def test_empty_lines(self):
        assert extract_snippet([], 1) == ""

    def test_invalid_line_num(self):
        assert extract_snippet(["a"], 0) == ""
        assert extract_snippet(["a"], -1) == ""

    def test_default_context(self):
        lines = [f"line{i}" for i in range(10)]
        result = extract_snippet(lines, 5)
        # Default context=2, so lines 3-7 (0-indexed: 2-6)
        assert "3: line2" in result
        assert "7: line6" in result

    def test_single_line_file(self):
        result = extract_snippet(["only"], 1, context=2)
        assert result == "1: only"


class TestCheckContext:
    def test_matching_pattern(self):
        content = "import subprocess\nos.system(cmd)"
        patterns = [re.compile(r"subprocess")]
        assert check_context(content, patterns) is True

    def test_no_match(self):
        content = "print('hello')"
        patterns = [re.compile(r"subprocess"), re.compile(r"database")]
        assert check_context(content, patterns) is False

    def test_empty_patterns(self):
        assert check_context("anything", []) is False

    def test_empty_content(self):
        assert check_context("", [re.compile(r"foo")]) is False

    def test_multiple_patterns_any(self):
        content = "from database import connect"
        patterns = [re.compile(r"subprocess"), re.compile(r"database")]
        assert check_context(content, patterns) is True
