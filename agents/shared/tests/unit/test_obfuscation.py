"""Unit tests for shared.tools.obfuscation — obfuscation detection helpers."""

from pathlib import Path

import pytest

from shared.tools.obfuscation import (
    COMMENT_LINE,
    SAFE_OBFUSCATION_CONTEXT,
    _ALL_PATTERNS,
    check_obfuscation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lines(*raw_lines: str) -> list[str]:
    """Convert raw strings into a list of lines."""
    return list(raw_lines)


# ---------------------------------------------------------------------------
# Pattern 1: base64 decode
# ---------------------------------------------------------------------------

class TestBase64Pattern:
    """Tests for base64-encoded payload detection."""

    def test_b64decode_with_long_payload(self):
        payload = "A" * 120  # >100 chars of base64-like content
        line = f'b64decode("{payload}")'
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.base64_decode"
        assert findings[0]["severity"] == "high"

    def test_atob_with_long_payload(self):
        payload = "Q" * 110
        line = f'atob("{payload}")'
        findings = check_obfuscation(Path("src/app.js"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.base64_decode"

    def test_buffer_from_with_long_payload(self):
        payload = "R" * 105
        line = f'Buffer.from("{payload}", "base64")'
        findings = check_obfuscation(Path("src/decode.js"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.base64_decode"

    def test_short_base64_is_ignored(self):
        line = 'b64decode("aGVsbG8=")'  # short payload, <100 chars
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 2: hex escape sequences
# ---------------------------------------------------------------------------

class TestHexEscapePattern:
    """Tests for hex-escaped byte sequence detection."""

    def test_six_hex_pairs(self):
        line = r's = "\x41\x42\x43\x44\x45\x46"'
        findings = check_obfuscation(Path("src/shell.py"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.hex_escape"

    def test_fewer_than_six_hex_pairs_is_ignored(self):
        line = r's = "\x41\x42\x43"'
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 3: String.fromCharCode
# ---------------------------------------------------------------------------

class TestFromCharCodePattern:
    """Tests for String.fromCharCode obfuscation chain detection."""

    def test_long_from_char_code(self):
        args = ", ".join(str(i) for i in range(65, 85))  # 20 chars worth
        line = f"var s = String.fromCharCode({args});"
        findings = check_obfuscation(Path("src/payload.js"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.fromcharcode"

    def test_short_from_char_code_is_ignored(self):
        line = "String.fromCharCode(65, 66)"  # <20 chars of args
        findings = check_obfuscation(Path("src/app.js"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 4: chr() concatenation
# ---------------------------------------------------------------------------

class TestChrConcatPattern:
    """Tests for chr() concatenation chain detection."""

    def test_three_chr_concat(self):
        line = "s = chr(72) + chr(101) + chr(108)"
        findings = check_obfuscation(Path("src/build.py"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.chr_concat"

    def test_two_chr_concat_is_ignored(self):
        line = "s = chr(72) + chr(101)"
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 5: exec(compile(...))
# ---------------------------------------------------------------------------

class TestExecCompilePattern:
    """Tests for exec(compile(...)) dynamic code execution detection."""

    def test_exec_compile(self):
        line = "exec(compile(source, '<string>', 'exec'))"
        findings = check_obfuscation(Path("src/loader.py"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.exec_compile"

    def test_exec_alone_is_ignored(self):
        line = "exec('print(1)')"
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 6: computed __import__
# ---------------------------------------------------------------------------

class TestComputedImportPattern:
    """Tests for computed __import__(variable) detection."""

    def test_computed_import_with_variable(self):
        line = "__import__(module_name)"
        findings = check_obfuscation(Path("src/plugin.py"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.computed_import"

    def test_string_literal_import_is_ignored(self):
        # String literal should NOT match the computed import regex
        # because the regex requires [a-zA-Z_]\w* (identifier, not quote)
        line = '__import__("os")'
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Pattern 7: eval with string concatenation
# ---------------------------------------------------------------------------

class TestEvalConcatPattern:
    """Tests for eval() with string concatenation detection."""

    def test_eval_concat(self):
        line = 'eval(part1 + part2)'
        findings = check_obfuscation(Path("src/runtime.js"), _make_lines(line), line)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "obfuscation.eval_concat"

    def test_eval_simple_is_ignored(self):
        line = "eval('console.log(42)')"
        findings = check_obfuscation(Path("src/app.js"), _make_lines(line), line)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Comments are skipped
# ---------------------------------------------------------------------------

class TestCommentsSkipped:
    """Test that obfuscation patterns in comments are not flagged."""

    @pytest.mark.parametrize("prefix", [
        "#",
        "//",
        "/*",
        " * ",
        "  # ",
        "<!--",
    ])
    def test_comment_line_skipped(self, prefix):
        payload = "A" * 120
        line = f'{prefix} b64decode("{payload}")'
        findings = check_obfuscation(Path("src/app.py"), _make_lines(line), line)
        assert len(findings) == 0

    def test_comment_regex_matches_expected_prefixes(self):
        assert COMMENT_LINE.match("# comment")
        assert COMMENT_LINE.match("// comment")
        assert COMMENT_LINE.match("/* comment */")
        assert COMMENT_LINE.match(" * middle of block")
        assert COMMENT_LINE.match("<!-- html comment -->")
        assert not COMMENT_LINE.match("normal code")


# ---------------------------------------------------------------------------
# Test files are skipped (SAFE_OBFUSCATION_CONTEXT)
# ---------------------------------------------------------------------------

class TestSafeObfuscationContext:
    """Test that test and example files are skipped entirely."""

    @pytest.mark.parametrize("file_path", [
        "tests/test_crypto.py",
        "src/test_runner.py",
        "examples/example_payload.js",
        "fixtures/mock_data.py",
        "README.md",
        "CHANGELOG.md",
    ])
    def test_safe_context_files_skipped(self, file_path):
        payload = "A" * 120
        line = f'b64decode("{payload}")'
        findings = check_obfuscation(Path(file_path), _make_lines(line), line)
        assert len(findings) == 0

    def test_safe_context_regex_matches(self):
        assert SAFE_OBFUSCATION_CONTEXT.search("test_something.py")
        assert SAFE_OBFUSCATION_CONTEXT.search("path/to/_test.py")
        assert SAFE_OBFUSCATION_CONTEXT.search("example_dir/code.js")
        assert SAFE_OBFUSCATION_CONTEXT.search("fixtures/data.json")
        assert SAFE_OBFUSCATION_CONTEXT.search("mock_server.py")
        assert SAFE_OBFUSCATION_CONTEXT.search("README.md")
        assert SAFE_OBFUSCATION_CONTEXT.search("CHANGELOG.txt")

    def test_non_safe_context_does_not_match(self):
        assert not SAFE_OBFUSCATION_CONTEXT.search("src/app.py")
        assert not SAFE_OBFUSCATION_CONTEXT.search("lib/crypto.js")


# ---------------------------------------------------------------------------
# Clean files produce no findings
# ---------------------------------------------------------------------------

class TestCleanFile:
    """Test that clean source files produce no findings."""

    def test_clean_python_file(self):
        lines = [
            "import os",
            "import sys",
            "",
            "def main():",
            "    print('Hello world')",
            "",
            "if __name__ == '__main__':",
            "    main()",
        ]
        content = "\n".join(lines)
        findings = check_obfuscation(Path("src/main.py"), lines, content)
        assert findings == []

    def test_clean_javascript_file(self):
        lines = [
            "const express = require('express');",
            "const app = express();",
            "app.get('/', (req, res) => res.send('OK'));",
            "app.listen(3000);",
        ]
        content = "\n".join(lines)
        findings = check_obfuscation(Path("src/server.js"), lines, content)
        assert findings == []

    def test_empty_file(self):
        findings = check_obfuscation(Path("src/empty.py"), [], "")
        assert findings == []


# ---------------------------------------------------------------------------
# Finding structure validation
# ---------------------------------------------------------------------------

class TestFindingStructure:
    """Verify finding dicts have all required fields."""

    def test_finding_has_all_fields(self):
        line = "exec(compile(code, 'x', 'exec'))"
        findings = check_obfuscation(Path("src/run.py"), _make_lines(line), line)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        assert f["category"] == "obfuscation"
        assert "title" in f
        assert "description" in f
        assert f["file_path"] == "src/run.py"
        assert f["line_start"] == 1
        assert f["line_end"] == 1
        assert "recommendation" in f
        assert "code_snippet" in f
        assert f["check_id"].startswith("obfuscation.")

    def test_one_finding_per_line(self):
        """Even if multiple patterns match a line, only one finding is emitted."""
        # eval with concat also contains eval, but only one should fire
        line = 'eval(chr(65) + chr(66) + chr(67))'
        findings = check_obfuscation(Path("src/evil.py"), _make_lines(line), line)
        assert len(findings) == 1  # break in inner loop ensures this


# ---------------------------------------------------------------------------
# All 7 patterns are registered
# ---------------------------------------------------------------------------

class TestAllPatterns:
    """Verify the _ALL_PATTERNS list covers all 7 patterns."""

    def test_seven_patterns_registered(self):
        assert len(_ALL_PATTERNS) == 7

    def test_pattern_tags_are_unique(self):
        tags = [tag for _, _, tag in _ALL_PATTERNS]
        assert len(tags) == len(set(tags))

    def test_expected_tags_present(self):
        tags = {tag for _, _, tag in _ALL_PATTERNS}
        expected = {
            "base64_decode", "hex_escape", "fromcharcode",
            "chr_concat", "exec_compile", "computed_import", "eval_concat",
        }
        assert tags == expected
