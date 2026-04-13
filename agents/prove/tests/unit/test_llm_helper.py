"""Tests for prove agent LLM helper JSON extraction."""

from prove_agent.llm_helper import _extract_json, _find_balanced_json, _strip_markdown_fences


class TestExtractJsonDirect:
    """Direct JSON parsing — no wrapper text."""

    def test_plain_json(self):
        result = _extract_json('{"url_path": "/api/test", "method": "GET"}')
        assert result == {"url_path": "/api/test", "method": "GET"}

    def test_empty_object(self):
        result = _extract_json("{}")
        assert result == {}

    def test_nested_object(self):
        result = _extract_json('{"headers": {"Content-Type": "application/json"}, "method": "POST"}')
        assert result["headers"]["Content-Type"] == "application/json"

    def test_empty_string(self):
        result = _extract_json("")
        assert result == {}


class TestExtractJsonThinkTags:
    """XML-style <think> tag stripping."""

    def test_think_tags_stripped(self):
        text = '<think>Let me think about this...</think>{"url_path": "/login"}'
        result = _extract_json(text)
        assert result == {"url_path": "/login"}

    def test_multiline_think_tags(self):
        text = (
            "<think>\nStep 1: Analyze the finding\n"
            "Step 2: Build the request\n</think>\n"
            '{"url_path": "/api/users", "method": "POST"}'
        )
        result = _extract_json(text)
        assert result["url_path"] == "/api/users"

    def test_output_tags_stripped(self):
        text = '<output>{"url_path": "/test"}</output>'
        result = _extract_json(text)
        assert result == {"url_path": "/test"}


class TestExtractJsonThinkingPreamble:
    """Text-based thinking preambles (Claude, Gemini, etc.)."""

    def test_thinking_process_preamble(self):
        text = (
            "Thinking Process:\n\n"
            "1. **Analyze the Request:**\n"
            "   * Role: Security Tester.\n"
            "   * Task: Create an HTTP request.\n\n"
            '{"url_path": "/api/login", "method": "POST", '
            '"description": "Test SQL injection"}'
        )
        result = _extract_json(text)
        assert result["url_path"] == "/api/login"
        assert result["method"] == "POST"

    def test_analysis_preamble(self):
        text = (
            "Analysis:\nThe finding describes a hardcoded credential.\n\n"
            '{"url_path": "/api/auth", "method": "GET"}'
        )
        result = _extract_json(text)
        assert result["url_path"] == "/api/auth"

    def test_reasoning_preamble(self):
        text = 'Reasoning: I need to test this endpoint.\n{"url_path": "/health"}'
        result = _extract_json(text)
        assert result["url_path"] == "/health"

    def test_let_me_preamble(self):
        text = 'Let me analyze this security finding...\n{"verdict": "confirmed"}'
        result = _extract_json(text)
        assert result["verdict"] == "confirmed"

    def test_step_by_step_preamble(self):
        text = 'Step-by-Step analysis:\n1. Check the endpoint\n{"url_path": "/test"}'
        result = _extract_json(text)
        assert result["url_path"] == "/test"


class TestExtractJsonMarkdown:
    """Markdown code fence stripping."""

    def test_json_code_fence(self):
        text = '```json\n{"url_path": "/api/test"}\n```'
        result = _extract_json(text)
        assert result == {"url_path": "/api/test"}

    def test_plain_code_fence(self):
        text = '```\n{"method": "POST"}\n```'
        result = _extract_json(text)
        assert result == {"method": "POST"}

    def test_preamble_plus_code_fence(self):
        text = 'Here is the JSON:\n```json\n{"url_path": "/login"}\n```'
        result = _extract_json(text)
        assert result == {"url_path": "/login"}


class TestExtractJsonBalancedBraces:
    """Brace-counting for deeply nested JSON."""

    def test_deeply_nested(self):
        text = (
            'Some text before\n'
            '{"headers": {"Authorization": "Bearer token", "X-Custom": {"nested": true}}, '
            '"method": "GET"}'
        )
        result = _extract_json(text)
        assert result["headers"]["Authorization"] == "Bearer token"
        assert result["headers"]["X-Custom"]["nested"] is True

    def test_json_with_escaped_braces_in_strings(self):
        text = '{"description": "Test {injection} payload", "url_path": "/api"}'
        result = _extract_json(text)
        assert result["url_path"] == "/api"
        assert "{injection}" in result["description"]

    def test_json_after_garbage(self):
        text = 'Not JSON at all. Random text.\n{"found": true}'
        result = _extract_json(text)
        assert result == {"found": True}

    def test_no_json_at_all(self):
        result = _extract_json("This is just plain text with no braces.")
        assert result == {}

    def test_truncated_json(self):
        """When JSON is cut off mid-stream, should return empty."""
        text = '{"url_path": "/api/test", "headers": {"Auth'
        result = _extract_json(text)
        assert result == {}


class TestFindBalancedJson:
    """Unit tests for _find_balanced_json specifically."""

    def test_simple_object(self):
        result = _find_balanced_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_nested_objects(self):
        result = _find_balanced_json('{"a": {"b": {"c": 1}}}')
        assert result == {"a": {"b": {"c": 1}}}

    def test_no_braces(self):
        result = _find_balanced_json("no braces here")
        assert result is None

    def test_unmatched_braces(self):
        result = _find_balanced_json('{"unclosed')
        assert result is None

    def test_braces_in_strings(self):
        result = _find_balanced_json('{"val": "has {braces} inside"}')
        assert result == {"val": "has {braces} inside"}

    def test_escaped_quotes(self):
        result = _find_balanced_json('{"val": "has \\"quotes\\""}')
        assert result == {"val": 'has "quotes"'}

    def test_prefix_text_skipped(self):
        result = _find_balanced_json('prefix text {"found": true} suffix')
        assert result == {"found": True}

    def test_array_values(self):
        result = _find_balanced_json('{"items": [1, 2, 3]}')
        assert result == {"items": [1, 2, 3]}


class TestStripMarkdownFences:
    """Unit tests for _strip_markdown_fences."""

    def test_single_fence(self):
        text = "```json\n{}\n```"
        assert _strip_markdown_fences(text) == "{}"

    def test_no_fences(self):
        text = "no fences here"
        assert _strip_markdown_fences(text) == text

    def test_multiple_lines_in_fence(self):
        text = "```\nline1\nline2\n```"
        assert _strip_markdown_fences(text) == "line1\nline2"
