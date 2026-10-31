"""Feature 0074 (T1): the MCP provenance family rule trims with Go's set.

Every runtime trims a provenance / origin string with exactly Go's
unicode.IsSpace set. Bare ``str.strip()`` is not it: it also strips
U+001C-U+001F, which Go keeps, so a tier Go calls skill-family ("\\x1fllm")
would read as LLM-family here. U+FEFF and U+001C-U+001F are whitespace nowhere.
"""
import pytest

# The code points unicode.IsSpace reports true for, enumerated from Go.
_GO_IS_SPACE = [
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680,
    *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
]


def test_the_constant_is_exactly_gos_set():
    from server import GO_SPACE
    assert sorted(ord(c) for c in GO_SPACE) == _GO_IS_SPACE


@pytest.mark.parametrize("cp", _GO_IS_SPACE)
def test_strips_every_go_space(cp):
    from server import _tier
    ch = chr(cp)
    assert _tier(f"{ch}{ch}LLM{ch}") == "llm"


@pytest.mark.parametrize("ch", ["\ufeff", "\x1c", "\x1d", "\x1e", "\x1f", "\u200b"])
def test_keeps_what_go_does_not_call_space(ch):
    from server import _is_llm_family, _spans_both_families, _tier
    assert _tier(f"{ch}llm{ch}") == f"{ch}llm{ch}"
    assert _is_llm_family({"provenance": f"{ch}llm"}) is False
    assert _spans_both_families({"validation": {"provenance_origins": ["skill", f"{ch}llm"]}}) is False


def test_nel_wrapped_llm_is_llm_family():
    from server import _is_llm_family, _spans_both_families
    assert _is_llm_family({"provenance": "\x85llm\x85"}) is True
    assert _spans_both_families({"validation": {"provenance_origins": ["skill", "\u3000llm"]}}) is True
