"""PR4 — depth-aware argument tokeniser (``cwe_agent/skills/_args.py``).

A rule that cares about an argument POSITION cannot use ``[^,]+`` / ``[^)]*``
as a stand-in for "the arguments I don't care about": the stand-in stops at the
first comma anywhere, so a later capture group slides onto a literal belonging
to an EARLIER argument. The measured instance::

    createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv)

matched an IV-position rule on the ``'hex'`` inside the KEY expression — and
``Buffer.from(k, 'hex')`` is how most code materialises a key, so the dominant
safe idiom became a finding.

These tests pin (a) the tokeniser's contract — top-level commas only, honouring
``()``/``[]``/``{}`` nesting and single/double/backtick quotes with escapes —
and (b) the two behavioural consequences in ``crypto_check``: the key idiom is
silent, and a genuine literal IV in the same call shape still fires.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills._args import (
    arg_slot,
    call_span_end,
    mask_literals,
    split_arguments,
    split_call_args,
    strip_kwarg_prefix,
)
from cwe_agent.skills.crypto_check import check_cryptography


def _crypto(name: str, body: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / name).write_text(body)
        return check_cryptography(d)["findings"]


def _of(findings: list[dict], *cwes: int) -> list[dict]:
    want = {f"CWE-{c}" for c in cwes}
    return [f for f in findings if f.get("category") in want]


# ── the tokeniser's contract ──────────────────────────────────────────


class TestSplitArgumentsShapes:
    """``split_arguments`` accepts a call, a parenthesised list or a bare list."""

    def test_whole_call(self) -> None:
        assert split_arguments("f(a, b)") == ["a", "b"]

    def test_parenthesised_list(self) -> None:
        assert split_arguments("(a, b)") == ["a", "b"]

    def test_bare_list(self) -> None:
        assert split_arguments("a, b") == ["a", "b"]

    def test_dotted_callee(self) -> None:
        assert split_arguments("crypto.createCipheriv(a, b, c)") == ["a", "b", "c"]

    def test_new_expression(self) -> None:
        assert split_arguments("new GCMParameterSpec(128, nonce)") == ["128", "nonce"]

    def test_no_arguments(self) -> None:
        assert split_arguments("f()") == []

    def test_single_argument(self) -> None:
        assert split_arguments("f(x)") == ["x"]

    def test_slots_are_trimmed(self) -> None:
        assert split_arguments("f(  a ,\tb  )") == ["a", "b"]

    def test_bare_list_whose_member_is_a_call(self) -> None:
        """The inner `(` is not the wrapper: `a, f(b, c)` is two slots."""
        assert split_arguments("a, f(b, c)") == ["a", "f(b, c)"]

    def test_unterminated_call_is_tokenised_as_far_as_it_goes(self) -> None:
        assert split_arguments("f(a, b") == ["a", "b"]

    def test_is_pure(self) -> None:
        text = "f(a, g(b, c))"
        first = split_arguments(text)
        assert split_arguments(text) == first
        assert text == "f(a, g(b, c))"


class TestSplitArgumentsNesting:
    """Commas inside brackets or quotes never separate slots."""

    def test_nested_call_keeps_one_slot(self) -> None:
        text = "createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv)"
        assert split_arguments(text) == [
            "'aes-256-cbc'", "Buffer.from(keyHex, 'hex')", "iv",
        ]

    def test_square_brackets(self) -> None:
        assert split_arguments("f([1, 2, 3], x)") == ["[1, 2, 3]", "x"]

    def test_braces(self) -> None:
        assert split_arguments("f({a: 1, b: 2}, x)") == ["{a: 1, b: 2}", "x"]

    def test_mixed_nesting(self) -> None:
        text = "f(g([1, {k: h(2, 3)}]), y)"
        assert split_arguments(text) == ["g([1, {k: h(2, 3)}])", "y"]

    def test_comma_in_single_quoted_literal(self) -> None:
        assert split_arguments("f('a,b', c)") == ["'a,b'", "c"]

    def test_comma_in_double_quoted_literal(self) -> None:
        assert split_arguments('f("a,b", c)') == ['"a,b"', "c"]

    def test_comma_in_backtick_literal(self) -> None:
        assert split_arguments("f(`a,b`, c)") == ["`a,b`", "c"]

    def test_escaped_quote_does_not_end_the_literal(self) -> None:
        assert split_arguments(r"f('it\'s, fine', x)") == [r"'it\'s, fine'", "x"]

    def test_unbalanced_bracket_inside_a_literal(self) -> None:
        """A `(` in a literal must not open a nesting level."""
        assert split_arguments('f("(", a, b)') == ['"("', "a", "b"]

    def test_mask_preserves_length_and_offsets(self) -> None:
        text = "f('a,b', c)"
        masked = mask_literals(text)
        assert len(masked) == len(text)
        assert masked.index(",", 3) == text.index(",", 7)


class TestSlotHelpers:
    """Slot access, keyword-argument prefixes and call extents."""

    def test_arg_slot_reads_a_position(self) -> None:
        assert arg_slot(split_arguments("f(a, b, c)"), 2) == "c"

    def test_arg_slot_out_of_range(self) -> None:
        assert arg_slot(split_arguments("f(a)"), 3) is None

    def test_arg_slot_none_index(self) -> None:
        assert arg_slot(["a"], None) is None

    def test_keyword_prefix_is_stripped(self) -> None:
        args = split_arguments('AES.new(key, AES.MODE_CBC, iv="0123456789abcdef")')
        assert arg_slot(args, 2) == '"0123456789abcdef"'

    def test_comparison_is_not_a_keyword_prefix(self) -> None:
        assert strip_kwarg_prefix("a == b") == "a == b"

    def test_split_call_args_requires_the_call_to_close(self) -> None:
        assert split_call_args("f(a, b", 1) is None
        assert split_call_args("f(a, b)", 1) == ["a", "b"]

    def test_call_span_end_points_at_the_closing_bracket(self) -> None:
        text = 'x = "iv".getBytes(Charset.forName("UTF-8"))'
        end = call_span_end(text, text.index("(", text.index("getBytes")))
        assert end == len(text) - 1

    def test_call_span_end_none_when_unclosed(self) -> None:
        assert call_span_end("f(a, b", 1) is None


# ── the behavioural consequence in crypto_check ───────────────────────


class TestKeyIdiomIsNotAnIv:
    """The FP class, and its clean twin."""

    def test_hex_key_buffer_is_not_a_static_iv(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);\n"
        assert _of(_crypto("enc.js", body), 329, 323) == []

    def test_hex_key_buffer_with_an_aead_mode_is_not_a_nonce_reuse(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), nonce);\n"
        assert _of(_crypto("enc.js", body), 329, 323) == []

    def test_literal_iv_still_fires(self) -> None:
        body = "const c = crypto.createCipheriv('aes-256-cbc', keyBuf, '1234567890123456');\n"
        assert [f["category"] for f in _of(_crypto("enc.js", body), 329, 323)] == ["CWE-329"]

    def test_literal_iv_beside_a_hex_key_buffer_still_fires(self) -> None:
        """Tokenising must not over-suppress: the same nested key expression
        with a genuinely hardcoded IV is still one CWE-329 row."""
        body = (
            "const c = crypto.createCipheriv('aes-256-cbc', "
            "Buffer.from(keyHex, 'hex'), '1234567890123456');\n"
        )
        assert [f["category"] for f in _of(_crypto("enc.js", body), 329, 323)] == ["CWE-329"]

    def test_literal_nonce_beside_a_hex_key_buffer_is_an_aead_row(self) -> None:
        body = (
            "const c = crypto.createCipheriv('chacha20-poly1305', "
            "Buffer.from(keyHex, 'hex'), '123456789012');\n"
        )
        assert [f["category"] for f in _of(_crypto("enc.js", body), 329, 323)] == ["CWE-323"]


class TestConversionWrappedLiteral:
    """A charset conversion does not launder a hardcoded IV."""

    _JCE_HEAD = 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'

    def test_literal_iv_with_a_nested_charset_call(self) -> None:
        body = self._JCE_HEAD + (
            'IvParameterSpec s = new IvParameterSpec('
            '"0123456789abcdef".getBytes(Charset.forName("UTF-8")));\n'
        )
        assert _of(_crypto("Enc.java", body), 329)

    def test_random_iv_with_the_same_charset_call_shape(self) -> None:
        body = self._JCE_HEAD + "IvParameterSpec s = new IvParameterSpec(ivBytes);\n"
        assert _of(_crypto("Enc.java", body), 329) == []


class TestGenerateKeyBitSlot:
    """Go `rsa.GenerateKey(reader, bits)`: the size is a SLOT, not a suffix."""

    def test_weak_bit_slot_fires(self) -> None:
        body = "\tpriv, err := rsa.GenerateKey(rand.Reader, 1024)\n"
        assert _of(_crypto("keys.go", body), 326)

    def test_strong_bit_slot_is_silent(self) -> None:
        body = "\tpriv, err := rsa.GenerateKey(rand.Reader, 4096)\n"
        assert _of(_crypto("keys.go", body), 326) == []

    def test_weak_number_inside_the_reader_argument_is_not_the_key_size(self) -> None:
        """The `[^,]+` reader stand-in read this line's `1024` as the bit size."""
        body = "\tpriv, err := rsa.GenerateKey(newReader(seed, 1024), 4096)\n"
        assert _of(_crypto("keys.go", body), 326) == []
