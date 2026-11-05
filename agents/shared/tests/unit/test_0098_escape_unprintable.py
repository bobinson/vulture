"""Unit contract: ``escape_unprintable`` makes text safe to print (feature 0098).

The offline gate prints file names, titles and error text to a terminal. A name
can carry an escape sequence, a carriage return, a bidi override or an
undecodable byte (a lone surrogate), any of which can rewrite what the reader
sees or fail to encode. Each must come out as a visible escape; everything else
is unchanged.
"""

from __future__ import annotations

import pytest

from shared.llm.errors import escape_unprintable


@pytest.mark.parametrize(("raw", "shown"), [
    ("mw\x1b[2K\rok.py", "mw\\x1b[2K\\rok.py"),
    ("bell\x07", "bell\\x07"),
    ("del\x7f", "del\\x7f"),
    ("c1\x9b31m", "c1\\x9b31m"),
    ("rlo\u202eyp.exe", "rlo\\u202eyp.exe"),
    ("lrm\u200e.py", "lrm\\u200e.py"),
    ("rlm\u200f.py", "rlm\\u200f.py"),
    ("zw\u200bsp", "zw\\u200bsp"),
    ("bad\udcff.py", "bad\\udcff.py"),
    ("tab\tnew\nline", "tab\\tnew\\nline"),
    # Every Bidi_Control character, and the other invisible format and
    # line-separator characters (reviewer R12).
    ("alm\u061c.py", "alm\\u061c.py"),
    ("ls\u2028ps\u2029", "ls\\u2028ps\\u2029"),
    ("wj\u2060x\u2064", "wj\\u2060x\\u2064"),
    ("shy\u00ad", "shy\\xad"),
    ("mvs\u180e", "mvs\\u180e"),
    ("lri\u2066pdi\u2069", "lri\\u2066pdi\\u2069"),
])
def test_escape_unprintable_covers_controls_bidi_and_surrogates(raw: str, shown: str) -> None:
    out = escape_unprintable(raw)

    assert out == shown
    out.encode("utf-8")  # never fails to encode


@pytest.mark.parametrize("text", ["plain.py", "naïve/日本語.py", "a b-c_d.e", ""])
def test_printable_text_is_unchanged(text: str) -> None:
    assert escape_unprintable(text) == text
