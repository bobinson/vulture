"""Go's whitespace set — the ONE set every runtime trims with (feature 0074
contract T1).

The backend trims provenance, origin, override and switch strings with
``strings.TrimSpace``, i.e. ``unicode.IsSpace``. Bare ``str.strip()`` is not
that set: it also strips the separators U+001C-U+001F, which Go keeps, so a
tier Go calls skill-family (``"\\x1fllm"``) would read as LLM-family here.
U+FEFF is whitespace nowhere. The frontend and the MCP server hold the same
constant; ``tests/unit/test_0074_go_space.py`` pins it code point by code point.
"""

from __future__ import annotations

__all__ = ["GO_SPACE", "trim_go_space"]

GO_SPACE = ("\t\n\v\f\r \x85\xa0       "
            "         　")


def trim_go_space(value: str) -> str:
    """``strings.TrimSpace``: strip Go's whitespace set from both ends."""
    return value.strip(GO_SPACE)
