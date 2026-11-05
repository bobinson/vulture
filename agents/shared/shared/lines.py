"""The ONE lenient line-number parser (feature 0074 review item 9).

A leaf module: no imports from ``shared``. Every reader of a line-number-ish
value — the generate parser, the anchor verifier and window stage, the L5
judge and the lineage checks — delegates here, so "no usable line" means the
same thing everywhere and no reader can raise on a value another accepts.
"""

from __future__ import annotations

from typing import Any

__all__ = ["parse_line"]


def parse_line(value: Any, default: int = 0) -> int:
    """``value`` as an int line number, or ``default`` when it is not one.

    A model that returns ``"55"`` must not be silently dropped by Go's
    ``LineStart int`` unmarshal (``agui/finding_parse.go``), so a numeric string
    parses. ``bool`` is not a line (``True`` is an ``int`` and would arrive as
    line 1). NaN and +/-Infinity reach here because ``json.loads`` accepts all
    three; ``int()`` refuses them (ValueError / OverflowError) and that
    exception once escaped and lost a whole batch. Junk costs the LINE, never
    the FINDING. The sign is the caller's business.
    """
    if isinstance(value, bool):
        return default
    try:
        return int(value) if isinstance(value, int | float) else int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return default
