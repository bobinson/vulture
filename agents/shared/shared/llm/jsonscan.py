"""Balanced-object scanning over text that is not purely JSON.

TWO CALLERS, ONE SCANNER. Both parse JSON out of a string that also contains
other things, and both get it wrong in the same ways if written carelessly:

  - `validate.llm_judge` reads a verdict object out of a reasoning model's
    reply, which intermittently leaks prose — and prose containing braces —
    around the object.
  - `llm.errors` reads the broker's error envelope out of an exception message,
    because some client libraries keep no structured body and only interpolate
    the response text into the message.

A regex cannot do this. `\\{.*\\}` spans past the end of the first object and
`\\{.*?\\}` stops at the first nested one, so the two obvious patterns fail in
opposite directions, and a brace inside a quoted message defeats both. The scan
below is a single O(n) pass that tracks string state, so a `}` inside a
provider's message cannot end an object.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any


def iter_balanced_objects(text: str) -> Iterator[str]:
    """Yield each top-level balanced ``{...}`` substring of `text`.

    Tracks JSON string literals (double-quoted, with ``\\`` escapes) so braces
    inside strings don't throw off the depth count.
    """
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                yield text[start : i + 1]


def first_json_object(text: str) -> dict[str, Any] | None:
    """The first balanced ``{...}`` in `text` that parses as a JSON object.

    A span that does not parse is skipped rather than fatal: the first braces
    in a message are often prose, and the envelope is further along.
    """
    for span in iter_balanced_objects(text):
        try:
            parsed = json.loads(span)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None
