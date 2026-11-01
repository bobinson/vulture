"""SSE writer for the vulture-plugin/1.0 contract.

Each plugin needs to emit a small fixed set of events on the same SSE
stream shape Vulture's backend already parses. This module is the
canonical writer for bundled plugins; community plugins copy it
verbatim — that is the intended pattern documented in the contract
spec.
"""

from __future__ import annotations

import json
from typing import Any


def write_event(event_name: str, data: dict | list | None = None) -> bytes:
    """Format one SSE event in vulture-plugin/1.0 shape.

    Returns bytes ready to write to the SSE stream. Always emits
    ``event:``, ``data:`` (JSON-encoded), and the terminating blank
    line required by the SSE spec.
    """
    payload: Any = {} if data is None else data
    body = json.dumps(payload)
    return f"event: {event_name}\ndata: {body}\n\n".encode("utf-8")
