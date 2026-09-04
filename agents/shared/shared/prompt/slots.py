"""Slot — the only path by which third-party bytes enter a prompt.

Feature 0089 §3.2. There is no f-string path. Markers, the per-request nonce
and the untrusted-content fragment are emitted together or not at all, which
turns five findings across three audit lenses into a type error.

The nonce is per REQUEST, not per run: a per-run token could be learned by an
injected payload from an earlier tool result and then used to forge a closing
marker in a later one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Slot:
    kind: str
    content: str

    @classmethod
    def source(cls, text: str) -> "Slot":
        return cls("SOURCE", text)

    @classmethod
    def code_window(cls, text: str) -> "Slot":
        return cls("CODE", text)

    @classmethod
    def description(cls, text: str) -> "Slot":
        return cls("DESC", text)

    @classmethod
    def http_response(cls, text: str) -> "Slot":
        return cls("RESP", text)

    @classmethod
    def prior_findings(cls, text: str) -> "Slot":
        return cls("PRIOR", text)

    @classmethod
    def tool_result(cls, text: str) -> "Slot":
        return cls("TOOL", text)


def new_nonce() -> str:
    return secrets.token_hex(4)


def scrub(content: str, kind: str, nonce: str) -> str:
    """Neutralise any attempt by the content to close its own marker."""
    closing = f"{kind}:{nonce}>>>"
    return content.replace(closing, closing.replace(">>>", "> >>"))


def wrap(slot: Slot, nonce: str) -> str:
    body = scrub(slot.content, slot.kind, nonce)
    return f"<<<{slot.kind}:{nonce}\n{body}\n{slot.kind}:{nonce}>>>"
