"""Slot — the only path by which third-party bytes enter a prompt.

Feature 0089 §3.2. There is no f-string path. Markers, the per-request nonce
and the untrusted-content fragment are emitted together or not at all, which
turns five findings across three audit lenses into a type error.

The nonce is per REQUEST, not per run: a per-run token could be learned by an
injected payload from an earlier tool result and then used to forge a closing
marker in a later one.

Item 4.3 made the marker rule enforceable in both directions. `scrub()` used to
neutralise ONE string — the live closer, `KIND:nonce>>>` — which is the one
shape an attacker cannot produce, because the nonce is minted after their bytes
are already on disk. What they CAN write is the tokenless `CODE>>>` that the
pre-4.3 prompt itself documented as a delimiter, or another channel's closer.
Both passed through untouched (0089 LLD §9.2: "markers are unforgeable only by
accident — nothing escapes a literal `CODE>>>` in content"). The scrub now
neutralises every marker-shaped token for every declared channel, and
`forged_markers()` reports exactly the set it neutralises so
`lint.check_06_marker_forgery` and this module cannot disagree about what a
forgery is.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

# The closed set of untrusted channels. Data rather than six unrelated
# constructors so three things can be derived from one list: the scrub's
# pattern, the linter's channel vocabulary, and the coverage assertion that
# `core/untrusted` states a rule for every one of them
# (`test_core_untrusted_marks_untrusted_and_names_every_channel`). A seventh
# channel added without a sentence in the policy fails that test, which is the
# exact omission that left tool results unmentioned for four tiers.
KINDS: tuple[str, ...] = ("SOURCE", "CODE", "DESC", "RESP", "PRIOR", "TOOL")

# A marker-shaped token: `<<<KIND`, `<<<KIND:token`, `KIND>>>` or `KIND:token>>>`.
#
# Anchored on the channel names on purpose. Neutralising every `>>>` would be
# simpler and would also mangle a Python doctest (`>>> import sys`), a bash
# here-string (`cat <<<'EOF'`) and JavaScript's unsigned right shift — all
# ordinary contents of an audited tree, all bytes the model has to read
# correctly to judge them. The token has to look like a marker for a channel
# this library actually delimits, or the defence costs more than the attack.
_ALT = "|".join(KINDS)
_MARKER_RE = re.compile(
    rf"<<<(?:{_ALT})(?::[0-9a-fA-F]+)?|(?:{_ALT})(?::[0-9a-fA-F]+)?>>>"
)


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


def forged_markers(content: str) -> list[str]:
    """Marker-shaped tokens in `content` — what `scrub()` will neutralise.

    Returned rather than counted so the linter can name the token it found: a
    finding reading "contains its closer" sent a reader hunting through a whole
    file block, and the shape is the thing that has to be recognised.
    """
    return _MARKER_RE.findall(content)


def _defang(match: re.Match) -> str:
    """Break the three-angle run so the token can no longer read as a marker.

    A space rather than a deletion or an escape: the content is EVIDENCE the
    model has to reason about, so it must still be able to see that the file
    contained something marker-shaped. Removing it would hide an injection
    attempt from the one reader positioned to report it.
    """
    tok = match.group(0)
    return "<< <" + tok[3:] if tok.startswith("<<<") else tok[:-3] + "> >>"


def scrub(content: str) -> str:
    """Neutralise every marker-shaped token, whatever channel it names.

    Cross-channel too, not just this slot's own: a `CODE>>>` inside a SOURCE
    block ends the CODE block the model believes it is still inside when the
    two are adjacent in one turn, and the payload does not have to guess which
    channel carries it to try both.

    Idempotent — `<< <CODE` no longer matches — so a value that passes through
    two wraps is not mutated twice.
    """
    return _MARKER_RE.sub(_defang, content)


def wrap(slot: Slot, nonce: str) -> str:
    body = scrub(slot.content)
    return f"<<<{slot.kind}:{nonce}\n{body}\n{slot.kind}:{nonce}>>>"
