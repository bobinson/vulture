"""Keep an emitted ``category`` inside the agent's DECLARED vocabulary.

Every agent advertises its categories through ``/info``'s ``config_schema``
enum, and consumers rely on that contract: the frontend's category filters,
cross-agent dedup, and the OWASP categorizer all key off it.

Measured on one real target: 30 of the SSDF agent's 56 findings (54%) carried a
category OUTSIDE its declared ``["PO", "PS", "PW", "RV"]`` -- and that included
ALL NINE skill-tier rows, so it was not merely the LLM inventing ids. The LLM
tier alone produced 15 distinct strings, among them invented task numbers
(``PW-102``, ``PW-107``), a doubled id (``PW-1/PW-3``), a missing hyphen
(``PW2``) and practice-group NAMES (``PW-produce-well-secured-software``).
Nothing downstream can filter on a vocabulary like that.

The rule is deliberately narrow: reduce a value to its LEADING TOKEN when that
token is a declared category, and otherwise leave it ALONE. Guessing which
group an unrecognised id belongs to would trade a visible contract break for an
invisible mis-classification.
"""
from __future__ import annotations

import re

from shared.env import env_flag

# Separators are equalised before comparison: an agent may DECLARE
# `blast_radius` while a tier EMITS `blast-radius`, and those are the same
# concept. Folding to a single canonical separator is what lets the reduction
# see that.
_SEP = re.compile(r"[-_.\s]+")

# Feature 0079 C2. The COMPOUND JOINERS, folded like any other separator when
# the switch is on.
#
# Without them a compound value never matches its leading declared token on a
# token boundary -- `circuit_breaker, retry` folds to `circuit_breaker,_retry`,
# the prefix test fails on the comma, and `_fallback_token`'s re.findall then
# scans the WHOLE string and can return a LATER member. Measured:
#
#     normalize_to_enum("circuit_breaker, retry", chaos) -> "retry"
#
# A circuit-breaker finding filed under retry. It is a silent misclassification,
# not a survival: the result is inside the declared vocabulary, so no consumer
# can tell. Folding the joiner makes the documented rule -- reduce to the
# LEADING declared token -- apply to compounds too.
#
# ssdf and soc2 are unaffected: their declared tokens are short prefixes that
# already matched (`PW-1/PW-3` -> `PW`), and folding a joiner cannot change a
# match that already succeeded on the first token.
_JOINER = re.compile(r"[,/]+")


def _joiner_folding_enabled() -> bool:
    """Read at call time so the rollback stays flippable.

    ``VULTURE_CATEGORY_JOINER=false`` restores the pre-0079 behaviour exactly,
    including the misclassification -- it exists for the operator who sees a
    categorisation shift and needs to reverse precisely this.
    """
    return env_flag("VULTURE_CATEGORY_JOINER", True)


def _fold(value: str) -> str:
    """Lowercase and collapse separator runs to one underscore.

    Separators are ``-`` ``_`` ``.`` and whitespace, plus (feature 0079 C2) the
    compound joiners ``,`` and ``/``.
    """
    text = value.strip().lower()
    if _joiner_folding_enabled():
        text = _JOINER.sub("_", text)
    return _SEP.sub("_", text).strip("_")


def normalize_to_enum(category: str, allowed: frozenset[str] | set[str]) -> str:
    """Return ``category`` reduced to a declared value, or unchanged.

    Exact matches pass straight through. Otherwise the LONGEST declared value
    that is a token-boundary prefix of the folded input wins -- longest so that
    `blast_radius` beats a shorter `blast`, and token-boundary so that `PW` does
    not claim `PWX`.

    A value matching nothing declared is returned UNCHANGED. Guessing which
    declared value an unrecognised id belongs to would trade a visible contract
    break for an invisible mis-classification.
    """
    if not category or category in allowed:
        return category
    folded = _fold(category)
    if not folded:
        return category
    best: str | None = None
    for candidate in allowed:
        token = _fold(candidate)
        if not token:
            continue
        matches = folded == token or folded.startswith(token + "_")
        if matches and (best is None or len(token) > len(_fold(best))):
            best = candidate
    if best is not None:
        return best
    # No prefix match. A digit-suffixed form (`PW2`) has no separator to split
    # on, so try the leading letters as a last resort -- and a parenthesised
    # trailing id (`Change Management (CC8)`) needs the same treatment from the
    # other end.
    return _fallback_token(category, allowed)


def _fallback_token(category: str, allowed: frozenset[str] | set[str]) -> str:
    """Leading-letters and embedded-token attempts, in that order."""
    for token in re.findall(r"[A-Za-z]+[0-9]*|[0-9]+", category):
        for candidate in allowed:
            if _fold(token) == _fold(candidate):
                return candidate
    lead = re.match(r"^([A-Za-z]{1,12})", category.strip())
    if lead:
        for candidate in allowed:
            if _fold(lead.group(1)) == _fold(candidate):
                return candidate
    return category


def split_practice_detail(category: str, normalized: str) -> str | None:
    """The part of ``category`` the normalisation dropped, if any.

    Returned so a caller can PRESERVE the specific practice reference (say
    ``PW-3.3``) alongside the conforming group id, rather than losing it.
    """
    if category == normalized:
        return None
    return category
