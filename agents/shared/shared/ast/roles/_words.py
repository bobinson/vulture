"""The two identifier normalisers and the one table inversion (feature 0102, LLD §9.1; L1, A10).

``glue`` and ``words`` are defined HERE, once (A10): ``shared.ast.roles`` re-exports them,
``shared.ast.model`` imports them for ``chain_words`` and its cap tally, and 0101's
``cwe_agent.skills._lexical.identifier_words`` IS ``words`` (A27 (8)), so a fix to how an
identifier splits lands in the regex rules and the AST tier's word lexicons at once.

* ``glue`` (L1 (a)): the key a SINK-SIDE callee lexicon and an R4 exact-key lexicon are
  matched by — lowercased, ``_`` and ``$`` removed (``check_output`` -> ``checkoutput``).
* ``words`` (L1 (b), (c)): the lower-cased words a GUARD/SANITISER role lexicon and a
  word-set lexicon are matched by (``isTrustedHost`` -> ``is``, ``trusted``, ``host``), at
  most ``MAX_WORDS`` of them: the cap bounds the probes a role test makes (§8.5).
* ``hits`` and ``word_set``: the two mode-(c) operations over several identifiers — whether
  any of their words is in a lexicon, and all their words as one set — so the role predicates
  and the flow modules spell each once.

This module imports only ``limits`` (and the standard library): ``model`` loads it, and
importing ``shared.ast`` must stay a leaf (D1).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from functools import lru_cache
from itertools import islice
from types import MappingProxyType

from shared.ast.limits import MAX_WORDS, WORDS_MEMO

__all__ = ["NO_WORDS", "glue", "hits", "invert", "word_count", "word_set", "words"]

# 0101's identifier splitter: a capitalised or lower-case run, or an ACRONYM run that stops
# before the capital starting the next word (`HTTPServer` -> HTTP, Server); digits stay with
# the letters before them (`oauth2Token` -> oauth2, token); `_`, `-` and `$` split. Every
# quantifier is bounded, so a match never backtracks past 64 characters.
_WORD = re.compile(r"[A-Z]?[a-z0-9]{1,64}|[A-Z]{1,64}[0-9]{0,16}(?![a-z])")
# The one empty word set (CPython shares no empty ``frozenset``): what ``word_set`` answers
# with no word, and the empty role set of ``guards`` (``NO_ROLES``) - a memo of many empty
# answers then keeps no copies.
NO_WORDS: frozenset[str] = frozenset()


def glue(ident: str) -> str:
    """L1 (a): the glued key of an identifier (``check_output`` -> ``checkoutput``): lowercased,
    ``_`` and ``$`` removed (two ``replace`` calls: several times faster than ``translate``)."""
    return ident.lower().replace("_", "").replace("$", "")


@lru_cache(maxsize=WORDS_MEMO)
def words(ident: str) -> tuple[str, ...]:
    """The lower-cased words of ``ident`` (``readFile`` -> ``read``, ``file``), at most
    ``MAX_WORDS`` of them: the cap bounds the word probes a role lexicon makes (§8.5), and the
    scan stops at the cap, so an adversarial identifier costs what a short one does."""
    return tuple(m[0].lower() for m in islice(_WORD.finditer(ident), MAX_WORDS))


def hits(names: Iterable[str], lexicon: frozenset[str]) -> bool:
    """Mode (c): some word of some identifier of ``names`` is in ``lexicon``."""
    return any(not lexicon.isdisjoint(words(name)) for name in names)


def word_set(names: Iterable[str]) -> frozenset[str]:
    """Every word of ``names``, as one set: the one shared empty set when there is none, so a
    memo of many word-less identifiers keeps no copies."""
    return frozenset(w for name in names for w in words(name)) or NO_WORDS


def word_count(ident: str) -> int:
    """How many words ``ident`` has, uncapped: what the ``words_capped`` tally counts (§8.7)."""
    return sum(1 for _ in _WORD.finditer(ident))


def invert(table: Mapping[str, Iterable[str]]) -> Mapping[str, frozenset[str]]:
    """The inverted index of a role table (§9.1 ``invert``): member -> the frozenset of the
    roles whose set holds it, read-only. A role test is then one dict probe per word."""
    index: dict[str, set[str]] = {}
    for role, members in table.items():
        for member in members:
            index.setdefault(member, set()).add(role)
    return MappingProxyType({member: frozenset(found) for member, found in index.items()})
