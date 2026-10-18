"""The guard role lexicons, the model reads the role predicates share, ``guard_roles`` and the
``host_allow`` composition (feature 0102, LLD §8.3, §8.5, §9.1; L1 (b), L4, L5, L11, L12, M2,
P1-P3, R1-R4, R6, A21, A29).

Mode (b) of §9.1: a guard role lexicon is a WORD lexicon of generic concept words, never a
helper, package or framework name. A CALL callee's last identifier, or a MEMBER property name
(L11), reaches role r when any of its ``words`` - or its glued key - is in r's set
(``GUARD_INDEX.words``, an inverted index: one probe a word). R4: the short ambiguous words
(``has``, ``base``, ``escape``, ``quote``, ``number``, ``int``) are in no word set; membership
reaches ``allowlist`` only by an EXACT glued callee key (``MEMBERSHIP_KEYS``), and no word
yields ``host_allow`` alone: ``host_allow`` is COMPOSED (L12), by ``host_allow`` below. There
is no ``url_parse`` role (L5, P3): a URL parse restricts no host.

Every predicate takes the model first (A21) and reads at most ``MAX_TEST_NODES`` nodes (the
root counted, A32), at most ``MAX_CHAIN`` names of a chain and at most ``MAX_WORDS`` words of an
identifier: each is O(1). ``symbol_of`` lets the flow pass key a callee NAME bound by an import
by its imported symbol (R-H, W6: ``rf`` imported as ``readFile``); without it a callee is read
by the identifier the model ships.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from itertools import chain, islice
from types import MappingProxyType
from typing import TYPE_CHECKING

from shared.ast._nodes import is_kind, last_segment, member_object, object_of, preorder, union
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_CHAIN
from shared.ast.roles._words import NO_WORDS, glue, hits, invert, words

if TYPE_CHECKING:
    from shared.ast.model import FileModel

__all__ = [
    "ADDRESS_CLASS_WORDS",
    "ALLOWLIST_WORDS",
    "CONTAINMENT_KEYS",
    "CONTAINMENT_ROLES",
    "COVERING_GUARDS",
    "EQUALITY_KEYS",
    "EQUALITY_OPERATORS",
    "GUARD_INDEX",
    "GUARD_KEYS",
    "GUARD_OPERATORS",
    "GUARD_WORDS",
    "HOST_WORDS",
    "MEMBERSHIP_KEYS",
    "NEGATION_OPERATORS",
    "NO_ROLES",
    "TRUST_WORDS",
    "VALIDATE_WORDS",
    "RoleIndex",
    "SymbolOf",
    "call_host_allow",
    "callee_identifier",
    "callee_text",
    "guard_roles",
    "held",
    "host_allow",
    "identifier_text",
    "last_identifier",
    "receiver",
]

# The R-H resolver a caller may pass: a callee NAME node -> its imported symbol, or None (W6).
type SymbolOf = Callable[[int], str | None] | None

# The one empty role set every predicate answers with when no role holds (``_words.NO_WORDS``:
# CPython shares no empty ``frozenset``, and a role set is memoised per node by the flow pass).
NO_ROLES: frozenset[str] = NO_WORDS

# ── the guard lexicons (§9.1 mode (b); R4) ───────────────────────────────────

ALLOWLIST_WORDS = frozenset({
    "allow", "allowed", "allowlist", "whitelist", "permitted", "enum", "oneof",
})
# R4: EXACT keys only - Set.has, Map.containsKey, hasOwnProperty, Array.includes,
# Collection.contains, in_array; the operator form is the M2 `in` / `not in` (GUARD_OPERATORS).
MEMBERSHIP_KEYS = frozenset({
    "has", "haskey", "hasownproperty", "contains", "includes", "inarray", "containskey",
})
# R3: EXACT keys (Java host.equals("x")); host_allow (a) only.
EQUALITY_KEYS = frozenset({"equals", "equalsignorecase"})
VALIDATE_WORDS = frozenset({
    "validate", "validator", "valid", "verify", "assert", "test", "match", "fullmatch", "schema",
    "isalnum", "isalpha", "alphanumeric", "isdigit", "isinstance",
})
GUARD_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    # Go HasPrefix -> prefix (R4), is_relative_to -> relative, isAbsolute -> absolute;
    # includes/contains/inarray are also allowlist, by EXACT key (L4: roles are a set; R4).
    "path_contain": frozenset({
        "startswith", "prefix", "strpos", "indexof", "includes", "contains", "inarray", "resolve",
        "realpath", "abspath", "commonpath", "commonprefix", "relative", "absolute", "inside",
        "within", "subpath",
    }),
    "allowlist": ALLOWLIST_WORDS,  # R4: no membership key here - see GUARD_KEYS
    "validate": VALIDATE_WORDS,
})
# R4: membership by EXACT callee key only.
GUARD_KEYS: Mapping[str, frozenset[str]] = MappingProxyType({"allowlist": MEMBERSHIP_KEYS})
# M2 tokens, matched as whole operator tokens, never as words.
GUARD_OPERATORS: Mapping[str, frozenset[str]] = MappingProxyType({
    "in": frozenset({"allowlist", "path_contain"}),
    "not in": frozenset({"allowlist", "path_contain"}),
    "typeof": frozenset({"validate"}),
    "instanceof": frozenset({"validate"}),
})

# ── the host_allow composition's word sets (L12; R1, R2, R3) ─────────────────

HOST_WORDS = frozenset({
    "host", "hosts", "hostname", "hostnames", "domain", "domains", "origin", "origins", "netloc",
    "authority",
})  # R2: plurals included
TRUST_WORDS = frozenset({"trusted", "allowed", "allow", "permitted", "safe"})
# An address-class check restricts the destination (`reserved`: revision 3); `ssrf` names the
# protection itself (cwe_918_12_clean ssrfGuard); both kept (R1).
ADDRESS_CLASS_WORDS = frozenset({"private", "loopback", "internal", "reserved", "ssrf"})
EQUALITY_OPERATORS = frozenset({"==", "===", "!=", "!=="})
# §8.5 (b) (A29 (1)): the M2 tokens of a NEGATED guard TEST, whose ALT is the guarded branch.
NEGATION_OPERATORS = frozenset({"!", "not"})
# R-R (W2): a TRY body's direct CALL with this glued key, on the sink argument's Defs, whose every
# CATCH exits, is a `path_contain` guard (Python `p.relative_to(base)`).
CONTAINMENT_KEYS = frozenset({"relativeto"})
CONTAINMENT_ROLES = frozenset({"path_contain"})

# ── coverage (§8.3; defined here, once, A27 (5)) ─────────────────────────────

# The guard roles that cover each family (§8.5 decide). `validate` never covers `request`
# (isURL accepts any host); `path_contain` never does either (startsWith("http") proves nothing).
COVERING_GUARDS: Mapping[str, frozenset[str]] = MappingProxyType({
    "path": frozenset({"path_contain", "allowlist", "validate"}),
    "request": frozenset({"host_allow"}),
    "command": frozenset({"allowlist", "validate", "shell_quote"}),
})


# ── the inverted indexes (§9.1 WORD_ROLES / KEY_ROLES) ───────────────────────


@dataclass(frozen=True, slots=True)
class RoleIndex:
    """One role kind's two inverted indexes: ``words`` (a word or glued key -> its roles, L1 (b))
    and ``keys`` (an EXACT glued callee key -> its roles, R4)."""

    words: Mapping[str, frozenset[str]]
    keys: Mapping[str, frozenset[str]]

    def of_word(self, ident: str) -> frozenset[str]:
        """The roles an identifier's words - or its glued key - reach: at most ``MAX_WORDS``
        probes plus one (a MEMBER property name, L11)."""
        return self._of(ident, glue(ident))

    def of_callee(self, ident: str) -> frozenset[str]:
        """``of_word`` plus the ONE exact-key probe a CALL callee's glued key makes (R4)."""
        return self.of_glued(ident, glue(ident))

    def of_glued(self, ident: str, key: str) -> frozenset[str]:
        """``of_callee`` of an identifier whose glued ``key`` the caller already made."""
        return union((self._of(ident, key), self.keys.get(key, NO_ROLES)), NO_ROLES)

    def _of(self, ident: str, key: str) -> frozenset[str]:
        found = self.words
        return union((found.get(w, NO_ROLES) for w in (*words(ident), key)), NO_ROLES)


GUARD_INDEX = RoleIndex(invert(GUARD_WORDS), invert(GUARD_KEYS))
# (a)'s operator form: the M2 tokens that carry the allowlist role (`in`, `not in`).
_MEMBERSHIP_OPERATORS = frozenset(
    op for op, found in GUARD_OPERATORS.items() if "allowlist" in found
)

# ── reading a CALL (§8.2 "which identifier", W3, W6) ─────────────────────────


def last_identifier(model: FileModel, node: int) -> int:
    """The NAME holding ``node``'s last identifier: ``node`` itself when it is a NAME, a
    MEMBER's PROPERTY NAME (the last segment of a compound name, W3: ``_nodes.last_segment``,
    at most ``MAX_CHAIN`` nested compound PROPERTYs deep); ``-1`` for anything else."""
    if is_kind(model, node, Kind.NAME):
        return node
    found = last_segment(model, node)
    return found if is_kind(model, found, Kind.NAME) else -1


def callee_identifier(model: FileModel, call: int) -> int:
    """The NAME holding the CALL's callee's last identifier (``fs.readFile`` -> ``readFile``,
    Java ``a.b()`` -> ``b``, ``std::filesystem::remove`` -> ``remove``), or ``-1``."""
    return last_identifier(model, model.callee(call))


def receiver(model: FileModel, call: int) -> int:
    """The CALL's receiver: its own OBJECT (the ``object_name`` call shape, Java/PHP), else
    the OBJECT of a MEMBER callee (``host.equals(x)`` -> ``host``); ``-1`` for a bare call."""
    own = object_of(model, call)
    return own if own >= 0 else member_object(model, model.callee(call))


def identifier_text(model: FileModel, node: int, symbol_of: SymbolOf = None) -> str:
    """The text a role test reads for the identifier ``node``: the symbol an import binds it
    to, when the caller resolved one (R-H, W6), else its own; ``""`` for none (``-1``)."""
    if node < 0:
        return ""
    return _bound_symbol(node, symbol_of) or model.ident(node) or ""


def _bound_symbol(node: int, symbol_of: SymbolOf) -> str | None:
    """The symbol an import binds ``node`` to, when the caller passed a resolver (R-H, W6)."""
    return symbol_of(node) if symbol_of is not None else None


# ── bounded walks ────────────────────────────────────────────────────────────


def _link_children(model: FileModel, node: int) -> list[int]:
    """A chain's links below ``node``, nearest segment first: CALLEE, PROPERTY, then OBJECT -
    never ARGS, so an argument is no part of a receiver chain."""
    return [*model.children(node, Field.CALLEE), *model.children(node, Field.PROPERTY),
            *model.children(node, Field.OBJECT)]


def _name_text(model: FileModel, node: int) -> str:
    """A NAME's own text, ``""`` for any other node."""
    return (model.ident(node) or "") if model.kind(node) is Kind.NAME else ""


def chain_names(model: FileModel, node: int) -> list[str]:
    """The identifiers of ``node``'s chain - a CALL's callee and receiver links, never its
    arguments - nearest first, at most ``MAX_CHAIN`` of them (``shlex.quote`` -> ``quote``,
    ``shlex``): raw, so ``ShellUtils`` still splits into ``shell``, ``utils``. The walk reads
    at most ``MAX_TEST_NODES`` nodes (``preorder``) and stops once it holds ``MAX_CHAIN``."""
    names = (_name_text(model, n) for n in preorder(model, node, below=_link_children))
    return list(islice(filter(None, names), MAX_CHAIN))


# ── a TEST's or a CALL's parts (§8.5 (i)-(iv), L12) ──────────────────────────


def _no_names() -> Iterable[str]:
    return ()


@dataclass(slots=True)
class _Parts:
    """What a guard TEST, or a sanitiser CALL, offers the role tests."""

    callees: list[str] = field(default_factory=list)  # CALL callees' last identifiers
    properties: list[str] = field(default_factory=list)  # MEMBER property names (L11)
    names: list[str] = field(default_factory=list)  # every identifier read: L12 (a)'s host words
    operators: list[str] = field(default_factory=list)  # M2 operator tokens
    equality: bool = False  # an equality whose operands hold no presence literal (R3)
    regex: bool = False  # a regex LITERAL (§8.5 (iii))
    # More of (a)'s host words, read only when (a)'s first half holds (a CALL's chain and
    # argument names: most sanitiser CALLs never need them).
    deferred: Callable[[], Iterable[str]] = _no_names


# R3: a presence literal's class -> whether a literal of that length is one (`null`, `None`,
# `nil`, `undefined`; an empty string).
_PRESENT: Mapping[str, Callable[[int], bool]] = MappingProxyType({
    "null": lambda _length: True,
    "string": lambda length: length == 0,
})
_EMPTY_STRING_BYTES = 2  # `""`: two quote bytes and nothing between


def _empty_template(model: FileModel, node: int) -> bool:
    """A childless TEMPLATE spanning ``""`` (PHP ships a double-quoted string as one, with no
    ``lit`` record): an empty string, so a presence literal."""
    start, end = model.span(node)
    empty = end - start == _EMPTY_STRING_BYTES
    return empty and model.kind(node) is Kind.TEMPLATE and not model.children(node)


def _presence(model: FileModel, node: int) -> bool:
    """R3: ``node`` is a PRESENCE literal - ``lit`` class ``null``, or a string of length 0."""
    if node < 0:
        return False
    lit = model.literal(node)
    present = _PRESENT.get(lit.kind)
    return present(lit.length) if present is not None else _empty_template(model, node)


def _operands_present(model: FileModel, nodes: Iterable[int]) -> bool:
    return any(_presence(model, n) for n in nodes)


def _equality_call(model: FileModel, call: int, key: str) -> bool:
    """R3: an EXACT ``EQUALITY_KEYS`` callee whose operands - receiver and arg 0 - hold no
    presence literal (``host.equals("x")`` yes, ``host.equals(null)`` no)."""
    if key not in EQUALITY_KEYS:
        return False
    return not _operands_present(model, (receiver(model, call), *model.args(call)[:1]))


def _read_call(model: FileModel, call: int, parts: _Parts, symbol_of: SymbolOf) -> None:
    ident = callee_text(model, call, symbol_of)
    if ident:
        parts.callees.append(ident)
    parts.equality |= _equality_call(model, call, glue(ident))


def _read_name(model: FileModel, name: int, parts: _Parts, _symbol_of: SymbolOf) -> None:
    ident = model.ident(name) or ""
    parts.names.append(ident)
    if model.field(name) is Field.PROPERTY:
        parts.properties.append(ident)


def _read_binop(model: FileModel, binop: int, parts: _Parts, symbol_of: SymbolOf) -> None:
    _read_unary(model, binop, parts, symbol_of)
    if model.ident(binop) in EQUALITY_OPERATORS:
        parts.equality |= not _operands_present(model, model.children(binop))


def _read_unary(model: FileModel, unary: int, parts: _Parts, _symbol_of: SymbolOf) -> None:
    op = model.ident(unary)
    if op:
        parts.operators.append(op)


def _read_literal(model: FileModel, literal: int, parts: _Parts, _symbol_of: SymbolOf) -> None:
    # R3's literal class `other` is what a regex ships as (§6.2).
    parts.regex |= model.literal(literal).kind == "other"


# A TEST node's kind -> what it adds to the parts.
_READERS: Mapping[Kind, Callable[[FileModel, int, _Parts, SymbolOf], None]] = MappingProxyType({
    Kind.CALL: _read_call,
    Kind.NAME: _read_name,
    Kind.BINOP: _read_binop,
    Kind.UNARY: _read_unary,
    Kind.LITERAL: _read_literal,
})


def _test_parts(model: FileModel, test: int, symbol_of: SymbolOf) -> _Parts:
    """A guard TEST's parts: its NAMEs, MEMBER properties, callee identifiers, operators and
    literals, over at most ``MAX_TEST_NODES`` nodes in document order."""
    parts = _Parts()
    for node in preorder(model, test):
        reader = _READERS.get(model.kind(node))
        if reader is not None:
            reader(model, node, parts, symbol_of)
    return parts


def callee_text(model: FileModel, call: int, symbol_of: SymbolOf = None) -> str:
    """The text a role test reads for a CALL's callee: its last identifier's
    (``identifier_text``: an import binding's symbol when ``symbol_of`` resolves one)."""
    return identifier_text(model, callee_identifier(model, call), symbol_of)


def _call_parts(model: FileModel, call: int, ident: str, key: str) -> _Parts:
    """A sanitiser CALL's parts (L12): membership, trust and address read from its callee
    identifier ``ident`` (``key`` glued) alone; host words from the callee chain and its
    argument NAMEs / properties, deferred until (a)'s first half holds."""
    return _Parts(
        callees=[ident] if ident else [],
        equality=_equality_call(model, call, key),
        deferred=lambda: _call_names(model, call),
    )


def _call_names(model: FileModel, call: int) -> Iterator[str]:
    """A sanitiser CALL's host-word candidates: its callee chain, then its argument names (a
    NAME argument's, a MEMBER argument's last segment)."""
    args = filter(None, (identifier_text(model, last_identifier(model, a)) for a in model.args(call)))
    return chain(chain_names(model, call), args)


# ── host_allow (L12, P2; R2, R3, R6) ─────────────────────────────────────────


def _restricts_host(ident: str) -> bool:
    """(b) or (c) on ONE identifier: a trust word AND a host word (``isTrustedHost``), or an
    address-class word (``is_private_address``, ``ssrfGuard``)."""
    found = words(ident)
    if not ADDRESS_CLASS_WORDS.isdisjoint(found):
        return True
    return not TRUST_WORDS.isdisjoint(found) and not HOST_WORDS.isdisjoint(found)


def _index_roles(parts: _Parts) -> frozenset[str]:
    """(i): the ``GUARD_INDEX`` roles of each callee (its words, glued key and EXACT key, R4)
    and of each MEMBER property name (L11) - probed once per TEST or CALL."""
    callees = map(GUARD_INDEX.of_callee, parts.callees)
    properties = map(GUARD_INDEX.of_word, parts.properties)
    return union(chain(callees, properties), NO_ROLES)


def _compares(parts: _Parts, roles: frozenset[str]) -> bool:
    """(a)'s first half: the allowlist role among the index ``roles`` (an ``ALLOWLIST_WORDS``
    word of a callee or property, or an EXACT ``MEMBERSHIP_KEYS`` callee key, R4), ``in`` /
    ``not in``, or an equality (R3)."""
    membership = not _MEMBERSHIP_OPERATORS.isdisjoint(parts.operators)
    return parts.equality or membership or "allowlist" in roles


def _names_a_host(parts: _Parts) -> bool:
    """(a)'s second half: some part's words meet ``HOST_WORDS`` (the deferred names read now)."""
    return hits(chain(parts.names, parts.deferred(), parts.callees), HOST_WORDS)


def _host_composes(parts: _Parts, roles: frozenset[str]) -> bool:
    """L12: (a) a membership/equality role AND a host word, or (b)/(c) on one identifier."""
    identifiers = chain(parts.callees, parts.properties)
    return any(map(_restricts_host, identifiers)) or (_compares(parts, roles) and _names_a_host(parts))


def host_allow(model: FileModel, node: int, *, symbol_of: SymbolOf = None) -> bool:
    """L12 (A21): ``node`` restricts a request's host. A guard TEST (an IF's ``TEST`` child)
    is read whole (``MAX_TEST_NODES``); any other node as a sanitiser CALL - its callee
    identifier, callee chain and argument names. A bare truthiness test on a host, a presence
    comparison (``u.hostname == null``) and a URL parse alone are never ``host_allow``."""
    if model.field(node) is Field.TEST:
        return _composes(_test_parts(model, node, symbol_of))
    ident = callee_text(model, node, symbol_of)
    return call_host_allow(model, node, ident, glue(ident))


def call_host_allow(model: FileModel, call: int, ident: str, key: str) -> bool:
    """``host_allow`` of a sanitiser CALL whose callee identifier ``ident`` (``key`` glued)
    the caller already resolved (``sanitizer_roles``)."""
    return _composes(_call_parts(model, call, ident, key))


def _composes(parts: _Parts) -> bool:
    return _host_composes(parts, _index_roles(parts))


# ── guard_roles (§8.5 (i)-(iv)) ──────────────────────────────────────────────


def held(flags: Iterable[tuple[str, bool]]) -> frozenset[str]:
    """The roles whose flag holds (``NO_ROLES`` when none does)."""
    return frozenset(role for role, holds in flags if holds) or NO_ROLES


def _operator_roles(operators: Iterable[str]) -> frozenset[str]:
    return union((GUARD_OPERATORS.get(op, NO_ROLES) for op in operators), NO_ROLES)


def _flag_roles(parts: _Parts, roles: frozenset[str]) -> frozenset[str]:
    """(iii) ``validate`` for a regex literal; (iv) the composed ``host_allow``."""
    return held((("validate", parts.regex), ("host_allow", _host_composes(parts, roles))))


def guard_roles(model: FileModel, test: int, *, symbol_of: SymbolOf = None) -> frozenset[str]:
    """The SET of roles of the guard TEST ``test`` (§8.5, L4, A21): (i) each callee's last
    identifier and each MEMBER property name by ``GUARD_INDEX`` (a callee also by its exact
    key, R4); (ii) each M2 operator token's ``GUARD_OPERATORS`` roles; (iii) ``validate`` for a
    regex literal; (iv) ``host_allow`` when ``host_allow(model, test)`` holds."""
    parts = _test_parts(model, test, symbol_of)
    found = _index_roles(parts)
    return union((found, _operator_roles(parts.operators), _flag_roles(parts, found)), NO_ROLES)
