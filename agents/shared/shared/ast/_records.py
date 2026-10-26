"""The flow pass's records (feature 0102, LLD §5, §8.1, §8.6; A28 (4), A29 (5)).

``flow`` re-exports every name here; the records live in a module of their own so the flow
engine's private modules (``_calls``, ``_params``, ``_origins``, ``_hops``, ``_guards``) can
build them without importing ``flow``, which imports them.

An ``Origin`` is one of the three classes of §8.1: ``external(role, via)``, ``constant`` and
``unknown(reason)`` — ``Origin`` has no reason field, so an unknown origin's reason is its
``role`` (§5). An origin set never holds more than ``MAX_ORIGINS`` members: a larger one
collapses to ``TOP`` = ``{external(any), unknown(overflow)}``, the conservative direction
(reportable, never declinable).

``external`` and ``unknown`` answer ONE shared ``Origin`` per value (``ANY`` and ``OVERFLOW``
are theirs), ``only`` one shared one-origin set per role and ``role_set`` one shared copy of
each role set: all are bounded by the role vocabulary (the §9.1 tables and the §8.1
reasons, never the input), so an analysis keeps no origin or role set of its own beyond its
origin SETS — what its footprint counts (A35).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import NamedTuple

__all__ = [
    "ANY",
    "CONSTANT",
    "EMPTY",
    "EXPR",
    "EXTERNAL",
    "EXTERNAL_ROLES",
    "FLAG",
    "HOP_KINDS",
    "INDEX",
    "OVERFLOW",
    "PARAM",
    "TOP",
    "UNKNOWN",
    "UNKNOWN_REASONS",
    "Flow",
    "Guard",
    "Hop",
    "Origin",
    "Origins",
    "external",
    "externals",
    "has_external",
    "only",
    "role_set",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class Origin:
    """One origin (§8.1): ``cls`` is ``external``, ``constant`` or ``unknown``; ``role`` the
    external role (``request`` ...) or the unknown reason (``param`` ...); ``via`` the sanitiser
    roles an external value passed through."""

    cls: str
    role: str = ""
    via: frozenset[str] = frozenset()


type Origins = frozenset[Origin]

EXTERNAL = "external"
UNKNOWN = "unknown"
CONSTANT = Origin("constant")
EMPTY: Origins = frozenset()
# §8.1's closed vocabularies: an external origin's role (``any`` is the overflow collapse's) and
# an unknown origin's reason. The flow pass mints no other; D3' admits a worker-built answer's
# origins against them (§4.1 item 2).
EXTERNAL_ROLES = frozenset({
    "request", "network", "upload", "argv", "stdin", "env", "error", "param_hint", "any",
})
UNKNOWN_REASONS = frozenset({
    "unresolved", "param", "depth", "dynamic", "recursion", "arity", "external_call",
    "summary_cap", "overflow",
})


@lru_cache(maxsize=None)  # bounded by the role vocabulary and its via subsets, not the input
def external(role: str, via: frozenset[str] = frozenset()) -> Origin:
    """``external(role, via)`` (§8.1), one shared object per value."""
    return Origin(EXTERNAL, role, via)


@lru_cache(maxsize=None)  # bounded by the §8.1 reasons
def unknown(reason: str) -> Origin:
    """``unknown(reason)`` (§8.1): the reason is the origin's ``role``; one shared object."""
    return Origin(UNKNOWN, reason)


@lru_cache(maxsize=None)  # one per role: bounded by the role vocabulary, not by the input
def only(role: str) -> Origins:
    """``{external(role)}``, one shared set per role."""
    return frozenset({external(role)})


ANY = external("any")
OVERFLOW = unknown("overflow")
# A read of a parameter no caller in the file binds (§8.1): what the command parameter
# heuristic keys on (D25, A42 (1)).
PARAM = unknown("param")
# §8.1: what an origin set past MAX_ORIGINS collapses to.
TOP: Origins = frozenset({ANY, OVERFLOW})


@lru_cache(maxsize=None)  # bounded by the subsets of the role vocabulary
def role_set(roles: frozenset[str]) -> frozenset[str]:
    """The one shared copy of a set of roles (a guard's, a flow's filtered roles)."""
    return roles


def externals(origins: Origins) -> Origins:
    """The ``external`` origins of a set (§8.1's class test, once)."""
    return frozenset(o for o in origins if o.cls == EXTERNAL)


def has_external(origins: Origins) -> bool:
    """Whether a set holds an ``external`` origin (``externals`` without building it)."""
    return any(o.cls == EXTERNAL for o in origins)


# §8.6: a hop's kinds, and the placeholders of a hop's name (A30 (2)): a segment is a D16
# identifier, ``INDEX`` (an M1 subscript key) or ``FLAG`` (an M4 literal); a name that cannot be
# so spelled is ``EXPR`` whole.
HOP_KINDS = frozenset({"param", "member", "assign", "call", "return", "loop", "catch", "sink"})
EXPR, INDEX, FLAG = "<expr>", "<index>", "<flag>"


class Hop(NamedTuple):
    """One step of a flow (§8.6, A28 (4)): its 1-based line, its kind (``param``, ``member``,
    ``assign``, ``call``, ``return``, ``loop``, ``catch``, ``sink``) and its name — §10.1's JSON
    key, up to three ``.``-joined D16 segments or placeholders, else ``<expr>`` (A30 (2))."""

    line: int
    kind: str
    name: str


@dataclass(frozen=True, slots=True)
class Guard:
    """A guard ``guards_for`` found (A29 (5)): the IF (or, through R-R, TRY) node and the SET
    of its roles (L4)."""

    node: int
    roles: frozenset[str]


@dataclass(frozen=True, slots=True)
class Flow:
    """One sink argument's flow (§5, §8.6): ``sink`` the sink CALL (or R-X declaration),
    ``arg`` the argument node (A28 (4)), ``origins`` what reaches it after R-P — never
    ``constant`` (W15 (c)) — ``hops`` at most ``MAX_HOPS`` from the source side (``truncated``
    when more were cut), ``guards`` in ``guards_for`` order (A29), ``filtered_roles`` the roles
    R-P removed (A28 (3)), ``sink_key`` the sink's GLUED callee key, the flow pass's
    ``Calls.key`` (L1 (a)): what a rule's gate reads (A40 (3), A41 (2)).

    The command parameter heuristic's per-flow facts (D25, A42 (1), A43 (1); §8.5), set for a
    ``command`` flow only (False elsewhere) and read only by a rule's hook: ``shell_sink`` —
    the sink interprets ``arg`` through a shell by the command row's existing tables;
    ``built_arg`` — ``arg`` is a BINOP or TEMPLATE, or a NAME one of whose reaching Defs' value
    is (one hop); ``param_bound`` — set only on a flow holding ``unknown(param)``: another
    candidate at the same ``(sink, arg)`` holds none, so a same-file caller bound the
    parameter, and that flow decides; ``builtin_program`` — ``arg`` is the program position of
    a command builtin of the profile's own table (the whole command)."""

    family: str
    sink: int
    sink_line: int
    span: tuple[int, int]
    arg: int
    origins: Origins
    hops: tuple[Hop, ...]
    guards: tuple[Guard, ...]
    truncated: bool
    filtered_roles: frozenset[str] = frozenset()
    sink_key: str = ""
    shell_sink: bool = False
    built_arg: bool = False
    param_bound: bool = False
    builtin_program: bool = False
