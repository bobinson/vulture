"""The structural reads the scope and flow modules share (feature 0102, LLD §6.1, §6.2, §7.2
W8, §8.2 M1): one home each.

Each is O(1) over the model's precomputed indexes — a walk (``preorder``, ``ancestors``,
``chain_links``, ``open_links``, a compound name's segments) O(its ``limits`` cap) — and each
tolerates the ``-1`` a missing child reads as, so a caller never branches on it first.
``cached`` is the one per-node memo of the flow modules (and of the scope table's reads), and
``union`` their one copy-free set union (the scope pass's binding sets join through it too).
"""

from __future__ import annotations

from collections.abc import Callable, Container, Hashable, Iterable, Iterator, Mapping, Sequence
from itertools import chain, pairwise
from types import MappingProxyType
from typing import TYPE_CHECKING

from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_CHAIN, MAX_DEPTH, MAX_TEST_NODES

if TYPE_CHECKING:
    from shared.ast.model import FileModel

__all__ = [
    "CHAINS",
    "NOT_READ",
    "ancestors",
    "and_ancestors",
    "cached",
    "chain_links",
    "chain_root",
    "edges_up",
    "first",
    "first_segment",
    "is_kind",
    "is_read",
    "kids_of",
    "kids_outside",
    "last_segment",
    "member_object",
    "methods_of",
    "named",
    "object_of",
    "of_kind",
    "open_links",
    "pair_part",
    "params_in",
    "parsed_buffer",
    "preorder",
    "segment",
    "top_statement",
    "unawaited",
    "union",
]

type Below = Callable[[FileModel, int], Sequence[int]]

# The kinds a dotted chain runs through by its OBJECT link (W8: a CALL result starts none).
CHAINS = frozenset({Kind.MEMBER, Kind.SUBSCRIPT})
# W8: never a read where it stands — a property or key, a declared name, a type, a target.
NOT_READ = frozenset({
    Field.PROPERTY, Field.KEY, Field.NAME, Field.ANNOTATION, Field.LHS, Field.TARGET,
    Field.SOURCE, Field.PARAMS,
})
_NOT_READ_IDS = frozenset(map(int, NOT_READ))  # as ``FileModel.field_ids`` holds them
_CALLEE = int(Field.CALLEE)
# The field a chain link's own segment hangs under, and the kind it must have (M1: a literal
# subscript key the worker gave an identifier text).
_SEGMENTS: Mapping[Kind, tuple[Field, Kind]] = MappingProxyType({
    Kind.MEMBER: (Field.PROPERTY, Kind.NAME),
    Kind.SUBSCRIPT: (Field.INDEX, Kind.LITERAL),
})


def parsed_buffer(text: str) -> str | bytes:
    """The buffer the worker parsed, as a node's byte span indexes it: ``text`` itself when it
    is ASCII (its UTF-8 bytes are its characters, so a byte offset is a character offset;
    ``str.isascii`` is O(1)), else its UTF-8 bytes, encoded once."""
    return text if text.isascii() else text.encode("utf-8")


def first(model: FileModel, node: int, fld: Field) -> int:
    """``node``'s first child under ``fld``, or ``-1`` (also for ``node == -1``): the model's
    ``first_child``, one bisection and no slice."""
    return model.first_child(node, fld)


def object_of(model: FileModel, node: int) -> int:
    """A MEMBER's / SUBSCRIPT's / CALL's OBJECT child, or ``-1``."""
    return first(model, node, Field.OBJECT)


def is_kind(model: FileModel, node: int, kind: Kind) -> bool:
    """``node`` exists and is of ``kind``."""
    return node >= 0 and model.kind(node) is kind


def unawaited(model: FileModel, node: int) -> int:
    """``node``, or what an AWAIT ``node`` awaits (``await f(x)`` -> ``f(x)``): the one AWAIT
    unwrap of the scope pass and the guards; ``-1`` passes through."""
    return first(model, node, Field.NONE) if is_kind(model, node, Kind.AWAIT) else node


def member_object(model: FileModel, node: int) -> int:
    """A MEMBER's OBJECT child, or ``-1`` (for ``-1`` or any other kind)."""
    return object_of(model, node) if is_kind(model, node, Kind.MEMBER) else -1


def kids_of(model: FileModel, node: int, kind: Kind) -> list[int]:
    """``node``'s children of ``kind``, in document order."""
    return of_kind(model, model.children(node), kind)


def of_kind(model: FileModel, nodes: Iterable[int], kind: Kind) -> list[int]:
    """The nodes of ``nodes`` that are of ``kind``, in order (a call's arguments, a node's
    children)."""
    return [node for node in nodes if model.kind(node) is kind]


def kids_outside(model: FileModel, node: int, fields: frozenset[Field]) -> list[int]:
    """``node``'s children whose Field is not in ``fields``, in document order (read off
    ``FileModel.field_ids``: no ``Field`` is built per child)."""
    ids = model.field_ids
    return [kid for kid in model.children(node) if ids[kid] not in fields]


def named(model: FileModel, node: int) -> str:
    """The text of the NAME under ``node``'s Field NAME (a FUNCTION's declared name), else ``""``."""
    return model.ident(first(model, node, Field.NAME)) or ""


def params_in(model: FileModel, holder: int) -> Sequence[int]:
    """A3: the PARAMs a holder under a FUNCTION's Field PARAMS gives — an ARGS's children, a
    bare holder (``x => ...``) itself."""
    return model.children(holder) if model.kind(holder) is Kind.ARGS else (holder,)


def _children(model: FileModel, node: int) -> Sequence[int]:
    return model.children(node)


def preorder(
    model: FileModel, root: int, budget: int = MAX_TEST_NODES, below: Below = _children
) -> Iterator[int]:
    """``root`` and the nodes ``below`` reaches from it (its children by default), depth first
    in document order, at most ``budget`` of them, the root counted (A32). A node's children
    are taken only up to the budget left, so one wide node never costs its whole degree."""
    stack, seen = [root], 0
    while stack and seen < budget:
        node = stack.pop()
        seen += 1
        yield node
        stack.extend(reversed(below(model, node)[: budget - seen]))


def ancestors(model: FileModel, node: int) -> Iterator[int]:
    """``node``'s ancestors, nearest first, at most ``MAX_DEPTH`` of them: a tree is never
    deeper (§8.7, the bound of ``guards_for``'s ancestor walk)."""
    for _ in range(MAX_DEPTH):
        node = model.parent(node)
        if node < 0:
            return
        yield node


def and_ancestors(model: FileModel, node: int) -> Iterator[int]:
    """``node`` itself, then its ``ancestors`` (nearest first, at most ``MAX_DEPTH``)."""
    return chain((node,), ancestors(model, node))


def edges_up(model: FileModel, node: int) -> Iterator[tuple[int, int]]:
    """Each ``(child, parent)`` edge on the way up from ``node`` (``and_ancestors``, pairwise):
    the child is the branch of its parent that holds ``node``."""
    return pairwise(and_ancestors(model, node))


def chain_links(model: FileModel, node: int) -> tuple[list[int], int]:
    """A MEMBER / SUBSCRIPT chain's links from ``node`` down its OBJECTs, outermost first, and
    the node the chain starts at (``node`` itself, links ``[]``, when it is no chain; ``-1``
    for a link with no object). At most ``MAX_DEPTH`` links: a chain is never deeper."""
    links: list[int] = []
    while node >= 0 and model.kind(node) in CHAINS and len(links) < MAX_DEPTH:
        links.append(node)
        node = object_of(model, node)
    return links, node


def open_links(model: FileModel, node: int, memo: Container[int]) -> tuple[list[int], int]:
    """The chain ``node`` heads (a MEMBER / SUBSCRIPT) walked down its OBJECTs until a link
    ``memo`` already answers: ``node`` and each link walked, outermost first, and where the
    walk stopped — that link, the node the chain starts at, or ``-1``. Every link of a chain
    shares what its start gives it, so a caller fills each walked link from one answer and a
    chain costs O(1) amortised per link, never one walk per link (at most ``MAX_DEPTH`` links a
    walk: a chain is never deeper)."""
    links, kinds, step = [node], model.kind_ids, model.first_child
    below = step(node, Field.OBJECT)
    while _unanswered(below, memo, kinds) and len(links) < MAX_DEPTH:
        links.append(below)
        below = step(below, Field.OBJECT)
    return links, below


def _unanswered(link: int, memo: Container[int], kinds: Sequence[int]) -> bool:
    """``open_links``' walk goes on through ``link``: a chain link (a MEMBER / SUBSCRIPT, read
    off ``kinds``, the model's ``kind_ids``) that ``memo`` does not answer yet."""
    return link >= 0 and link not in memo and kinds[link] in CHAINS


def first_segment(model: FileModel, node: int) -> int:
    """W3: the first segment of a compound name — ``node`` itself unless it is a MEMBER, else
    its first child (its OBJECT; a lone PROPERTY, Python's ``import os``), through each nested
    MEMBER (``_segment``)."""
    return _segment(model, node, 0, None)


def last_segment(model: FileModel, node: int) -> int:
    """W3: the last segment of a compound name — ``node`` itself unless it is a MEMBER, else
    its last PROPERTY, through each nested compound PROPERTY (C++ ``std::filesystem::remove``
    ships its PROPERTY as the MEMBER ``filesystem::remove``; ``_segment``)."""
    return _segment(model, node, -1, Field.PROPERTY)


def _segment(model: FileModel, node: int, end: int, under: Field | None) -> int:
    """The ``end`` one (``0`` first, ``-1`` last) of the children under ``under`` (None:
    every child) of each MEMBER from ``node`` down, at most ``MAX_CHAIN`` MEMBERs below the
    first; ``-1`` past a MEMBER with none."""
    for _ in range(MAX_CHAIN + 1):
        if not is_kind(model, node, Kind.MEMBER):
            break
        kids = model.children(node, under)
        node = kids[end] if kids else -1
    return node


def chain_root(model: FileModel, node: int) -> tuple[list[int], int]:
    """W9: a chain's links (``chain_links``) and the NAME it starts at — ``node`` itself when
    it is a NAME — else ``-1`` (a chain that starts at a call result, a literal ...)."""
    links, base = chain_links(model, node)
    return links, base if is_kind(model, base, Kind.NAME) else -1


def union[T](parts: Iterable[frozenset[T]], empty: frozenset[T]) -> frozenset[T]:
    """The union of frozen sets with no needless copy: ``empty`` itself when no part holds
    anything, the first part that does itself when every other is empty or equals it (mostly
    the same object: one ``list.count``, in C, with its identity shortcut), else one new set.
    A memoised value is then never a fresh copy of a set it equals (CPython has no shared
    empty ``frozenset``); the scope pass's binding sets join the same way."""
    found = [part for part in parts if part]
    return _distinct_union(found) if found else empty


def _distinct_union[T](found: list[frozenset[T]]) -> frozenset[T]:
    """One set or more: the first itself when each equals it (the one set itself), else
    their union."""
    head = found[0]
    return head if found.count(head) == len(found) else head.union(*found[1:])


_MISSING: object = object()


def cached[K: Hashable, T](memo: dict[K, T], key: K, compute: Callable[[K], T]) -> T:
    """``compute(key)``, computed once per key in ``memo``: the one memo the flow modules keep
    (§8.7: O(1) amortised per node). A caller keeps one dict per fact, keyed by the node the
    fact is about, so a node fact builds and keeps no key tuple; one probe on a hit."""
    found = memo.get(key, _MISSING)
    if found is _MISSING:
        found = memo[key] = compute(key)
    return found  # type: ignore[return-value]


def is_read(model: FileModel, node: int) -> bool:
    """W8: whether a NAME is a read where it stands — a property, key, declared name, type or
    target is not; nor is a method's own name (Java's ``o.get(x)``, PHP's ``$o->get(x)``: a
    callee beside a receiver)."""
    fld = model.field_ids[node]
    if fld == _CALLEE:
        return model.first_child(model.parent(node), Field.OBJECT) < 0
    return fld not in _NOT_READ_IDS


def segment(model: FileModel, link: int) -> str | None:
    """A chain link's own segment (M1): a MEMBER's property name, a SUBSCRIPT's literal key;
    None for a dynamic key."""
    fld, kind = _SEGMENTS[model.kind(link)]
    part = first(model, link, fld)
    return model.ident(part) if is_kind(model, part, kind) else None


def top_statement(model: FileModel, node: int) -> int:
    """The module-level statement holding ``node``: its ancestor, or ``node`` itself, whose
    parent is the MODULE (``edges_up``); ``-1`` when none is within ``MAX_DEPTH`` (and for
    ``-1``, which ``ancestors`` would read as the last node)."""
    if node < 0:
        return -1
    edges = edges_up(model, node)
    return next((child for child, up in edges if model.kind(up) is Kind.MODULE), -1)


def methods_of(model: FileModel, cls: int) -> list[int]:
    """A CLASS's methods: the FUNCTION children of its BODY, in document order."""
    bodies = model.children(cls, Field.BODY)
    return [fn for body in bodies for fn in kids_of(model, body, Kind.FUNCTION)]


def pair_part(model: FileModel, node: int, fld: Field) -> int:
    """A PAIR's child under ``fld`` (an OBJECT member's VALUE, an aliased import's KEY), else
    ``node`` itself."""
    return first(model, node, fld) if is_kind(model, node, Kind.PAIR) else node
