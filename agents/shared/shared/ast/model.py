"""The parent-side file model: one validated worker document, columnar and immutable
(feature 0102, LLD §5, §6.2, §8.7).

``FileModel.from_doc`` turns a document ``validate_model`` admitted into ``array('i')``
columns plus every index the scope and flow passes read, each built in ONE linear pass:

* a per-kind index (a counting sort of the node indices by kind, document order kept);
* CSR child arrays twice over — in document order, and grouped by ``Field`` within each
  parent — so ``children(i)`` and ``children(i, field)`` are slices, never scans;
* ``function_of[]`` / ``block_of[]``: the nearest FUNCTION, and the nearest BLOCK or MODULE
  (W2), each node's answer read off its parent's because a parent precedes its children;
* ``nl_lines``, the sequence ``text.split("\\n")``: AST rows number lines and slice windows
  by ``\\n`` only, as tree-sitter counts them (D21), never by ``str.splitlines``. It holds the
  text once plus one offset per line, and slices a line out when it is read.

``grammar_stamp(path)`` answers the stamp a file's models carry without the model: each
``from_doc`` records its document's stamp under the stamp's prefix (its grammar entry point),
which a path selects as the cache does (A41 (4)).

Every query is O(1), or O(degree) where it returns or filters one node's children
(``args``, ``kwargs``); ``chain_words`` is O(1) amortised through a per-model memo of at most
``WORDS_MEMO`` chains (A38), past which a chain is walked again when asked.
``first_child`` reads one child under a field with one bisection and no slice: the scope and
flow passes ask it of most nodes they visit (through ``_nodes.first``). ``kind_ids`` and
``field_ids`` are read-only views of two columns, for a pass that dispatches on every node.

A cap's tally is a fact about the FILE, so it is counted here, once, over constructs:
``tallies`` holds how many calls carry more than ``MAX_ARGS`` positional arguments, how many
chains run past ``MAX_CHAIN`` segments, and how many identifiers have more than
``MAX_WORDS`` words. An audit's ``ast_coverage.tallies`` aggregates them (§10.2); asking a
query again never moves them.

``bytes_estimate`` — the model cache's LRU weight (D5) — is the footprint the build made
(A17): every array buffer, dict and list slot, the text and each distinct string it keeps,
summed once by ``sys.getsizeof``; ``tracemalloc`` measures within [0.8, 1.25] of it
(``test_0102_bytes_estimate.py``, ``bench_ast.py``).

Nothing here imports ``tree_sitter`` (D1): the model is plain Python over the columns.
"""

from __future__ import annotations

import dataclasses
import sys
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import accumulate, compress, islice, repeat
from operator import add, gt, mul, sub
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, overload

from shared.ast._sizing import INT_SIZE, own_int_count, own_strs
from shared.ast._validate import COLUMNS, IDENTIFIER_KINDS, LITERAL_CLASSES, prefix_of, stamp_prefix
from shared.ast.coverage import ARGS_CAPPED, CHAIN_TRUNCATED, WORDS_CAPPED
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_ARGS, MAX_CHAIN, MAX_WORDS, WORDS_MEMO
from shared.ast.profile import profile_for
from shared.ast.roles._words import glue, word_count, words

if TYPE_CHECKING:
    from shared.ast.flow import FlowAnalysis

__all__ = [
    "ARGS_CAPPED",
    "CHAIN_TRUNCATED",
    "NO_LITERAL",
    "WORDS_CAPPED",
    "FileModel",
    "Literal_",
    "glue",
    "grammar_stamp",
    "owns_lang",
    "words",
]

# The two identifier normalisers (L1) are defined once, in ``shared.ast.roles._words`` (A10),
# and the ``tallies`` keys of the caps the model enforces in ``coverage``, beside the wire
# (§10.2): imported above, and re-exported here for the model's readers.

# ── ownership by language, without a parse ───────────────────────────────────


def owns_lang(path: str | Path) -> bool:
    """True iff ``path``'s language has a v1 profile: the §9.2 prefilter's cheap test of
    "owned, no sink" against "unsupported", decided by extension alone — never a parse."""
    return profile_for(path) is not None


# ── the grammar stamp a file's models carry (A41 (4)) ─────────────────────────

# Stamp prefix (``_validate.stamp_prefix``: ``<module>.<entry point>@``) -> the stamp the
# latest model of that grammar entry point was built with. The worker mints a stamp from its
# grammar's own version, which the parent cannot read (D1: no ``tree_sitter`` here, and a
# grammar's version is not its package's); ``from_doc`` records each model's here
# (``_stamped``). Bounded by the entry points: ``validate_reply`` binds a stamp's prefix to
# the request it answers.
_STAMP_OF: dict[str, str] = {}


def _stamped(stamp: str) -> str:
    """``stamp``, recorded under its prefix as the stamp of its grammar entry point."""
    _STAMP_OF[prefix_of(stamp)] = stamp
    return stamp


def grammar_stamp(path: str | Path) -> str:
    """The grammar stamp of ``path``'s models (``FileModel.grammar``, §10.1): its profile's
    module and the entry point the cache parses the file with (``grammar_for``: a ``.tsx`` file
    reads the TSX stamp), as ``from_doc`` recorded it; ``""`` for a file with no profile, or
    whose grammar no model of this process was built with."""
    profile = profile_for(path)
    if profile is None:
        return ""
    return _STAMP_OF.get(stamp_prefix(profile.grammar_module, profile.grammar_for(path)), "")


# ── the literal record (§6.2, R3, W15 b, D16) ────────────────────────────────


@dataclass(frozen=True, slots=True)
class Literal_:
    """A LITERAL's shipped record: its class (``string``, ``number``, ``bool``, ``null``,
    ``char``, ``other``), its content length, and a value only for a boolean or a number
    of at most 20 characters — a string's value never leaves the worker (D16)."""

    kind: str
    length: int
    value: str | None = None


# What ``literal`` answers for a node that carries no literal record.
NO_LITERAL = Literal_("", 0)

# ── the chain rule, shared by ``chain_words`` and its tally (L1, W3, §8.2 M1) ──

# A chain runs through these kinds; a child under one of these fields continues it.
_CHAIN_KINDS = frozenset({Kind.MEMBER, Kind.SUBSCRIPT, Kind.CALL})
_LINK_FIELDS = frozenset({Field.OBJECT, Field.PROPERTY, Field.CALLEE})
# A node whose own text is a segment: an identifier, or an M1 subscript key.
_SEGMENT_KINDS = frozenset({Kind.NAME, Kind.LITERAL})
_KINDS = tuple(Kind)
_FIELDS = tuple(Field)
# R3's literal classes (``_validate.LITERAL_CLASSES``, what the validator admits), each held
# once: a record names its class by this shared string, not by the string the decoder made
# for it (one per literal).
_LITERAL_CLASSES: Mapping[str, str] = MappingProxyType({name: name for name in LITERAL_CLASSES})


@dataclass(frozen=True, slots=True)
class _Columns:
    """The six §6.2 columns of one document, as ``array('i')``."""

    kind: array[int]
    parent: array[int]
    field: array[int]
    sb: array[int]
    eb: array[int]
    sl: array[int]


def _links(cols: _Columns, i: int) -> bool:
    """Node ``i`` continues its parent's chain: an OBJECT, PROPERTY or CALLEE child of a
    MEMBER, SUBSCRIPT or CALL, or an M1 LITERAL key in a SUBSCRIPT's INDEX."""
    parent = cols.parent[i]
    return parent >= 0 and cols.kind[parent] in _CHAIN_KINDS and _link_position(cols.kind, cols.field, i)


def _link_position(kinds: Sequence[int], fields: Sequence[int], i: int) -> bool:
    """Node ``i`` hangs under OBJECT, PROPERTY or CALLEE, or is an M1 LITERAL key."""
    fld = fields[i]
    return fld in _LINK_FIELDS or (fld == Field.INDEX and kinds[i] == Kind.LITERAL)


def _has_segment(kinds: Sequence[int], text: Mapping[int, str], i: int) -> bool:
    """Node ``i``'s own text is a chain segment."""
    return bool(text.get(i)) and kinds[i] in _SEGMENT_KINDS


def _segment(kinds: Sequence[int], text: Mapping[int, str], i: int) -> str | None:
    """Node ``i``'s own glued segment, if it carries one."""
    return glue(text[i]) if _has_segment(kinds, text, i) else None


# ── the indexes (one linear pass each) ───────────────────────────────────────


def _csr(keys: list[int], buckets: int, items: Sequence[int]) -> tuple[array[int], array[int]]:
    """``items`` grouped by ``keys[item]`` in key order, document order kept within a key: the
    ``buckets + 1`` start offsets and the grouped list, so bucket ``b`` is
    ``out[start[b]:start[b + 1]]``. The grouping is one stable sort, in C."""
    counts = [0] * (buckets + 1)
    for key in map(keys.__getitem__, items):
        counts[key + 1] += 1
    return array("i", accumulate(counts)), array("i", sorted(items, key=keys.__getitem__))


def _by_parent_then_field(parents: list[int], fields: list[int]) -> array[int]:
    """Every non-root node grouped by parent, then by Field within a parent, document order
    kept within a group (one stable sort on ``parent * len(Field) + field``)."""
    keys = list(map(add, map(mul, parents, repeat(len(_FIELDS))), fields))
    return array("i", sorted(range(1, len(keys)), key=keys.__getitem__))


def _nearest(kinds: list[int], parents: list[int], wanted: frozenset[Kind]) -> array[int]:
    """Each node's nearest strict ancestor of a kind in ``wanted``, or ``-1``: a parent
    precedes its children, so one forward pass reads each answer off the parent's."""
    hit = [kind in wanted for kind in _KINDS]
    out = [-1] * len(kinds)
    for i in range(1, len(kinds)):
        parent = parents[i]
        out[i] = parent if hit[kinds[parent]] else out[parent]
    return array("i", out)


def _columns(doc: Mapping[str, Any]) -> _Columns:
    return _Columns(*(array("i", doc[name]) for name in COLUMNS))


def _deduplicated(text: Mapping[int, str]) -> tuple[dict[int, str], Iterable[str]]:
    """``text`` with each distinct value held once — a file repeats its identifiers, and the
    decoder builds a new string per occurrence — and those distinct values. Per file, never
    ``sys.intern`` (an interned string lives as long as the process)."""
    seen: dict[str, str] = {}
    return {i: seen.setdefault(value, value) for i, value in text.items()}, seen.values()


def _literal(entry: Sequence[Any]) -> Literal_:
    """A validated ``lit`` entry as its record, its class the shared string."""
    return Literal_(_LITERAL_CLASSES[entry[0]], *entry[1:])


class _Lines(Sequence[str]):
    """``text.split("\\n")`` as a sequence (D21), holding the text once plus each line's start
    offset: a line is sliced out when it is read, instead of every line being its own string
    for as long as the model is cached. ``text`` is the text whole, the one decode whose UTF-8
    encoding every span indexes (§4)."""

    __slots__ = ("_starts", "_text")

    def __init__(self, text: str) -> None:
        self._text = text
        lengths = (len(line) + 1 for line in text.split("\n"))
        self._starts = array("i", accumulate(lengths, initial=0))

    @property
    def text(self) -> str:
        return self._text

    def __len__(self) -> int:
        return len(self._starts) - 1

    @overload
    def __getitem__(self, k: int) -> str: ...
    @overload
    def __getitem__(self, k: slice) -> list[str]: ...
    def __getitem__(self, k: int | slice) -> str | list[str]:
        if isinstance(k, slice):
            return [self._line(j) for j in range(*k.indices(len(self)))]
        return self._line(range(len(self))[k])  # negative and out-of-range k as a list's

    def _line(self, k: int) -> str:
        return self._text[self._starts[k] : self._starts[k + 1] - 1]


# ── cap tallies (D18, §8.7), counted over constructs ─────────────────────────


def _chain_overflows(
    kinds: list[int], parents: list[int], fields: list[int], text: Mapping[int, str]
) -> int:
    """Chains of more than ``MAX_CHAIN`` segments, each counted once, at its outermost node.

    A chain's segments are the segment nodes whose climb along ``_links`` ends at its
    outermost node (the first node that does not link), so each segment is tallied at its
    ``top``. A parent precedes its children, so one forward pass over the linking nodes
    reads each one's top off its parent's. Only a linking node can be one of more than one
    segment (a top is always a chain kind, never a segment), so the segments are counted in
    that same pass."""
    top = list(range(len(parents)))
    segments: Counter[int] = Counter()
    for i in _linking(kinds, parents, fields):
        top[i] = top[parents[i]]
        if _has_segment(kinds, text, i):
            segments[top[i]] += 1
    return sum(count > MAX_CHAIN for count in segments.values())


def _linking(kinds: list[int], parents: list[int], fields: list[int]) -> list[int]:
    """``_links`` over every node, in document order: the children of a chain kind (one
    comprehension over the parent column), then ``_link_position`` on those alone."""
    chained = [kinds[parent] in _CHAIN_KINDS for parent in parents[1:]]
    linked = compress(range(1, len(parents)), chained)
    return [i for i in linked if _link_position(kinds, fields, i)]


def _words_overflows(kinds: list[int], text: Mapping[int, str]) -> int:
    """Identifiers of more than ``MAX_WORDS`` words. A word is at least one character, so
    only an identifier longer than ``MAX_WORDS`` characters is split."""
    return sum(
        len(value) > MAX_WORDS and kinds[i] in IDENTIFIER_KINDS and word_count(value) > MAX_WORDS
        for i, value in text.items()
    )


# ── the model ────────────────────────────────────────────────────────────────


def _uncharged(_weight: int) -> None:
    """A model no cache stored charges nothing (A35: served, not stored)."""


@dataclass(slots=True, eq=False)
class _Held:
    """What a model holds past its build (§5, A35): its one analysis, once built, and what the
    model cache charges its weight to (``FileModel.charge_to``)."""

    analysis: FlowAnalysis | None = None
    charge: Callable[[int], None] = _uncharged


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class FileModel:
    """One file's parsed skeleton (LLD §5, §6): immutable and shared across audits.

    Built only by ``from_doc``. Node ``0`` is the MODULE; ``parent(0) == -1``.
    """

    language: str
    grammar: str
    size: int
    error_nodes: int
    unmapped: Mapping[str, int]
    nl_lines: _Lines
    tallies: Mapping[str, int]
    bytes_estimate: int
    _cols: _Columns
    _text: Mapping[int, str]
    _lit: Mapping[int, Literal_]
    _kind_start: array[int]
    _by_kind: memoryview
    _child_start: array[int]
    _children: memoryview
    _child_fields: array[int]
    _by_field: memoryview
    _function_of: array[int]
    _block_of: array[int]
    _kind_ids: memoryview
    _field_ids: memoryview
    _chains: dict[int, tuple[str, ...]] = dataclasses.field(default_factory=dict, repr=False)
    # The memoised analysis (``analysis``) and the model cache's charge (``charge_to``, A35).
    _held: _Held = dataclasses.field(default_factory=_Held, repr=False)
    _lock: Lock = dataclasses.field(default_factory=Lock, repr=False)

    @classmethod
    def from_doc(cls, doc: Mapping[str, Any], text: str) -> FileModel:
        """The model of a document ``validate_model`` admitted (its language, grammar stamp
        and columns), built from ``text`` — the decoded text whose UTF-8 encoding the worker
        parsed (every span indexes it). The validated columns are read in place, not copied."""
        cols = _columns(doc)
        kinds, parents, fields = (doc[name] for name in ("kind", "parent", "field"))
        n = len(kinds)
        kind_start, by_kind = _csr(kinds, len(_KINDS), range(n))
        child_start, children = _csr(parents, n, range(1, n))
        by_field = _by_parent_then_field(parents, fields)
        texts, distinct = _deduplicated(doc["text"])
        lits = {i: _literal(entry) for i, entry in doc["lit"].items()}
        unmapped = dict(doc["unmapped"])
        model = cls(
            language=doc["language"],
            grammar=_stamped(doc["grammar"]),
            size=doc["size"],
            error_nodes=doc["error_nodes"],
            unmapped=MappingProxyType(unmapped),
            nl_lines=_Lines(text),
            tallies=MappingProxyType({}),
            bytes_estimate=0,
            _cols=cols,
            _text=MappingProxyType(texts),
            _lit=MappingProxyType(lits),
            _kind_start=kind_start,
            _by_kind=memoryview(by_kind),
            _child_start=child_start,
            _children=memoryview(children),
            _child_fields=array("i", map(fields.__getitem__, by_field)),
            _by_field=memoryview(by_field),
            _function_of=_nearest(kinds, parents, frozenset({Kind.FUNCTION})),
            _block_of=_nearest(kinds, parents, frozenset({Kind.BLOCK, Kind.MODULE})),
            _kind_ids=memoryview(cols.kind).toreadonly(),
            _field_ids=memoryview(cols.field).toreadonly(),
        )
        # The cap tallies read the model's own queries, so they count what those answer.
        tallies = model._count_tallies(kinds, parents, fields)
        footprint = _footprint(model, (texts, lits, unmapped, tallies), distinct)
        built = MappingProxyType(tallies)
        return dataclasses.replace(model, tallies=built, bytes_estimate=footprint)

    @property
    def node_count(self) -> int:
        """How many nodes the model has (node indices are ``range(node_count)``)."""
        return len(self._cols.kind)

    # ── one node ──

    @property
    def kind_ids(self) -> Sequence[int]:
        """Each node's ``Kind`` as its int, in node order (read-only): what a pass that
        dispatches on every node's kind indexes, instead of calling ``kind`` per node."""
        return self._kind_ids

    @property
    def field_ids(self) -> Sequence[int]:
        """Each node's ``Field`` as its int, in node order (read-only), as ``kind_ids``."""
        return self._field_ids

    def kind(self, i: int) -> Kind:
        return _KINDS[self._cols.kind[i]]

    def parent(self, i: int) -> int:
        return self._cols.parent[i]

    def field(self, i: int) -> Field:
        return _FIELDS[self._cols.field[i]]

    def span(self, i: int) -> tuple[int, int]:
        """Byte offsets into ``text.encode("utf-8")``."""
        return self._cols.sb[i], self._cols.eb[i]

    def line(self, i: int) -> int:
        """1-based start line, counted by ``\\n`` only (D21)."""
        return self._cols.sl[i] + 1

    def ident(self, i: int) -> str | None:
        """The node's shipped text (§6.2), or None."""
        return self._text.get(i)

    def literal(self, i: int) -> Literal_:
        """The node's literal record; ``NO_LITERAL`` when it carries none."""
        return self._lit.get(i, NO_LITERAL)

    def function_of(self, i: int) -> int:
        """The nearest FUNCTION strictly above ``i``, or ``-1`` at module level."""
        return self._function_of[i]

    def block_of(self, i: int) -> int:
        """The nearest BLOCK or MODULE strictly above ``i`` (W2); ``-1`` for the root."""
        return self._block_of[i]

    # ── indexes ──

    def nodes(self, kind: Kind) -> Sequence[int]:
        """Every node of ``kind``, in document order."""
        return self._by_kind[self._kind_start[kind] : self._kind_start[kind + 1]]

    def children(self, i: int, field: Field | None = None) -> Sequence[int]:
        """``i``'s children in document order; with ``field``, only those under it."""
        lo, hi = self._child_start[i], self._child_start[i + 1]
        if field is None:
            return self._children[lo:hi]
        first = bisect_left(self._child_fields, field, lo, hi)
        return self._by_field[first : bisect_right(self._child_fields, field, first, hi)]

    def texts_outside(self, field: Field) -> frozenset[str]:
        """Every distinct text the model ships on a node whose Field is not ``field``: one pass
        over the shipped texts, unmemoised (a pass that reads it asks once)."""
        fields = self._cols.field
        return frozenset({text for i, text in self._text.items() if fields[i] != field})

    def first_child(self, i: int, field: Field) -> int:
        """``i``'s first child under ``field``, or ``-1`` (also for ``i == -1``)."""
        if i < 0:
            return -1
        starts, fields = self._child_start, self._child_fields
        hi = starts[i + 1]
        k = bisect_left(fields, field, starts[i], hi)
        return self._by_field[k] if k < hi and fields[k] == field else -1

    def functions(self) -> Sequence[int]:
        return self.nodes(Kind.FUNCTION)

    def calls(self) -> Sequence[int]:
        return self.nodes(Kind.CALL)

    def catches(self) -> Sequence[int]:
        return self.nodes(Kind.CATCH)

    def loops(self) -> Sequence[int]:
        return self.nodes(Kind.LOOP)

    # ── calls ──

    def callee(self, call: int) -> int:
        """The CALL's CALLEE child, or ``-1``."""
        return self.first_child(call, Field.CALLEE)

    def args(self, call: int) -> Sequence[int]:
        """The CALL's positional arguments (KWARGs excluded, W1), the first ``MAX_ARGS``
        of them, positions unshifted; the rest are ignored and tallied (§8.7)."""
        return tuple(islice(self._positional(call), MAX_ARGS))

    def kwargs(self, call: int) -> Mapping[str, int]:
        """The CALL's keyword arguments: name -> the value node."""
        return dict(pair for c in self._args_of(call) if (pair := self._kwarg(c)) is not None)

    def chain_words(self, i: int) -> tuple[str, ...]:
        """The glued segments of ``i``'s chain in source order (L1 (a), W3, M1), at most
        the last ``MAX_CHAIN`` of them, so the callee's own key always survives."""
        hit = self._chains.get(i)
        return hit if hit is not None else self._fill_chain(i)

    # ── flow ──

    def analysis(self) -> FlowAnalysis:
        """The file's one pure flow analysis, built once under the model's lock (§5); once
        built, read without the lock. A35: its first build tells the model cache its
        ``bytes_estimate`` (``charge_to``)."""
        built = self._held.analysis
        return built if built is not None else self._built_analysis()

    def release(self) -> None:
        """Drop the memoised analysis (§5): a holder that asks again builds the same pure
        analysis. The analysis refers to its model weakly, so no cycle needs this to be freed."""
        self._held.analysis = None

    def charge_to(self, charge: Callable[[int], None]) -> None:
        """A35: ``charge(weight)`` is told the ``bytes_estimate`` of each analysis this model
        builds — the model cache sets it on every model it stores, so the entry's charge
        covers the analysis."""
        self._held.charge = charge

    def _built_analysis(self) -> FlowAnalysis:
        held = self._held
        with self._lock:
            built = held.analysis
            fresh = built is None
            if fresh:
                built = held.analysis = _analysed(self)
        if fresh:
            held.charge(built.bytes_estimate)
        return built

    # ── helpers ──

    def _args_of(self, call: int) -> Sequence[int]:
        """The children of the CALL's ARGS container (none without one)."""
        container = self.first_child(call, Field.ARGS)
        return self.children(container) if container >= 0 else ()

    def _kwarg(self, i: int) -> tuple[str, int] | None:
        """``(name, value node)`` when ``i`` is a KWARG with both, else None."""
        if self._cols.kind[i] != Kind.KWARG:
            return None
        name = self._kwarg_name(i)
        value = self.first_child(i, Field.VALUE)
        return (name, value) if name and value >= 0 else None

    def _kwarg_name(self, kw: int) -> str | None:
        """A KWARG's name: its own text, else its NAME child's."""
        return self._text.get(kw) or self._text.get(self.first_child(kw, Field.NAME))

    def _positional(self, call: int) -> Iterator[int]:
        """The CALL's positional arguments, all of them (W1: KWARGs are not positional)."""
        return (c for c in self._args_of(call) if self._cols.kind[c] != Kind.KWARG)

    def _count_tallies(
        self, kinds: list[int], parents: list[int], fields: list[int]
    ) -> dict[str, int]:
        """The cap tallies of this file (D18, §8.7), one count per construct, over the
        columns ``from_doc`` already holds as lists."""
        return {
            ARGS_CAPPED: sum(sum(1 for _ in self._positional(c)) > MAX_ARGS for c in self._wide_calls()),
            CHAIN_TRUNCATED: _chain_overflows(kinds, parents, fields, self._text),
            WORDS_CAPPED: _words_overflows(kinds, self._text),
        }

    def _wide_calls(self) -> list[int]:
        """The CALLs whose ARGS container has more than ``MAX_ARGS`` children: the only calls
        that can carry more than ``MAX_ARGS`` positional arguments (found from the CSR offsets
        in C, so the tally reads one call in thousands, not every call)."""
        starts = self._child_start
        degrees = map(sub, starts[1:], starts[:-1])
        wide = compress(range(len(starts) - 1), map(gt, degrees, repeat(MAX_ARGS)))
        return [self._cols.parent[c] for c in wide if self._is_args_container(c)]

    def _is_args_container(self, i: int) -> bool:
        """Node ``i`` is the container ``args`` reads for its parent CALL."""
        parent = self._cols.parent[i]
        return parent >= 0 and self._cols.kind[parent] == Kind.CALL and self.first_child(parent, Field.ARGS) == i

    def _links_of(self, i: int) -> list[int]:
        """``i``'s children that continue its chain."""
        return [c for c in self.children(i) if _links(self._cols, c)]

    def _fill_chain(self, i: int) -> tuple[str, ...]:
        """``i``'s chain and every unmemoised chain below it, children first, with an
        explicit stack (a chain may nest up to ``MAX_DEPTH`` deep). Each node's linked
        children are found once, when it is pushed, and ride on the stack with it. The walk
        fills a memo of its own; the model keeps it while it holds fewer than ``WORDS_MEMO``
        chains (``_keep``)."""
        fresh: dict[int, tuple[str, ...]] = {}
        stack = [(i, self._links_of(i))]
        while stack:
            node, links = stack[-1]
            pending = self._unfilled(links, fresh)
            if pending:
                stack.extend((c, self._links_of(c)) for c in pending)
                continue
            stack.pop()
            fresh.setdefault(node, self._joined(node, links, fresh))
        self._keep(fresh)
        return self._chains.get(i, fresh[i])

    def _keep(self, fresh: Mapping[int, tuple[str, ...]]) -> None:
        """Memoise the chains of ``fresh`` (children first) while the model holds fewer than
        ``WORDS_MEMO`` (A38: the memo is bounded; neither estimate charges it, A17)."""
        room = max(WORDS_MEMO - len(self._chains), 0)
        for node, chain in islice(fresh.items(), room):
            self._chains.setdefault(node, chain)

    def _unfilled(self, links: list[int], fresh: Mapping[int, tuple[str, ...]]) -> list[int]:
        """The linked children whose chain is neither memoised nor walked yet."""
        return [c for c in links if c not in self._chains and c not in fresh]

    def _joined(self, i: int, links: list[int], fresh: Mapping[int, tuple[str, ...]]) -> tuple[str, ...]:
        """``i``'s linked children's chains, then its own segment; the last ``MAX_CHAIN``."""
        parts = [w for c in links for w in self._chains.get(c, fresh.get(c, ()))]
        own = _segment(self._cols.kind, self._text, i)
        return tuple(parts + [own] if own else parts)[-MAX_CHAIN:]


def _analysed(model: FileModel) -> FlowAnalysis:
    """The model's flow analysis, built (``flow`` is imported on first use: D1)."""
    from shared.ast.flow import FlowAnalysis

    return FlowAnalysis(model)


# ── bytes_estimate: the built footprint (A17) ─────────────────────────────────

# A node index above CPython's shared small ints (``_sizing``) is an int of its own, held as a
# key of ``_text`` / ``_lit``. A one-character ASCII string is shared the same way.
_LITERAL_SIZE = sys.getsizeof(NO_LITERAL)


def _containers(model: FileModel) -> tuple[object, ...]:
    """Every container object the model holds of its own: itself, its column record and
    arrays, its indexes (each memoryview with the array under it), its line index, the
    read-only views over its tables, and its (empty) memos and lock."""
    cols, lines = model._cols, model.nl_lines
    views = (model._by_kind, model._children, model._by_field)
    return (
        model, cols, *(getattr(cols, name) for name in COLUMNS),
        model._kind_start, model._child_start, model._child_fields, model._function_of,
        model._block_of, *views, *(view.obj for view in views), lines, lines._starts,
        model._kind_ids, model._field_ids,  # read-only views over two columns above
        model._text, model._lit, model.unmapped, model.tallies, model._chains, model._held,
        model._lock,
    )


def _strings(
    model: FileModel, distinct: Iterable[str], lits: Mapping[int, Literal_]
) -> Iterator[str]:
    """Every string the model holds of its own (``_sizing.own_strs``): the text, its stamps,
    each distinct shipped text, each literal value and each ``unmapped`` type name."""
    own = (model.nl_lines.text, model.language, model.grammar)
    return own_strs((*own, *distinct, *_literal_values(lits), *model.unmapped))


def _literal_values(lits: Mapping[int, Literal_]) -> Iterator[str]:
    """The values the literal records carry (booleans and short numbers, D16)."""
    return (lit.value for lit in lits.values() if lit.value)


def _footprint(
    model: FileModel, tables: Sequence[Mapping[Any, Any]], distinct: Iterable[str]
) -> int:
    """A17: ``bytes_estimate`` is what ``from_doc`` built and the model keeps — every array
    buffer, list and dict slot, the text and each distinct string — by ``sys.getsizeof``, so
    the model cache's byte budget (D5) bounds memory, not a number. ``tables`` are the dicts
    under the model's read-only views (text, lit, unmapped, tallies). Computed once, at build,
    in O(texts + literals). A model's memos grow after the build: ``chain_words`` is not
    counted (risk 15), and the analysis is charged to the model's cache entry on its own
    (A35, ``FlowAnalysis.bytes_estimate``)."""
    texts, lits = tables[0], tables[1]
    return (
        sum(map(sys.getsizeof, _containers(model)))
        + sum(map(sys.getsizeof, tables))
        + sum(map(sys.getsizeof, _strings(model, distinct, lits)))
        + INT_SIZE * (own_int_count(texts) + own_int_count(lits))
        + _LITERAL_SIZE * len(lits)
    )
