"""Worker-built answers: what a consumer reads of a file, built in a worker and admitted at the
boundary (feature 0102, LLD §4.1 items 1-3, D3'; A44 (2), user decision D-I (ii)).

A consumer of the AST tier never reads a file's skeleton: it reads the model's coverage facts
and the candidate flows of every family the file's language owns. In production a WORKER builds
those facts, by the code the parent's library path runs (``FileModel.from_doc``, then
``analysis()``, which builds every owned family, A38), and ships them as the file's ANSWER: the
parent's per-file CPU — the skeleton decode, ``validate_reply``, ``from_doc`` and the analysis —
runs in the W workers instead of under the parent's GIL. The analysis is per file, pure and
audit-independent (D8), so an answer is cached across audits as a model is (``cache``).

* ``answer_of`` / ``encode`` (the worker's side, imported only inside its answer branch, A16):
  the answer document ``{schema, language, grammar, size, error_nodes, unmapped, tallies,
  analysis_tallies, families: {family: [flow, ...]}}``. A flow is a JSON object keyed by the
  ``Flow`` field names: ``origins`` a sorted list of ``[cls, role, [via...]]``, ``hops`` of
  ``[line, kind, name]``, ``guards`` of ``[node, [roles...]]``, ``span`` ``[start, end]``,
  ``filtered_roles`` sorted. A model with an ERROR node ships no analysis: no consumer reads it.
* ``validate_answer`` (D3', the parent's side) bounds what a forged answer can reach to what a
  validated skeleton reaches (§11 T10, T11). The answer is bound to its request (language, the
  stamp of its entry point, size, ``ANSWER_SCHEMA``); every vocabulary is closed (families the
  profile owns, origin classes, §8.1 roles and reasons, sanitiser and guard roles, §8.6 hop
  kinds, the tally names ``coverage`` defines); every name obeys D16; every line lies within
  the shipped text's ``\\n`` lines, every span within its bytes, every node id below
  ``MAX_NODES``; at most ``MAX_ORIGINS`` origins and ``MAX_HOPS`` hops; counts are never
  negative; ints and bools are of their JSON type. Anything else is ``ModelError``
  (``bad_model``). Records are built after their check, through ``_records``' shared
  constructors, and equal origin sets and strings are one object per answer.
* ``FileAnswer`` (frozen, slots) is what ``cache.owns_answer`` serves: the coverage facts, the
  stamp — registered as a model's is (``model.stamped``), so ``grammar_stamp`` is unchanged
  (A41 (4)) — ``analysis()``, ``nl_lines`` (the PARENT's ``text.split("\\n")``, D21, kept only
  when some family has a candidate: with none, no row is ever numbered) and ``bytes_estimate``,
  the footprint A17's rule counts. ``charge_to`` is a no-op: nothing is built after D3', so
  A35 has nothing to charge.

``encode`` and ``validate_answer`` read one table, ``_FLOW_FIELDS``: one codec per ``Flow``
field, in the record's order (D19). ``FileFacts`` is what a ``FileModel`` and a ``FileAnswer``
both are to ``consume`` and ``coverage``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from itertools import chain
from types import MappingProxyType
from typing import Any, NamedTuple, Protocol

from shared.ast import ANSWER_SCHEMA
from shared.ast._records import (
    EXPR,
    EXTERNAL,
    EXTERNAL_ROLES,
    FLAG,
    HOP_KINDS,
    INDEX,
    UNKNOWN,
    UNKNOWN_REASONS,
    Flow,
    Guard,
    Hop,
    Origin,
    Origins,
    external,
    role_set,
    unknown,
)
from shared.ast._sizing import flow_parts, own_ints, own_strs, sized_once
from shared.ast._validate import (
    IDENTIFIER,
    admissible,
    counts_ok,
    exact_int,
    frame_head,
    request_binding,
    require,
    require_all,
    spelled,
    validate_reply,
)
from shared.ast.coverage import (
    ARGS_CAPPED,
    BRANCH_DEPTH,
    CHAIN_TRUNCATED,
    ORIGIN_OVERFLOW,
    SUMMARY_CAP,
    WORDS_CAPPED,
)
from shared.ast.limits import MAX_HOP_SEGMENTS, MAX_HOPS, MAX_NODES, MAX_ORIGINS, MAX_TEXT_BYTES
from shared.ast.model import FileModel, Lines, stamped
from shared.ast.profile import PROFILES
from shared.ast.profiles import FAMILIES, LanguageProfile
from shared.ast.roles import (
    CHECKED_ROLE_WORDS,
    CONDITIONAL_SOURCE_ROOTS,
    CONTAINMENT_ROLES,
    COVERED_BY,
    COVERING_GUARDS,
    GUARD_KEYS,
    GUARD_OPERATORS,
    GUARD_WORDS,
    SANITIZER_KEYS,
    SANITIZER_WORDS,
    SOURCE_CALL_KEYS,
    SOURCE_ROLES_BY_FAMILY,
    SOURCE_WORDS,
    glue,
)

__all__ = [
    "Analysis",
    "AnswerAnalysis",
    "FileAnswer",
    "FileFacts",
    "answer_of",
    "encode",
    "validate_answer",
]

# ── what a consumer reads (§4.1 item 3) ──────────────────────────────────────


class Analysis(Protocol):
    """What a consumer reads of a file's analysis: its per-file fact counts and each family's
    candidates (``FlowAnalysis`` and ``AnswerAnalysis``)."""

    @property
    def tallies(self) -> Mapping[str, int]: ...

    def candidates(self, family: str) -> tuple[Flow, ...]: ...


class FileFacts(Protocol):
    """What the tier serves a consumer of one file, a ``FileModel`` or a ``FileAnswer``: the
    coverage facts ``coverage.record_model`` reads and the analysis and lines
    ``consume.family_spans`` reads."""

    @property
    def language(self) -> str: ...

    @property
    def grammar(self) -> str: ...

    @property
    def error_nodes(self) -> int: ...

    @property
    def unmapped(self) -> Mapping[str, int]: ...

    @property
    def tallies(self) -> Mapping[str, int]: ...

    @property
    def nl_lines(self) -> Sequence[str]: ...

    def analysis(self) -> Analysis: ...


class AnswerAnalysis:
    """An answer's analysis: the per-file fact counts and each owned family's candidates the
    worker's ``FlowAnalysis`` built, read as ``FileModel.analysis()`` is read."""

    __slots__ = ("_candidates", "tallies")

    def __init__(self, candidates: dict[str, tuple[Flow, ...]], tallies: Mapping[str, int]) -> None:
        self._candidates = candidates
        self.tallies = tallies

    def candidates(self, family: str) -> tuple[Flow, ...]:
        """Every ``family`` sink argument the worker's analysis kept, sorted by sink line; none
        for a family the file's language does not own."""
        return self._candidates.get(family, ())


@dataclass(frozen=True, slots=True, eq=False)
class FileAnswer:
    """One file's answer (§4.1 item 3): immutable and shared across audits, as a model is."""

    language: str
    grammar: str
    error_nodes: int
    unmapped: Mapping[str, int]
    tallies: Mapping[str, int]
    nl_lines: Sequence[str]
    bytes_estimate: int
    _analysis: AnswerAnalysis

    def analysis(self) -> AnswerAnalysis:
        """The analysis the worker built (none past an ERROR node: no consumer asks)."""
        return self._analysis

    def charge_to(self, _charge: Callable[[int], None]) -> None:
        """A35 has nothing to charge: an answer builds nothing after D3'."""


# ── the closed vocabularies (D3') ────────────────────────────────────────────


def _unlisted(minted: Iterable[str], vocabulary: frozenset[str]) -> None:
    """Raise at import when a table mints a word ``vocabulary`` does not admit: a role added to
    a §9.1 table alone would otherwise make D3' refuse every answer carrying it (``bad_model``,
    a silent regex fallback), never fail a run."""
    stray = sorted(frozenset(minted) - vocabulary)
    if stray:
        raise ImportError(f"source roles outside EXTERNAL_ROLES: {stray}")


# The source roles the §9.1 tables and the profiles' builtin sources mint (D22, W9): each must
# be one an answer may carry (§8.1).
_unlisted(chain(
    SOURCE_WORDS, SOURCE_CALL_KEYS.values(), *SOURCE_ROLES_BY_FAMILY.values(),
    (role for roots in CONDITIONAL_SOURCE_ROOTS.values() for role in roots.values()),
    (role for profile in PROFILES.values() for role in profile.builtin_sources.values()),
), EXTERNAL_ROLES)

_FAMILY_NAMES = spelled(FAMILIES)
_SOURCE_ROLES = spelled(EXTERNAL_ROLES)
_REASONS = spelled(UNKNOWN_REASONS)
# Every sanitiser and guard role the §9.1 tables name: what a ``via`` and a guard may hold.
_ROLES = spelled(frozenset().union(
    SANITIZER_WORDS, SANITIZER_KEYS, GUARD_WORDS, GUARD_KEYS, CHECKED_ROLE_WORDS,
    CONTAINMENT_ROLES, *GUARD_OPERATORS.values(), *COVERED_BY.values(), *COVERING_GUARDS.values(),
))
_HOP_KINDS = spelled(HOP_KINDS)
_PLACEHOLDERS = frozenset({INDEX, FLAG})
# §10.2: the per-file fact counts a model carries, and those its analysis carries (A28 (3)).
_MODEL_TALLIES = frozenset({ARGS_CAPPED, CHAIN_TRUNCATED, WORDS_CAPPED})
_ANALYSIS_TALLIES = frozenset({BRANCH_DEPTH, ORIGIN_OVERFLOW, SUMMARY_CAP})
# The answer document's members; ``id`` is the worker frame's (D3).
_HEAD = frozenset({
    "schema", "language", "grammar", "size", "error_nodes", "unmapped", "tallies",
    "analysis_tallies", "families",
})
_KEYS = _HEAD | {"id"}


def _named(value: object, vocabulary: Mapping[str, str]) -> str | None:
    """``value``'s spelling in ``vocabulary``, or None (for any value that is not a string)."""
    return vocabulary.get(value) if type(value) is str else None


@dataclass(frozen=True, slots=True)
class _Bounds:
    """What D3' reads one family's flows against: the family's spelling, the shipped bytes'
    size and ``\\n`` lines (D21), and the answer's shared values (one object per equal origin
    set or string)."""

    family: str
    size: int
    lines: int
    shared: dict[object, Any]

    def share[V](self, value: V) -> V:
        """``value``, or the equal one this answer already holds."""
        return self.shared.setdefault(value, value)


# ── one codec per Flow field (D19) ───────────────────────────────────────────


def _as_is(value: Any) -> Any:
    return value


def _family(value: object, bounds: _Bounds) -> str:
    require(value == bounds.family, "flow family")
    return bounds.family


def _node(value: Any, _bounds: object = None) -> int:
    require(exact_int(value, 0, MAX_NODES - 1), "node id")
    return value


def _line(value: Any, bounds: _Bounds) -> int:
    require(exact_int(value, 1, bounds.lines), "line")
    return value


def _pair(value: object) -> bool:
    return type(value) is list and len(value) == 2


def _span(value: Any, bounds: _Bounds) -> tuple[int, int]:
    require(_pair(value), "span")
    start, end = value
    require(exact_int(start, 0, bounds.size) and exact_int(end, start, bounds.size), "span")
    return start, end


def _flag(value: Any, _bounds: _Bounds) -> bool:
    require(type(value) is bool, "flag")
    return value


def _roles(value: Any, vocabulary: Mapping[str, str]) -> frozenset[str]:
    """A list of roles, each in ``vocabulary``, as the one shared set of them (``role_set``)."""
    require(type(value) is list, "roles")
    names = [_named(role, vocabulary) for role in value]
    require(None not in names, "role")
    return role_set(frozenset(names))  # type: ignore[arg-type]


def _filtered(value: Any, _bounds: _Bounds) -> frozenset[str]:
    """R-P's removed roles (A28 (3)): source roles."""
    return _roles(value, _SOURCE_ROLES)


def _sink_key(value: Any, bounds: _Bounds) -> str:
    """Empty, or ``glue`` of a D16 identifier no longer than ``MAX_TEXT_BYTES`` (L1 (a))."""
    require(value == "" or _glued(value), "sink key")
    return bounds.share(value)


def _glued(value: object) -> bool:
    return admissible(IDENTIFIER, value) and len(value) <= MAX_TEXT_BYTES and glue(value) == value  # type: ignore[arg-type]


def _origins(value: Any, bounds: _Bounds) -> Origins:
    require(type(value) is list and len(value) <= MAX_ORIGINS, "origins")
    return bounds.share(frozenset(map(_origin, value)))


def _origin(entry: Any) -> Origin:
    """``[cls, role, via]`` (§8.1): through ``_records``' shared constructors, once checked."""
    require(type(entry) is list and len(entry) == 3, "origin")
    cls, role, via = entry
    read = _ORIGIN_CLASSES.get(cls) if type(cls) is str else None
    require(read is not None, "origin class")
    return read(role, via)  # type: ignore[misc]


def _external(role: object, via: object) -> Origin:
    name = _named(role, _SOURCE_ROLES)
    require(name is not None, "origin role")
    return external(name, _roles(via, _ROLES))  # type: ignore[arg-type]


def _unknown(role: object, via: object) -> Origin:
    name = _named(role, _REASONS)
    require(name is not None and via == [], "origin reason")
    return unknown(name)  # type: ignore[arg-type]


_ORIGIN_CLASSES: Mapping[str, Callable[[object, object], Origin]] = MappingProxyType({
    EXTERNAL: _external, UNKNOWN: _unknown,
})


def _hops(value: Any, bounds: _Bounds) -> tuple[Hop, ...]:
    require(type(value) is list and len(value) <= MAX_HOPS, "hops")
    return tuple(_hop(entry, bounds) for entry in value)


def _hop(entry: Any, bounds: _Bounds) -> Hop:
    require(type(entry) is list and len(entry) == 3, "hop")
    line, kind, name = entry
    spelled = _named(kind, _HOP_KINDS)
    require(spelled is not None and _hop_name(name), "hop")
    return Hop(_line(line, bounds), spelled, bounds.share(name))  # type: ignore[arg-type]


def _hop_name(name: object) -> bool:
    """D16 as A30 (2) states it: ``<expr>``, or up to ``MAX_HOP_SEGMENTS`` ``.``-joined
    segments, each a D16 identifier or a placeholder."""
    if name == EXPR:
        return True
    segments = name.split(".") if type(name) is str else []
    return 0 < len(segments) <= MAX_HOP_SEGMENTS and all(map(_segment, segments))


def _segment(segment: str) -> bool:
    return segment in _PLACEHOLDERS or admissible(IDENTIFIER, segment)


def _guards(value: Any, _bounds: _Bounds) -> tuple[Guard, ...]:
    require(type(value) is list, "guards")
    return tuple(map(_guard, value))


def _guard(entry: Any) -> Guard:
    require(_pair(entry), "guard")
    node, roles = entry
    return Guard(_node(node), _roles(roles, _ROLES))


def _origins_doc(origins: Origins) -> list[list[Any]]:
    return sorted([o.cls, o.role, sorted(o.via)] for o in origins)


def _hops_doc(hops: tuple[Hop, ...]) -> list[list[Any]]:
    return [list(hop) for hop in hops]


def _guards_doc(guards: tuple[Guard, ...]) -> list[list[Any]]:
    return [[guard.node, sorted(guard.roles)] for guard in guards]


class _Codec(NamedTuple):
    """One ``Flow`` field on the wire: how ``encode`` writes it, and how D3' reads it back
    (the checked value, or ``ModelError``)."""

    write: Callable[[Any], Any]
    read: Callable[[Any, _Bounds], Any]


_CODECS: Mapping[str, _Codec] = MappingProxyType({
    "family": _Codec(_as_is, _family),
    "sink": _Codec(_as_is, _node),
    "sink_line": _Codec(_as_is, _line),
    "span": _Codec(list, _span),
    "arg": _Codec(_as_is, _node),
    "origins": _Codec(_origins_doc, _origins),
    "hops": _Codec(_hops_doc, _hops),
    "guards": _Codec(_guards_doc, _guards),
    "truncated": _Codec(_as_is, _flag),
    "filtered_roles": _Codec(sorted, _filtered),
    "sink_key": _Codec(_as_is, _sink_key),
    "shell_sink": _Codec(_as_is, _flag),
    "built_arg": _Codec(_as_is, _flag),
    "param_bound": _Codec(_as_is, _flag),
    "builtin_program": _Codec(_as_is, _flag),
})
# The one field list (D19), in the record's order: a ``Flow`` field with no codec fails here,
# at import, never on the wire.
_FLOW_FIELDS: tuple[tuple[str, _Codec], ...] = tuple((f.name, _CODECS[f.name]) for f in fields(Flow))
_FLOW_KEYS = frozenset(name for name, _ in _FLOW_FIELDS)


# ── the worker's side (§4.1 item 1) ──────────────────────────────────────────


def answer_of(doc: Mapping[str, Any], data: bytes, profile: LanguageProfile) -> dict[str, Any]:
    """The answer to a request for ``data`` under ``profile`` (its grammar entry point the
    request's), whose skeleton is ``doc``: the document checked as the parent checks one
    (``validate_reply``, which ``from_doc`` requires), the model built from the shipped text,
    then ``encode``."""
    valid = validate_reply(doc, profile, profile.grammar_attr, data)
    return encode(FileModel.from_doc(valid, data.decode("utf-8")))


def encode(model: FileModel) -> dict[str, Any]:
    """``model``'s answer document (``id`` aside: the worker's frame adds it)."""
    head = {
        "schema": ANSWER_SCHEMA, "language": model.language, "grammar": model.grammar,
        "size": model.size, "error_nodes": model.error_nodes, "unmapped": dict(model.unmapped),
        "tallies": dict(model.tallies),
    }
    return {**head, **_analysis_doc(model)}


def _analysis_doc(model: FileModel) -> dict[str, Any]:
    """The analysis a consumer reads — its tallies and every family the language owns, in
    ``FAMILIES`` order (A38) — or none for a model with an ERROR node."""
    if model.error_nodes:
        return {"analysis_tallies": {}, "families": {}}
    analysis, owned = model.analysis(), PROFILES[model.language].owned_families
    families = {f: list(map(_flow_doc, analysis.candidates(f))) for f in FAMILIES if f in owned}
    return {"analysis_tallies": dict(analysis.tallies), "families": families}


def _flow_doc(flow: Flow) -> dict[str, Any]:
    return {name: codec.write(getattr(flow, name)) for name, codec in _FLOW_FIELDS}


# ── D3': the answer at the boundary (§4.1 item 2) ────────────────────────────


def validate_answer(
    doc: Any, profile: LanguageProfile, grammar: str, data: bytes, text: str
) -> FileAnswer:
    """The worker's answer ``doc`` to the request that shipped ``data`` — the UTF-8 encoding
    of ``text``, the parent's — under ``profile`` with its entry point ``grammar``, checked
    (D3', module docstring), then built. Raises ``ModelError`` on anything else."""
    require(isinstance(doc, dict) and _HEAD <= doc.keys() <= _KEYS, "not an answer document")
    require_all(_head_checks(doc, profile, grammar, data), "answer binding")
    bounds = _Bounds("", len(data), data.count(b"\n") + 1, {})
    return _answer(doc, profile, _families(doc["families"], profile, bounds), text)


def _head_checks(
    doc: dict[str, Any], profile: LanguageProfile, grammar: str, data: bytes
) -> dict[str, bool]:
    """The answer bound to its request, as a skeleton is (``request_binding``), and its head's
    members each within its rule."""
    return {
        **request_binding(doc, profile, grammar, data),
        **frame_head(doc, ANSWER_SCHEMA),
        "tallies": _tallies_ok(doc["tallies"], _MODEL_TALLIES),
        "analysis_tallies": _tallies_ok(doc["analysis_tallies"], _ANALYSIS_TALLIES),
    }


def _tallies_ok(counts: object, names: frozenset[str]) -> bool:
    """A tally map: each name one of ``names``, each count an int, never negative."""
    return counts_ok(counts, names.__contains__, 0, sys.maxsize)


def _families(
    value: object, profile: LanguageProfile, bounds: _Bounds
) -> dict[str, tuple[Flow, ...]]:
    """Each family's flows, every family one the profile owns."""
    require(isinstance(value, dict), "families")
    return dict(_family_flows(family, flows, profile, bounds) for family, flows in value.items())  # type: ignore[union-attr]


def _family_flows(
    family: str, flows: object, profile: LanguageProfile, bounds: _Bounds
) -> tuple[str, tuple[Flow, ...]]:
    name = _named(family, _FAMILY_NAMES)
    require(name in profile.owned_families and type(flows) is list, "family")
    own = replace(bounds, family=name)
    return name, tuple(_flow(doc, own) for doc in flows)  # type: ignore[return-value, union-attr]


def _flow(doc: object, bounds: _Bounds) -> Flow:
    require(isinstance(doc, dict) and doc.keys() == _FLOW_KEYS, "flow")
    return Flow(**{name: codec.read(doc[name], bounds) for name, codec in _FLOW_FIELDS})  # type: ignore[index]


def _answer(
    doc: dict[str, Any], profile: LanguageProfile, candidates: dict[str, tuple[Flow, ...]],
    text: str,
) -> FileAnswer:
    """The checked answer as a ``FileAnswer``: its stamp registered (``stamped``), its lines
    the parent's ``text`` when some family has a candidate (D21), its weight counted."""
    tables = (doc["unmapped"], doc["tallies"], doc["analysis_tallies"])
    unmapped, tallies, analysis_tallies = map(MappingProxyType, tables)
    built = FileAnswer(
        language=profile.language,
        grammar=stamped(doc["grammar"]),
        error_nodes=doc["error_nodes"],
        unmapped=unmapped,
        tallies=tallies,
        nl_lines=Lines(text) if any(candidates.values()) else (),
        bytes_estimate=0,
        _analysis=AnswerAnalysis(candidates, analysis_tallies),
    )
    return replace(built, bytes_estimate=_footprint(built, tables))


# ── bytes_estimate (A17's rule, ``_sizing``) ─────────────────────────────────


def _footprint(answer: FileAnswer, tables: Sequence[Mapping[str, int]]) -> int:
    """What the answer keeps, by ``sys.getsizeof``, each object once: itself, its analysis and
    candidates (each family's tuple, but the shared ``()``) and each flow's own parts — every
    hop name is the answer's own — its three tables under their read-only views with the names
    and counts they hold, its stamp, and its lines with the text when it keeps them. Computed
    once, at build, in O(flows x MAX_HOPS); the language is the profile's."""
    analysis = answer.analysis()
    found = [flows for flows in analysis._candidates.values() if flows]
    views = (answer.unmapped, answer.tallies, analysis.tallies)
    own = (answer, analysis, analysis._candidates, *views, *tables, *found, *_lines(answer))
    flows = chain.from_iterable(flow_parts(flow, _every) for flow in chain.from_iterable(found))
    total = sized_once(chain(own, _table_parts(answer.grammar, tables), flows))
    return total + sys.getsizeof(total)  # the estimate is an int the answer keeps too


def _table_parts(stamp: str, tables: Sequence[Mapping[str, int]]) -> Iterator[object]:
    """The strings and ints an answer's tables and stamp hold of their own: the stamp, each
    table's names (decoded from the wire) and its counts."""
    names = own_strs(chain((stamp,), *tables))
    counts = own_ints(chain.from_iterable(map(dict.values, tables)))  # type: ignore[arg-type]
    return chain(names, counts)


def _lines(answer: FileAnswer) -> Iterator[object]:
    """The lines an answer with a candidate keeps (the index, its offsets, the text); none for
    one without, which holds the shared ``()``."""
    lines = answer.nl_lines
    return iter(lines.parts) if isinstance(lines, Lines) else iter(())


def _every(_name: str) -> bool:
    """Every hop name of an answer is its own: decoded from the wire, not the model's text."""
    return True
