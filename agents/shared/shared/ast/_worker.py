"""The isolated parse worker (feature 0102, D2, D3, LLD §6.2, W1, W3, W11, W15 b, C3, A36).

The pool starts this module as ``[sys.executable, "-I", "-c", BOOTSTRAP]`` with a private
cwd and env ``{PATH, LANG}`` (D2); ``main()`` sets its rlimits, then answers each request —
a JSON header frame and a file-bytes frame — with ONE JSON frame: the capture skeleton of
§6.2, or ``{"id", "error"}``. A per-file failure is an answer, never an exit; end of input
ends the loop. Importing the module starts nothing.

It imports, outside ``shared.ast``, exactly ``sys``, ``json``, ``resource``, ``importlib``,
``tree_sitter`` and the grammar modules (by name, through ``importlib``), plus ``ctypes``
inside a ``try`` for ``prctl`` (``test_0102_worker_imports.py``). The profile tables come
from ``shared.ast.profile``, which is data only (D1, D19). It never opens a file: the parent
ships the bytes.

**The grammar contract (D19).** A language is loaded once per worker: its grammar, then the
query ``build_query`` GENERATES from the profile's ``NODE_MAP``, compiled against that
grammar, then the parser. A table that names a node type or field the installed grammar
lacks fails that compile, so every file of the language is answered
``worker_error:QueryError`` and falls back to the regex tier — a renamed node can never
silently ship as transparent and leave the AST tier owning a file it cannot see.

**The skeleton (W1).** One cursor walk applies the same table to every named node, in
document order. The table is prepared once per grammar entry point, with its parser, as lists
indexed by the node's integer kind id and dicts keyed by its field id (``_Table``), so a node
costs O(1) probes and the walk never reads a type or field name per node. The dispositions
are functions of a node's ANCESTRY — which field its
outermost transparent ancestor was captured under, whether it sits in a positional slot of
an ARGS container, whether a type name is inside an annotation — which a flat capture list
does not carry, so the walk, not the capture list, builds the document:

* a ``(parent type, type)`` row wins over the plain row for a direct child; a mapped row
  ships its Capture; a ``kind=None`` row is transparent with its own field map;
* an unlisted node under a field mapped to ARGS or PARAMS ships as the ARGS container;
* an unlisted node in a positional slot of an ARGS container or ARRAY that would re-parent
  more than one shipped child ships as ONE text-less BINOP, so argument positions never
  shift (it is opened as a placeholder and collapsed afterwards when it holds fewer than two);
* every other unlisted node is transparent: its shipped descendants hang from the nearest
  shipped ancestor under the Field its OUTERMOST transparent ancestor was captured with;
* a PRUNED type, and a type name (W3) outside an ANNOTATION/CALLEE position, is dropped
  with its subtree. Every transparent and dropped type is tallied in ``unmapped``;
* a row with ``callee_from`` (C3, A28 (9): the C++ stack constructor ``std::ifstream
  in(p.c_str())``) ships its node as a synthetic CALL whose CALLEE is a COPY of the name
  chain the nearest shipped ancestor holds under that Field — the declaration's type, shipped
  already because it precedes the declarators — and whose ARGS container is the node itself.
  The CALL and the copy are nodes the tree does not hold: a copy that would take the document
  past ``MAX_NODES`` is refused (``ir_too_large``) before it is made, and the finished
  document is checked against the cap once more;
* a ``callee_from`` row with a ``subscript`` shape (A36, C2: the vexing parse ``std::ifstream
  in(argv[1]);``) is that CALL only when its node holds ONE parameter of the shape, which then
  ships as its one argument, a SUBSCRIPT: the parameter's type name a NAME under OBJECT, its
  array declarator transparent under INDEX. Any other node ships by the row's own kind.

A NAME is a leaf: its identifier is its ``text``. Rows count ``\\n`` only (D21) and spans are
byte offsets into the shipped bytes. A row is read as ``start_point[0]``, never as
``start_point.row``: tree-sitter 0.26's ``Point.row`` hands back a reference it does not
own, so on a temporary point the row (any int above 256) is freed while the document still
holds it — measured as a segfault within a few dozen real files.
"""

from __future__ import annotations

import importlib
import json
import resource
import sys

import tree_sitter

from shared.ast import MODEL_SCHEMA
from shared.ast._frames import ModelError, decode_json, read_frame, write_frame
from shared.ast._validate import (
    COLUMNS,
    DECLARATION_KEYWORDS,
    IDENTIFIER,
    LIST_KINDS,
    LIT_VALUE,
    LITERAL_CLASS_WORDS,
    MODULE_PATH_SEPARATORS,
    OPERATOR_TOKENS,
    UNMAPPED_TYPE,
    admissible,
    shell_word,
    stamp_prefix,
)
from shared.ast.kinds import Field, Kind
from shared.ast.limits import (
    FRAME_CAP,
    MAX_DEPTH,
    MAX_NODES,
    MAX_TEXT_BYTES,
    WORKER_AS_BYTES,
    WORKER_CPU_HARD_S,
    WORKER_CPU_S,
)
from shared.ast.profile import GRAMMAR_PROFILES, PROFILES, build_query
from shared.ast.profiles import Capture, LanguageProfile, Subscript

__all__ = ["main", "skeleton"]

# D2: the limits a worker sets on itself, each where the platform has it, as (soft, hard).
# Risk 14: RLIMIT_CPU's hard limit sits above its soft one, so the kernel sends SIGXCPU (the
# lifecycle exit the breaker ignores) before the hard limit's SIGKILL; a SIGXCPU must not
# dump core, hence RLIMIT_CORE = 0.
_RLIMITS = (
    ("RLIMIT_AS", WORKER_AS_BYTES, WORKER_AS_BYTES),
    ("RLIMIT_CPU", WORKER_CPU_S, WORKER_CPU_HARD_S),
    ("RLIMIT_NPROC", 0, 0),
    ("RLIMIT_FSIZE", 0, 0),
    ("RLIMIT_CORE", 0, 0),
)
_PR_SET_NO_NEW_PRIVS = 38  # <linux/prctl.h>
# The `modules` probe (plan task 1.3): where this process resolved the code it runs.
_PROBED_MODULES = ("shared", "shared.ast._worker", "tree_sitter")

_CONTAINER_FIELDS = frozenset({Field.ARGS, Field.PARAMS})
# W3: where a type name names something the analysis reads.
_TYPE_FIELDS = frozenset({Field.ANNOTATION, Field.CALLEE})
_TYPE_NAMES = frozenset({"type_identifier", "namespace_identifier"})
_PLAIN_ASSIGNMENT = frozenset({"=", ":="})  # any other operator makes an ASSIGN an AUG_ASSIGN
_VALUED = frozenset({"bool", "number"})  # D3: the literal classes that may carry a value
_TEXTUAL = frozenset({"string", "char"})  # whose `lit` length counts the content (R3)
_REFINABLE = frozenset({Kind.LITERAL, Kind.ASSIGN})  # kinds `_refined` may change (M3)
# The frame stack holds a sentinel plus one frame per ancestor of the node being placed, so
# a node's cursor depth is len(frames) - 1: deeper than MAX_DEPTH is more frames than this.
_FRAMES_CAP = MAX_DEPTH + 1


class _Refused(Exception):
    """A file the worker answers with a reason instead of a model (§6.2, §8.7)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── the loop (D2, D3) ────────────────────────────────────────────────────────


def main() -> None:
    """Limit this process, then answer requests until the parent closes stdin."""
    _limit_resources()
    _forbid_new_privileges()
    _serve(sys.stdin.buffer, sys.stdout.buffer)


def _serve(inp: object, out: object) -> None:
    request = _next_request(inp)
    while request is not None:
        write_frame(out, _reply(*request))
        request = _next_request(inp)


def _next_request(inp: object) -> tuple[bytes, bytes] | None:
    """A header and its file bytes; ``None`` at end of input or on a broken frame."""
    try:
        header = read_frame(inp, FRAME_CAP)
        body = None if header is None else read_frame(inp, FRAME_CAP)
    except ModelError:
        return None
    return None if body is None else (header, body)


def _reply(header: bytes, body: bytes) -> bytes:
    """One answer frame's payload. Any exception is ``worker_error:<Type>`` — the type only,
    never its message (egress) — and the loop goes on."""
    request = _request(header)
    request_id = _request_id(request)
    try:
        return _payload(request_id, _answer(request, body))
    except _Refused as refused:
        return _payload(request_id, {"error": refused.reason})
    except Exception as exc:
        return _payload(request_id, {"error": f"worker_error:{type(exc).__name__}"})


def _request(header: bytes) -> dict[str, object]:
    try:
        request = decode_json(header)
    except ModelError:
        return {}
    return request if isinstance(request, dict) else {}


def _request_id(request: dict[str, object]) -> int | None:
    request_id = request.get("id")
    return request_id if type(request_id) is int else None


def _payload(request_id: int | None, answer: dict[str, object]) -> bytes:
    """The answer as JSON; a document the parent's frame cap would refuse is ``ir_too_large``."""
    payload = json.dumps({"id": request_id, **answer}, separators=(",", ":"), check_circular=False).encode()
    if len(payload) > FRAME_CAP:
        raise _Refused("ir_too_large")
    return payload


def _answer(request: dict[str, object], body: bytes) -> dict[str, object]:
    probe = request.get("probe")
    if probe is not None:
        return {probe: _PROBES[probe]()}
    profile = _profile(request)
    grammar = _grammar(profile)
    return skeleton(grammar.parser.parse(body), body, profile, grammar.table)


def _profile(request: dict[str, object]) -> LanguageProfile:
    """The request's profile as its grammar entry point parses with it (§6.3: ``.tsx``); the
    language's own entry point when the header names none. Only an entry point the profile
    lists is ever loaded: any other is a ``KeyError``, answered ``worker_error``."""
    language = request["language"]
    grammar = request.get("grammar") or PROFILES[language].grammar_attr
    return GRAMMAR_PROFILES[language, grammar]


# ── the grammars (D19: the generated query is the table/grammar contract) ────

class _Grammar:
    """One loaded grammar entry point: its parser and the table its walk reads (``_Table``),
    both built from the same ``Language``."""

    __slots__ = ("parser", "table")

    def __init__(self, profile: LanguageProfile, language: tree_sitter.Language) -> None:
        self.parser = tree_sitter.Parser(language)
        self.table = _Table(profile, language)


# (language, grammar entry point) -> its loaded grammar, or the exception class its load
# raised (a load is never retried).
_LOADED: dict[tuple[str, str], _Grammar | type[Exception]] = {}


def _grammar(profile: LanguageProfile) -> _Grammar:
    """The profile's grammar entry point, loaded on first use: only the grammars a worker
    needs load. An entry point whose load failed fails every request again, without
    reloading."""
    key = (profile.language, profile.grammar_attr)
    loaded = _LOADED.get(key)
    if loaded is None:
        loaded = _LOADED[key] = _load(profile)
    if isinstance(loaded, type):
        raise loaded(f"{profile.language}: grammar unavailable or its query does not compile")
    return loaded


def _load(profile: LanguageProfile) -> _Grammar | type[Exception]:
    """The grammar, checked against the profile's generated query, then its parser and table."""
    try:
        entry = getattr(importlib.import_module(profile.grammar_module), profile.grammar_attr)
        language = tree_sitter.Language(entry())
        tree_sitter.Query(language, build_query(profile.node_map))
    except (ImportError, AttributeError, ValueError) as exc:
        return type(exc)
    return _Grammar(profile, language)


# ── isolation (D2) and the probes ────────────────────────────────────────────


def _enforceable(name: str) -> bool:
    """D2: each limit where the platform has it; RLIMIT_AS is unreliable on darwin."""
    return hasattr(resource, name) and not (name == "RLIMIT_AS" and sys.platform == "darwin")


def _set_limit(which: int, soft: int, hard: int) -> None:
    """``(soft, hard)``, neither above an existing hard limit, so the worker can never raise
    the limit past ``hard``. Best effort: a refusal leaves the caps and the wall timeout."""
    current = resource.getrlimit(which)[1]
    top = hard if current == resource.RLIM_INFINITY else min(hard, current)
    try:
        resource.setrlimit(which, (min(soft, top), top))
    except (ValueError, OSError):
        return


def _limit_resources() -> None:
    for name, soft, hard in _RLIMITS:
        if _enforceable(name):
            _set_limit(getattr(resource, name), soft, hard)


def _forbid_new_privileges() -> None:
    """D2: ``PR_SET_NO_NEW_PRIVS`` on Linux, if ``prctl`` is reachable."""
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes

        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    except (ImportError, OSError, AttributeError):
        return


def _modules() -> dict[str, str | None]:
    return {name: getattr(sys.modules.get(name), "__file__", None) for name in _PROBED_MODULES}


def _rlimits() -> dict[str, list[int]]:
    names = [name for name, *_ in _RLIMITS if hasattr(resource, name)]
    return {name: list(resource.getrlimit(getattr(resource, name))) for name in names}


_PROBES = {"modules": _modules, "rlimits": _rlimits}


# ── the tables a walk reads, prepared once per grammar entry point ───────────
#
# Every per-node probe is a list index by the node's integer kind id, or an int-keyed dict
# probe by its field id: the walk never reads a node's type string or a field name, and
# never hashes a string per node. Kinds and fields are plain ints from here on.

_NONE = int(Field.NONE)
_PROPERTY = int(Field.PROPERTY)
_OBJECT = int(Field.OBJECT)
_INDEX = int(Field.INDEX)
_SUBSCRIPT = int(Kind.SUBSCRIPT)
_NAME = int(Kind.NAME)
_MEMBER = int(Kind.MEMBER)
_IMPORT = int(Kind.IMPORT)
_LITERAL = int(Kind.LITERAL)
_BINOP = int(Kind.BINOP)
_TEMPLATE = int(Kind.TEMPLATE)
_AUG_ASSIGN = int(Kind.AUG_ASSIGN)
_CALL = int(Kind.CALL)
_ARGS = int(Kind.ARGS)
_CALLEE = int(Field.CALLEE)
_ARGS_FIELD = int(Field.ARGS)
_LHS = int(Field.LHS)
# C3: what a synthetic CALL may borrow as its callee — a name chain (W3), nothing else.
_CHAIN_KINDS = frozenset({_NAME, _MEMBER})
_ERROR_TYPE = "ERROR"  # the one symbol outside a grammar's id table (tree-sitter's 65535)
_NO_FIELD_IDS: dict[str, int | None] = {}


class _Row:
    """A Capture as the walk reads it: its kind as an int (None: transparent), its field map
    keyed by the grammar's field ID, its positional map, the Field a synthetic CALL borrows
    its callee from (``callee``, C3; None for every other row), the parameter shape that
    narrows it (``subscript``, A36; None for every other row), and ``place``, the
    ``_Skeleton`` method that places a node under it (``_row_placement``)."""

    __slots__ = ("callee", "fields", "kind", "place", "positional", "subscript")

    def __init__(self, cap: Capture, field_ids: dict[str, int | None] = _NO_FIELD_IDS) -> None:
        self.kind = _optional_int(cap.kind)
        self.fields = {field_ids[name]: int(fld) for name, fld in cap.fields.items()}
        self.positional = {index: int(fld) for index, fld in cap.positional.items()}
        self.callee = _optional_int(cap.callee_from)
        self.subscript = cap.subscript
        self.place = _row_placement(self)


def _optional_int(member: Kind | Field | None) -> int | None:
    """A Kind or Field as the plain int the walk compares; None stays None."""
    return None if member is None else int(member)


class _Table:
    """A profile's ``NODE_MAP`` against one loaded grammar, as lists indexed by kind id: each
    id's type name, its ``(placement, plain row)`` disposition (``_disposition``), its R3
    literal class, and the ``(parent type, type)`` rows that apply to its direct children,
    by the child's kind id. The last slot of each list is ``ERROR``, whose id (65535) lies
    outside the grammar's (``slot`` maps an id to its slot)."""

    __slots__ = ("classes", "dispositions", "error", "names", "paired_under")

    def __init__(self, profile: LanguageProfile, language: tree_sitter.Language) -> None:
        plain, paired = _split(profile)
        field_ids = _field_ids(profile, language)
        count = language.node_kind_count
        self.names = [*map(language.node_kind_for_id, range(count)), _ERROR_TYPE]
        self.error = count
        self.classes = list(map(_literal_class, self.names))
        self.paired_under = _paired_under(self.names, paired, field_ids)
        self.dispositions = _dispositions(self.names, plain, paired, profile.pruned, field_ids)

    def slot(self, kid: int) -> int:
        """A node's kind id as its slot in the lists: ERROR's id lands on the last one."""
        return min(kid, self.error)


def _split(
    profile: LanguageProfile,
) -> tuple[dict[str, Capture], dict[tuple[str, str], Capture]]:
    """The plain rows and the ``(parent type, type)`` rows of a profile's ``NODE_MAP``."""
    rows: dict[str, Capture] = {}
    paired: dict[tuple[str, str], Capture] = {}
    for key, row in profile.node_map.items():
        if isinstance(key, tuple):
            paired[key] = row
        else:
            rows[key] = row
    return rows, paired


def _field_ids(profile: LanguageProfile, language: tree_sitter.Language) -> dict[str, int | None]:
    """Every field name the profile's rows map, as the grammar's field id (the generated
    query already proved each one exists)."""
    names = {name for row in profile.node_map.values() for name in row.fields}
    return {name: language.field_id_for_name(name) for name in names}


def _dispositions(
    names: list[str],
    plain: dict[str, Capture],
    paired: dict[tuple[str, str], Capture],
    pruned: frozenset[str],
    field_ids: dict[str, int | None],
) -> list[tuple[_Placement, _Row]]:
    """Each kind id's ``(placement, plain row)``."""
    paired_types = frozenset(key[1] for key in paired)
    rows = (_plain_row(plain.get(name), field_ids) for name in names)
    return [
        _disposition(name, row, pruned, paired_types)
        for name, row in zip(names, rows, strict=True)
    ]


def _plain_row(cap: Capture | None, field_ids: dict[str, int | None]) -> _Row:
    """A type's plain row; an unlisted type's is ``_UNLISTED`` (W1 rules 3-5)."""
    return _UNLISTED if cap is None else _Row(cap, field_ids)


def _paired_under(
    names: list[str], paired: dict[tuple[str, str], Capture], field_ids: dict[str, int | None]
) -> list[dict[int, _Row]]:
    """Per parent kind id, its ``(parent type, type)`` rows keyed by the child's kind id (a
    name several ids alias shares one row)."""
    ids = _kind_ids(names)
    under: list[dict[int, _Row]] = [{} for _ in names]
    for (parent, child), cap in paired.items():
        row = _Row(cap, field_ids)
        for parent_id in ids.get(parent, ()):
            under[parent_id].update(dict.fromkeys(ids.get(child, ()), row))
    return under


def _kind_ids(names: list[str]) -> dict[str, list[int]]:
    """Each type name's kind ids, ascending (a name several ids alias has more than one)."""
    ids: dict[str, list[int]] = {}
    for kid, name in enumerate(names):
        ids.setdefault(name, []).append(kid)
    return ids


# A placement is a ``_Skeleton`` method read off the class, called as
# ``place(builder, node, kind id, parent frame, Field, row) -> entered``. (The worker imports no
# ``typing``/``collections.abc``, so the type is spelled ``object``.)
type _Placement = object


def _disposition(
    name: str, row: _Row, pruned: frozenset[str], paired_types: frozenset[str]
) -> tuple[_Placement, _Row]:
    """How a node of type ``name`` is placed, in the order the dispositions apply (W1, W3):
    PRUNED, a type name, a type some ``(parent, type)`` row names, else its plain row's."""
    if name in pruned:
        return _Skeleton.pruned, row
    if name in _TYPE_NAMES:
        return _Skeleton.type_name, row
    if name in paired_types:
        return _Skeleton.paired, row
    return row.place, row


def _row_placement(row: _Row) -> _Placement:
    """A row's placement: a synthetic CALL (C3; A36 when a parameter shape narrows it), else
    by its kind (``_plain_placement``)."""
    if row.callee is None:
        return _plain_placement(row.kind)
    return _Skeleton.construct if row.subscript is None else _Skeleton.subscripted


def _plain_placement(kind: int | None) -> _Placement:
    """A row's placement: transparent, a NAME leaf, or a shipped node."""
    if kind is None:
        return _Skeleton.transparent
    return _Skeleton.ship_name if kind == _NAME else _Skeleton.ship


# ── the skeleton (§6.2, W1, W3) ──────────────────────────────────────────────


def skeleton(
    tree: tree_sitter.Tree, data: bytes, profile: LanguageProfile, table: _Table | None = None
) -> dict[str, object]:
    """The §6.2 document of ``tree`` (parsed from ``data``) under ``profile``, read through
    ``table`` (the loaded grammar's; built from ``tree.language`` when not given).

    Raises ``_Refused("ir_too_large")`` when the tree, or the document (C3 copies its
    borrowed callees), has more than ``MAX_NODES`` nodes and ``_Refused("too_deep")`` when
    the walk goes deeper than ``MAX_DEPTH``.
    """
    if tree.root_node.descendant_count > MAX_NODES:
        raise _Refused("ir_too_large")
    builder = _Skeleton(data, profile, table or _Table(profile, tree.language))
    builder.walk(tree.walk())
    return builder.document(tree)


class _Frame:
    """Where the named children of one node are placed: their shipped parent, the field
    they inherit, the row whose own field map (or positions) applies to them, and the
    ``(parent type, type)`` rows of the node's type."""

    __slots__ = (
        "fallback", "field", "fields", "last", "named", "own", "paired", "parent", "positional",
        "type", "types",
    )  # fmt: skip

    def __init__(
        self, row: _Row, field: int, parent: int, node_type: str, paired: dict[int, _Row],
        own: int = -1, types: bool = False,
    ) -> None:
        self.fields = row.fields  # grammar field id -> Field
        self.positional = row.positional
        self.field = field  # inherited by a child the row names no field for
        # The Field of a child captured under no field of ``fields`` (``_Skeleton._enter``)
        # when no position can decide it; None when one can (``_positioned``).
        self.fallback = None if row.positional else field
        self.parent = parent  # the nearest shipped ancestor of the children
        self.type = node_type  # the grammar type of the node itself
        self.paired = paired  # child kind id -> the (type of this node, child type) row
        self.own = own  # this node's index when it is shipped, else -1
        self.types = types  # W3: type names may ship below (a MEMBER in a type position)
        self.last = -1  # W3: a MEMBER's last named child, the PROPERTY when unfielded
        self.named = 0  # named children seen: the next one's position


def _segment_field(frame: _Frame, position: int) -> int:
    """W3: an unfielded child of a MEMBER is its PROPERTY when last, else its OBJECT; any
    other unfielded child inherits."""
    if frame.last < 0:
        return frame.field
    return _PROPERTY if position == frame.last else _OBJECT


def _positioned(frame: _Frame, position: int) -> int:
    """An unfielded child's Field by its position: the row's positional map, else W3."""
    own = frame.positional.get(position)
    return _segment_field(frame, position) if own is None else own


def _misplaced_type(node_type: str, field: int, frame: _Frame) -> bool:
    """W3: a type name outside ANNOTATION/CALLEE and outside a compound name there."""
    return node_type in _TYPE_NAMES and field not in _TYPE_FIELDS and not frame.types


def _member_frame(node: tree_sitter.Node, child: _Frame, field: int, frame: _Frame) -> None:
    """A MEMBER's frame carries the W3 segment rule (so no unfielded child takes the
    fallback) and, in a type position, lets the type names of its compound name ship."""
    child.last = node.named_child_count - 1
    child.fallback = None
    child.types = field in _TYPE_FIELDS or frame.types


# ── A36: a parameter read as a subscript ─────────────────────────────────────
# Read on a parameter list only once its declaration's callee is known (``subscripted``), so
# no ordinary node pays for the grammar names these compare.

type _Parts = tuple[tree_sitter.Node, tree_sitter.Node, tree_sitter.Node]


def _subscript_parts(node: tree_sitter.Node, spec: Subscript) -> _Parts | None:
    """``node``'s one parameter, its type name and its array declarator when the parameter
    has ``spec``'s shape (``argv[1]``), else None."""
    param = _lone_param(node, spec)
    if param is None:
        return None
    name, array = param.child_by_field_name(spec.object), param.child_by_field_name(spec.declarator)
    return (param, name, array) if _is_type_name(name) and _indexed(array, spec) else None


def _lone_param(node: tree_sitter.Node, spec: Subscript) -> tree_sitter.Node | None:
    """``node``'s one named child when it is a ``spec.param`` of two named children (a type
    and a declarator: no qualifier, no attribute), else None."""
    if node.named_child_count != 1:
        return None
    param = node.named_child(0)
    return param if param.type == spec.param and param.named_child_count == 2 else None


def _is_type_name(node: tree_sitter.Node | None) -> bool:
    return node is not None and node.type in _TYPE_NAMES


def _indexed(array: tree_sitter.Node | None, spec: Subscript) -> bool:
    """A ``spec.array`` holding its index and no declarator of its own: ``[1]``, never
    ``[]`` or ``[1][2]``."""
    if array is None or array.type != spec.array:
        return False
    held = array.child_by_field_name
    return held(spec.index) is not None and held(spec.declarator) is None


# ── literals and tokens (§6.2: M2, R3, W15 b) ────────────────────────────────

def _literal_class(node_type: str) -> str:
    """R3: the literal class of a grammar type (derived once per kind id, by ``_Table``)."""
    words = frozenset(node_type.split("_"))
    return next((cls for cls, keys in LITERAL_CLASS_WORDS if words & keys), "other")


def _lit_value(cls: str, token: bytes) -> list[str]:
    """D3, W15 b: a boolean lowercased, a number matching the lit pattern; else nothing."""
    value = token.decode("ascii", "replace").lower()
    return [value] if cls in _VALUED and LIT_VALUE.fullmatch(value) else []


def _ascii(raw: bytes) -> str | None:
    return raw.decode("ascii") if raw.isascii() else None


def _identifier_text(value: str | None) -> str | None:
    """``value`` when it may ship as text: identifier-shaped (D16) within the text cap."""
    if value is not None and len(value) <= MAX_TEXT_BYTES and admissible(IDENTIFIER, value):
        return value
    return None


def _augmented(node: tree_sitter.Node) -> bool:
    """An assignment whose operator is not plain ``=``/``:=`` (Go/Java/C ``+=``)."""
    operator = node.child_by_field_name("operator")
    return operator is not None and operator.type not in _PLAIN_ASSIGNMENT


def _first_token(node: tree_sitter.Node) -> str | None:
    """The TYPE of the node's first anonymous child (M2: never its source text)."""
    return next((child.type for child in node.children if not child.is_named), None)


# ── the document head ────────────────────────────────────────────────────────


def _error_count(root: tree_sitter.Node) -> int:
    """ERROR and MISSING nodes (D10, T7), walked only when ``root.has_error`` says one exists."""
    return _count_errors(root) if root.has_error else 0


def _count_errors(root: tree_sitter.Node) -> int:
    """ERROR and MISSING nodes, descending only into subtrees that contain one."""
    count, pending = 0, [root]
    while pending:
        node = pending.pop()
        count += _is_error(node)
        pending.extend(child for child in node.children if child.has_error)
    return count


def _is_error(node: tree_sitter.Node) -> bool:
    """An ERROR or a MISSING node."""
    return node.is_error or node.is_missing


def _stamp(language: tree_sitter.Language, profile: LanguageProfile) -> str:
    """The grammar a document was built with: its entry point and its version."""
    version = language.semantic_version
    release = ".".join(map(str, version)) if version else f"abi{language.abi_version}"
    return stamp_prefix(profile.grammar_module, profile.grammar_attr) + release


def _survivors(parents: list[int], collapsed: set[int]) -> tuple[list[int], list[int]]:
    """The kept nodes, and each node's new index — a collapsed node's is its parent's."""
    keep: list[int] = []
    remap: list[int] = []
    for i, parent in enumerate(parents):
        if i in collapsed:
            remap.append(remap[parent])
        else:
            remap.append(len(keep))
            keep.append(i)
    return keep, remap


def _kept_columns(columns: list[list[int]], keep: list[int], remap: list[int]) -> list[list[int]]:
    """The columns of the kept nodes; each parent renumbered (the root is never collapsed)."""
    kinds, parents, *rest = columns
    moved = [-1, *(remap[parents[i]] for i in keep[1:])]
    return [_kept(kinds, keep), moved, *(_kept(column, keep) for column in rest)]


def _kept(column: list[int], keep: list[int]) -> list[int]:
    """``column``'s values at the ``keep`` indices, in order."""
    return [column[i] for i in keep]


def _remapped[V](entries: dict[int, V], remap: list[int]) -> dict[int, V]:
    return {remap[i]: value for i, value in entries.items()}


def _each_sibling(cursor: tree_sitter.TreeCursor) -> object:
    """Yield at the cursor's node, then at each following sibling (a generator: resuming
    it is cheaper than a call per node)."""
    yield None
    while cursor.goto_next_sibling():
        yield None


_UNSEEN = object()  # an identifier's source not admitted or refused yet in this file


class _Skeleton:
    """One file's document, built by a single cursor walk (O(n) in the tree's nodes).

    Each shipped node is ONE ``(kind, parent, field, sb, eb, sl)`` tuple while the walk
    runs; ``document`` transposes them into the §6.2 columns. The placements (``ship``,
    ``transparent``, ...) are read from the grammar's ``_Table`` as plain functions, so a
    file binds nothing per kind id.
    """

    def __init__(self, data: bytes, profile: LanguageProfile, table: _Table) -> None:
        self._data = data
        self._profile = profile
        self._table = table
        self._names = table.names
        self._dispositions = table.dispositions
        self._paired_under = table.paired_under
        self._nodes: list[tuple[int, int, int, int, int, int]] = []
        self._text: dict[int, str] = {}
        self._lit: dict[int, list[object]] = {}
        self._unmapped: dict[str, int] = {}
        self._words: dict[int, str] = {}  # M4 candidates, decided by the final parent
        self._open: dict[int, int] = {}  # open placeholder -> its shipped children so far
        self._collapsed: set[int] = set()
        self._idents: dict[bytes, str | None] = {}  # identifier source -> its admitted text
        self._callees: dict[tuple[int, int], int] = {}  # C3: (owner, Field) -> its name chain
        self._frames = [_Frame(_TRANSPARENT, _NONE, -1, "", {})]
        self._by_field = {
            Field.INDEX: self._set_text,  # M1: an identifier-shaped subscript key
            Field.SOURCE: self._module_segment,
            Field.NONE: self._shell_word,
        }

    # ── the walk ──

    def walk(self, cursor: tree_sitter.TreeCursor) -> None:
        """Pre-order over every node; a node is entered when it pushed a frame."""
        node = cursor.node
        if node.is_named and self._enter(cursor, node):
            self._children(cursor)

    def _children(self, cursor: tree_sitter.TreeCursor) -> None:
        """Place every child of the cursor's entered node, descending into each child that
        is entered in turn, then close the node. An anonymous token costs no call; the
        recursion is as deep as the frames (``too_deep`` stops it past ``MAX_DEPTH``)."""
        enter = self._enter
        cursor.goto_first_child()
        for _ in _each_sibling(cursor):
            node = cursor.node  # fetched once: the cursor builds a new Node object per read
            if node.is_named and enter(cursor, node):
                self._children(cursor)
        cursor.goto_parent()
        self._leave()

    def _enter(self, cursor: tree_sitter.TreeCursor, node: tree_sitter.Node) -> bool:
        """Place the cursor's NAMED ``node`` under the innermost frame (``_field_of`` inlined)."""
        if len(self._frames) > _FRAMES_CAP:  # the cursor depth, counted without a C call
            raise _Refused("too_deep")
        frame = self._frames[-1]
        position = frame.named
        frame.named = position + 1
        field = frame.fields.get(cursor.field_id, frame.fallback)
        if field is None:
            field = _positioned(frame, position)
        kid = node.kind_id
        try:
            place, row = self._dispositions[kid]
        except IndexError:  # ERROR: the one kind id outside the grammar's table
            kid = self._table.error
            place, row = self._dispositions[kid]
        return place(self, node, kid, frame, field, row)

    def _leave(self) -> None:
        """Close a frame; a placeholder holding fewer than two shipped children collapses."""
        frame = self._frames.pop()
        shipped = self._open.pop(frame.own, None)
        if shipped is not None and shipped < 2:
            self._collapsed.add(frame.own)
            self._tally(frame.type)

    # ── placements (W1, W3) ──
    # Each takes (node, kind id, parent frame, Field, row) and answers whether the node was
    # entered (it pushed a frame); the table calls them as plain functions.

    def pruned(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """PRUNED, or a misplaced type name: dropped with its subtree, tallied."""
        self._tally(self._names[kid])
        return False

    def type_name(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """W3: a type name outside the positions the analysis reads is dropped."""
        if _misplaced_type(self._names[kid], field, frame):
            return self.pruned(node, kid, frame, field, row)
        return self.paired(node, kid, frame, field, row)

    def paired(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """W1: a ``(parent type, type)`` row wins for a direct child; else the plain row."""
        own = frame.paired.get(kid)
        if own is not None:
            row = own
        return row.place(self, node, kid, frame, field, row)

    def unlisted(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """W1 rules 3-5: an ARGS container, a positional placeholder, or transparent."""
        if field in _CONTAINER_FIELDS:
            return self.ship(node, kid, frame, field, _CONTAINER)
        if self._is_candidate(node, frame, field):
            return self._open_placeholder(node, kid, frame)
        return self.transparent(node, kid, frame, field, _TRANSPARENT)

    def transparent(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """Not shipped: the children hang from ``frame.parent`` and inherit ``field``."""
        node_type = self._names[kid]
        self._tally(node_type)
        if node.child_count == 0:
            return False
        paired = self._paired_under[kid]
        self._frames.append(_Frame(row, field, frame.parent, node_type, paired, -1, frame.types))
        return True

    def ship_name(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """A NAME: a leaf whose text is its source, never entered."""
        self._identifier(node, self._append(node, _NAME, frame.parent, field), field)
        return False

    def ship(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """A shipped node of any kind but NAME (``ship_name``); entered when it has children."""
        kind = self._refined(node, row.kind) if row.kind in _REFINABLE else row.kind
        index = self._append(node, kind, frame.parent, field)
        annotate = _ANNOTATORS[kind]
        if annotate is not None:
            annotate(self, node, index, field)
        if node.child_count == 0:
            return False
        return self._open_children(node, kid, kind, row, field, frame, index)

    def construct(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """C3: a synthetic CALL under ``field`` (the declarator's RHS) whose CALLEE copies the
        name chain the nearest shipped ancestor holds under ``row.callee`` (the declaration's
        type) and whose ARGS container is ``node``, entered for its arguments. Transparent
        when that ancestor holds no name chain there (a primitive type ships none)."""
        callee = self._borrowed_callee(frame.parent, row.callee)
        if callee < 0:
            return self.transparent(node, kid, frame, field, _TRANSPARENT)
        args = self._synthetic_call(node, frame.parent, field, callee)
        # An argument list always has children (its parentheses): it is always entered.
        return self._open_children(node, kid, _ARGS, _CONTAINER, _ARGS_FIELD, frame, args)

    def subscripted(
        self, node: tree_sitter.Node, kid: int, frame: _Frame, field: int, row: _Row
    ) -> bool:
        """A36: C3's synthetic CALL under ``field`` when the nearest shipped ancestor holds a
        name chain under ``row.callee`` and ``node`` holds ONE parameter of ``row.subscript``'s
        shape; its one argument is that parameter as a SUBSCRIPT — the type name its OBJECT,
        the array declarator's index its INDEX. Any other ``node`` ships by its row."""
        callee = self._borrowed_callee(frame.parent, row.callee)
        parts = _subscript_parts(node, row.subscript) if callee >= 0 else None
        if parts is None:
            return self.ship(node, kid, frame, field, row)
        param, name, array = parts
        args = self._synthetic_call(node, frame.parent, field, callee)
        subscript = self._append(param, _SUBSCRIPT, args, _NONE)
        self._place_under(subscript, name, _OBJECT, True)  # W3: the type name ships here
        self._place_under(subscript, array, _INDEX, False)  # transparent: its index ships
        return False

    # ── placement helpers ──

    def _synthetic_call(self, node: tree_sitter.Node, owner: int, field: int, callee: int) -> int:
        """C3: a CALL spanning ``node`` under ``owner`` with ``field``, its CALLEE a copy of the
        name chain ``callee`` and its ARGS container ``node`` too: the container's index."""
        call = self._append(node, _CALL, owner, field)
        self._copy(callee, call, _CALLEE)
        return self._append(node, _ARGS, call, _ARGS_FIELD)

    def _place_under(self, parent: int, node: tree_sitter.Node, field: int, types: bool) -> None:
        """Walk ``node`` as a child of shipped node ``parent`` under ``field`` (A36: a part of
        a parameter re-read as a SUBSCRIPT); ``types`` lets a type name ship there (W3)."""
        self._frames.append(_Frame(_TRANSPARENT, field, parent, "", {}, -1, types))
        self.walk(node.walk())
        self._frames.pop()

    def _is_candidate(self, node: tree_sitter.Node, frame: _Frame, field: int) -> bool:
        """W1: an unlisted node in a positional slot of an ARGS container or ARRAY."""
        if field != _NONE or node.child_count == 0 or frame.parent < 0:
            return False
        return self._nodes[frame.parent][0] in LIST_KINDS

    def _open_placeholder(self, node: tree_sitter.Node, kid: int, frame: _Frame) -> bool:
        index = self._append(node, _BINOP, frame.parent, _NONE)
        self._open[index] = 0
        paired = self._paired_under[kid]
        child = _Frame(_TRANSPARENT, _NONE, index, self._names[kid], paired, index, frame.types)
        self._frames.append(child)
        return True

    def _open_children(
        self, node: tree_sitter.Node, kid: int, kind: int, row: _Row, field: int, frame: _Frame,
        index: int,
    ) -> bool:
        """The frame of a shipped node's children."""
        child = _Frame(row, _NONE, index, self._names[kid], self._paired_under[kid], index)
        if kind == _MEMBER:
            _member_frame(node, child, field, frame)
        self._frames.append(child)
        return True

    def _refined(self, node: tree_sitter.Node, kind: int) -> int:
        """M3: an interpolated string is a TEMPLATE; a compound assignment an AUG_ASSIGN."""
        if kind == _LITERAL:
            return _TEMPLATE if self._interpolated(node) else kind
        return _AUG_ASSIGN if _augmented(node) else kind

    def _interpolated(self, node: tree_sitter.Node) -> bool:
        """M3: a string with an interpolation part — directly, or in a string it concatenates
        (Python ``f"{a}" "b"``), so the parts are carried, never read as a constant."""
        if node.named_child_count == 0:
            return False
        return any(self._carries_part(child) for child in node.named_children)

    def _carries_part(self, child: tree_sitter.Node) -> bool:
        kind = self._dispositions[self._table.slot(child.kind_id)][1].kind  # its plain row's
        if kind == _LITERAL:
            return self._interpolated(child)
        return kind == _TEMPLATE

    # ── C3: the borrowed callee ──

    def _borrowed_callee(self, owner: int, field: int) -> int:
        """``_chain_under(owner, field)``, searched once per owner: the declarators of one
        declaration share its type."""
        key = (owner, field)
        callee = self._callees.get(key)
        if callee is None:
            callee = self._callees[key] = self._chain_under(owner, field)
        return callee

    def _chain_under(self, owner: int, field: int) -> int:
        """The name chain (a NAME or MEMBER) shipped node ``owner`` holds under ``field``,
        else -1. A declaration's type precedes its declarators, so the search stops at the
        first declarator (a direct child under LHS): it reads only what precedes the type."""
        child = self._first_owned(owner, (field, _LHS))
        if child < 0:
            return -1
        kind, _, own, *_ = self._nodes[child]
        return child if own == field and kind in _CHAIN_KINDS else -1

    def _first_owned(self, owner: int, fields: tuple[int, int]) -> int:
        """The first direct child of ``owner`` shipped under one of ``fields``, else -1."""
        nodes = self._nodes
        hits = (i for i in range(owner + 1, len(nodes)) if nodes[i][1] == owner and nodes[i][2] in fields)
        return next(hits, -1)

    def _subtree_end(self, root: int) -> int:
        """One past the last node of ``root``'s shipped subtree: nodes ship in pre-order, so
        the subtree is contiguous and ends at the first later node whose parent precedes it."""
        nodes = self._nodes
        return next((i for i in range(root + 1, len(nodes)) if nodes[i][1] < root), len(nodes))

    def _copy(self, root: int, parent: int, field: int) -> None:
        """Append a copy of ``root``'s shipped subtree: its root under ``parent`` with
        ``field``, every other node under the copy of its own parent. O(subtree)."""
        end = self._subtree_end(root)  # before the copy grows the list
        if len(self._nodes) + end - root > MAX_NODES:
            raise _Refused("ir_too_large")
        shift = len(self._nodes) - root
        self._copy_node(root, shift, parent, field)
        for i in range(root + 1, end):
            _, up, own, *_ = self._nodes[i]
            self._copy_node(i, shift, up + shift, own)

    def _copy_node(self, i: int, shift: int, parent: int, field: int) -> None:
        """Node ``i`` again at ``i + shift``: its kind, span and row, its text, literal and
        M4 word, and its collapse (a placeholder that held fewer than two children)."""
        kind, _, _, start, end, row = self._nodes[i]
        self._nodes.append((kind, parent, field, start, end, row))
        for table in (self._text, self._lit, self._words):
            if i in table:
                table[i + shift] = table[i]
        if i in self._collapsed:
            self._collapsed.add(i + shift)

    def _append(self, node: tree_sitter.Node, kind: int, parent: int, field: int) -> int:
        nodes = self._nodes
        index = len(nodes)
        # A row is `start_point[0]`, never `.row`: see the module docstring.
        nodes.append((kind, parent, field, node.start_byte, node.end_byte, node.start_point[0]))
        if parent in self._open:
            self._open[parent] += 1
        return index

    def _span(self, index: int) -> bytes:
        """The source bytes of shipped node ``index``."""
        _, _, _, start, end, _ = self._nodes[index]
        return self._data[start:end]

    def _tally(self, node_type: str) -> None:
        self._unmapped[node_type] = self._unmapped.get(node_type, 0) + 1

    # ── text and lit (§6.2: M1-M4, W1, W3, W15 b, R3) ──

    def _set_text(self, index: int, value: str | None) -> None:
        """An identifier-shaped value (D16) within the text cap, else nothing."""
        admitted = _identifier_text(value)
        if admitted is not None:
            self._text[index] = admitted

    def _set_ident(self, index: int, raw: bytes) -> None:
        """``_set_text`` of an identifier's source, each distinct source decided once."""
        value = self._idents.get(raw, _UNSEEN)
        if value is _UNSEEN:
            value = self._idents[raw] = _identifier_text(_ascii(raw))
        if value is not None:
            self._text[index] = value

    def _identifier(self, node: tree_sitter.Node, index: int, field: int) -> None:
        """A leaf's source; a PHP ``variable_name`` without its ``$``."""
        if node.named_child_count == 0:
            self._set_ident(index, self._span(index))
            return
        start = _after_dollar(node)
        if start >= 0:
            self._set_ident(index, self._data[start : node.end_byte])

    def _operator(self, node: tree_sitter.Node, index: int, field: int) -> None:
        self._token(node, index, OPERATOR_TOKENS)

    def _keyword(self, node: tree_sitter.Node, index: int, field: int) -> None:
        self._token(node, index, DECLARATION_KEYWORDS)

    def _token(self, node: tree_sitter.Node, index: int, allowed: frozenset[str]) -> None:
        token = _first_token(node)
        if token in allowed:
            self._text[index] = token

    def _literal(self, node: tree_sitter.Node, index: int, field: int) -> None:
        cls = self._table.classes[self._table.slot(node.kind_id)]
        token = self._span(index)
        content = self._content(node) if cls in _TEXTUAL else token
        self._lit[index] = [cls, len(content), *_lit_value(cls, token)]
        value = _ascii(content) if cls == "string" else None
        if value is not None:
            self._by_field.get(field, _no_string_text)(index, value)

    def _content(self, node: tree_sitter.Node) -> bytes:
        """A string's content: between its opening and closing delimiters."""
        count = node.child_count
        if count >= 2:
            start, end = node.child(0).end_byte, node.child(count - 1).start_byte
        else:
            start, end = (node.child(0) if count else node).byte_range
        return self._data[start:end]

    def _module_segment(self, index: int, value: str) -> None:
        """W3: an IMPORT of a string module carries the path's last segment."""
        parent = self._nodes[index][1]
        if self._nodes[parent][0] == _IMPORT:
            self._set_text(parent, MODULE_PATH_SEPARATORS.split(value)[-1])

    def _shell_word(self, index: int, value: str) -> None:
        """M4 candidate: kept only if the final parent is an ARGS container or ARRAY."""
        word = shell_word(value)
        if word is not None:
            self._words[index] = word

    # ── the document ──

    def _columns(self) -> list[list[int]]:
        """The §6.2 columns, in ``COLUMNS`` order, with collapsed placeholders dropped and
        their child re-parented to their parent."""
        columns = _transposed(self._nodes)
        if not self._collapsed:
            return columns
        keep, remap = _survivors(columns[1], self._collapsed)
        self._text = _remapped(self._text, remap)
        self._lit = _remapped(self._lit, remap)
        self._words = _remapped(self._words, remap)
        return _kept_columns(columns, keep, remap)

    def _resolve_words(self, kinds: list[int], parents: list[int]) -> None:
        for index, word in self._words.items():
            if kinds[parents[index]] in LIST_KINDS:
                self._text[index] = word

    def document(self, tree: tree_sitter.Tree) -> dict[str, object]:
        columns = self._columns()
        if len(columns[0]) > MAX_NODES:  # C3's CALLs and copies are nodes the tree does not hold
            raise _Refused("ir_too_large")
        self._resolve_words(columns[0], columns[1])
        unmapped = {t: n for t, n in self._unmapped.items() if UNMAPPED_TYPE.fullmatch(t)}
        return {
            "schema": MODEL_SCHEMA,
            "language": self._profile.language,
            "grammar": _stamp(tree.language, self._profile),
            "size": len(self._data),
            "error_nodes": _error_count(tree.root_node),
            "node_count": len(columns[0]),
            "unmapped": unmapped,
            **dict(zip(COLUMNS, columns, strict=True)),
            "text": self._text,
            "lit": self._lit,
        }


def _no_string_text(index: int, value: str) -> None:
    """A string in a position whose value never ships."""


def _after_dollar(node: tree_sitter.Node) -> int:
    """Where the anonymous ``$`` a node starts with (PHP's ``variable_name``) ends, else -1."""
    first = node.child(0)
    if first is None or first.type != "$" or first.is_named:
        return -1
    return first.end_byte


def _transposed(nodes: list[tuple[int, int, int, int, int, int]]) -> list[list[int]]:
    """The shipped nodes' tuples as the §6.2 columns, in ``COLUMNS`` order (each empty for
    none)."""
    return [list(column) for column in zip(*nodes, strict=True)] or [[] for _ in COLUMNS]


# The rows every grammar shares, and the annotation each shipped kind gets (None: none).
_TRANSPARENT = _Row(Capture(None))
_CONTAINER = _Row(Capture(Kind.ARGS))  # W1 rule 3
_UNLISTED = _Row(Capture(None))  # an unlisted type: placed by W1 rules 3-5
_UNLISTED.place = _Skeleton.unlisted
# kind -> the ``_Skeleton`` method ``ship`` annotates a node of it with (builder, node, index,
# Field), or None. A NAME is never shipped by ``ship``: ``ship_name`` annotates it itself.
_ANNOTATED = {
    Kind.PARAM: _Skeleton._identifier,
    Kind.LITERAL: _Skeleton._literal,
    Kind.BINOP: _Skeleton._operator,
    Kind.UNARY: _Skeleton._operator,
    Kind.OTHER: _Skeleton._keyword,
}
_ANNOTATORS: list[object] = [_ANNOTATED.get(kind) for kind in sorted(Kind)]
