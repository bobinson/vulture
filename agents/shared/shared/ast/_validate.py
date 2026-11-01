"""The parent's boundary check of a worker document (feature 0102, D3, D16, LLD §6.2).

The parse worker runs native code over attacker-controlled bytes (LLD §11 T4, T10), so the
parent treats every frame it sends back as hostile: the payload is decoded by ``json.loads``
(``_frames.decode_json``, the layer's one decoder) and the result must have exactly the §6.2
shape, or ``validate_model`` raises ``ModelError`` (the pool's ``bad_model``).
``validate_reply`` then binds a document to the request it answers: the requested language
and grammar entry point, the byte count actually shipped and the lines those bytes hold, so a
compromised worker cannot hand back spans or rows past the text the parent holds.

This module is also the one home of the wire VOCABULARY — the D16 identifier pattern, the
``lit`` value pattern, the M2 operator tokens, the M4 flag shape and shell-interpreter
basenames (L3), the W1 declaration keywords and the literal classes (R3). The worker builds
its document from the same constants, so what it may ship and what the parent admits are one
fact each (D19). Every column check runs in C (``min``/``max``/``map``): the O(n) pass stays
cheap at ``MAX_NODES``.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable, Iterable, Mapping
from functools import partial
from itertools import compress, repeat
from types import MappingProxyType
from typing import Any, TypeGuard

from shared.ast import MODEL_SCHEMA
from shared.ast._frames import ModelError, decode_json
from shared.ast.kinds import Field, Kind
from shared.ast.limits import FRAME_CAP, MAX_NODES, MAX_TEXT_BYTES
from shared.ast.profile import PROFILES, LanguageProfile

__all__ = [
    "COLUMNS",
    "DECLARATION_KEYWORDS",
    "IDENTIFIER",
    "IDENTIFIER_KINDS",
    "LIST_KINDS",
    "LITERAL_CLASSES",
    "LITERAL_CLASS_WORDS",
    "LIT_VALUE",
    "MODULE_PATH_SEPARATORS",
    "OPERATOR_TOKENS",
    "OTHER_LITERAL_CLASS",
    "SHELL_INTERPRETERS",
    "UNMAPPED_TYPE",
    "ModelError",
    "admissible",
    "counts_ok",
    "exact_int",
    "frame_head",
    "prefix_of",
    "request_binding",
    "require",
    "require_all",
    "shell_word",
    "spelled",
    "stamp_prefix",
    "unmapped_ok",
    "validate_model",
    "validate_reply",
]

# ── the wire vocabulary (§6.2) ───────────────────────────────────────────────

# D16: an identifier, or up to three dotted identifier segments. ASCII only.
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]{0,63}(?:\.[A-Za-z_$][\w$]{0,63}){0,2}", re.ASCII)
# D3: the only literal values that leave the worker: booleans and short plain numbers.
LIT_VALUE = re.compile(r"true|false|-?\d[\d._]{0,19}", re.ASCII)
# M4: a command flag (`-c`, `/c`, `-Command`).
_FLAG = re.compile(r"[-/][A-Za-z][\w-]{0,15}", re.ASCII)
# §6.2: an `unmapped` key is a grammar type name.
UNMAPPED_TYPE = re.compile(r"[a-z_]{1,64}", re.ASCII)
# W3: a string module path is split on every character outside [A-Za-z0-9_$].
MODULE_PATH_SEPARATORS = re.compile(r"[^A-Za-z0-9_$]+")
_GRAMMAR = re.compile(r"[\w.@:+-]{1,128}", re.ASCII)
_INDEX = re.compile(r"0|[1-9][0-9]{0,8}", re.ASCII)

# L3: the program basenames R-M recognises; M4 ships one as that basename, never the path.
SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "ash", "cmd", "cmd.exe", "powershell", "pwsh",
})
# M2 (W11 adds `&` and `*`): the operator tokens a BINOP/UNARY may carry, by token TYPE.
OPERATOR_TOKENS = frozenset({
    "in", "not in", "==", "===", "!=", "!==", "<", "<=", ">", ">=", "!", "not", "&&", "||",
    "??", "and", "or", "instanceof", "typeof", "is", "is not", "&", "*",
})
# W1: the keyword an OTHER declaration carries, the input of the scope rules.
DECLARATION_KEYWORDS = frozenset({"let", "const", "var"})
# R3: a literal's class, read from the words of its grammar type (first match wins);
# a type that meets none is ``OTHER_LITERAL_CLASS``.
LITERAL_CLASS_WORDS: tuple[tuple[str, frozenset[str]], ...] = (
    ("null", frozenset({"null", "none", "nil", "undefined"})),
    ("bool", frozenset({"true", "false", "boolean"})),
    ("string", frozenset({"string", "nowdoc", "heredoc"})),
    ("char", frozenset({"char", "character", "rune"})),
    ("number", frozenset({"number", "integer", "int", "float", "floating", "imaginary"})),
)
# R3's catch-all class: a regex literal (what §8.5 (iii) and A44 (1) (c) read a regex by) or
# any other type that meets no class word (Go `iota`). A `regex` class of its own changes the
# skeleton, so it waits for the next MODEL_SCHEMA bump.
OTHER_LITERAL_CLASS = "other"
# R3's class vocabulary: what a ``lit`` entry may name (and ``model`` interns).
LITERAL_CLASSES = frozenset({cls for cls, _ in LITERAL_CLASS_WORDS} | {OTHER_LITERAL_CLASS})
# M4: the containers whose string LITERAL children may carry a flag or interpreter text.
LIST_KINDS = frozenset({Kind.ARGS, Kind.ARRAY})


def admissible(pattern: re.Pattern[str], value: object) -> bool:
    """``value`` is a string ``pattern`` matches whole (a trailing newline never matches)."""
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def spelled(names: Iterable[str]) -> Mapping[str, str]:
    """A closed vocabulary as name -> its one string object: a lookup both admits a wire value
    and hands back the shared spelling, so what is built from a document keeps no copy of a
    vocabulary word (``model``'s literal classes, ``answer``'s vocabularies)."""
    return MappingProxyType({name: name for name in names})


def shell_word(value: str) -> str | None:
    """M4/L3: what a string literal in ARGS/ARRAY position may ship — the lowercased basename
    (after the last ``/`` or ``\\``) of a shell interpreter, else the flag itself. The
    interpreter is tried first, so ``"/zsh"`` ships the program ``zsh`` R-M reads, not a flag."""
    base = value.replace("\\", "/").rpartition("/")[2].lower()
    if base in SHELL_INTERPRETERS:
        return base
    return value if _FLAG.fullmatch(value) else None


# ── the document ─────────────────────────────────────────────────────────────

# §6.2: the parallel int arrays, in document order (sl = 0-based start row, \n-counted).
COLUMNS = ("kind", "parent", "field", "sb", "eb", "sl")
_REQUIRED = frozenset({
    "schema", "language", "grammar", "size", "error_nodes", "node_count", "unmapped", *COLUMNS,
})
_KEYS = _REQUIRED | {"id", "text", "lit"}
_LAST_KIND = max(Kind)
_LAST_FIELD = max(Field)

type _Doc = dict[str, Any]


def validate_model(doc: bytes | str | Mapping[str, Any]) -> _Doc:
    """The worker document ``doc`` — a frame payload or an already decoded mapping — checked
    against §6.2; ``text`` and ``lit`` come back keyed by ``int`` node index.

    Raises ``ModelError`` on anything else: a payload that is not JSON (a pickle stream,
    100k-deep nesting, memory exhaustion while decoding), a missing or extra key, unequal or
    non-int columns, more than ``MAX_NODES`` nodes, a kind or field outside its enum, a
    parent that does not precede its child, a span outside the file, or a ``text``/``lit``/
    ``unmapped`` entry outside its rule.
    """
    raw = _decoded(doc)
    n = _columns(raw)
    require_all(_head_checks(raw, n), "document head")
    require_all(_tree_checks(raw, n), "tree columns")
    texts = _keyed(raw, "text", n, _texts_ok, _text_ok)
    return {**raw, "text": texts, "lit": _keyed(raw, "lit", n, _lits_ok, _lit_ok)}


def stamp_prefix(module: str, entry: str) -> str:
    """The head of the ``grammar`` stamp of a document parsed with ``module.entry`` (the
    worker appends the grammar's version)."""
    return f"{module}.{entry}@"


def prefix_of(stamp: str) -> str:
    """``stamp_prefix`` read back off a ``grammar`` stamp: what precedes its version."""
    head, at, _version = stamp.partition("@")
    return head + at


def validate_reply(doc: Mapping[str, Any], profile: LanguageProfile, grammar: str, data: bytes) -> _Doc:
    """``validate_model(doc)``, bound to the request it answers (§11 T10): ``profile``'s
    language parsed with its entry point ``grammar``, over exactly the shipped ``data`` — its
    ``size`` is ``len(data)`` and no row lies past the last ``\\n`` of ``data``."""
    valid = validate_model(doc)
    rows = max(valid["sl"]) <= data.count(b"\n")
    require_all({**request_binding(valid, profile, grammar, data), "rows": rows}, "reply binding")
    return valid


def request_binding(
    doc: Mapping[str, Any], profile: LanguageProfile, grammar: str, data: bytes
) -> dict[str, bool]:
    """The checks that bind a worker's reply — a skeleton (D3) or an answer (D3', §4.1) — to
    the request it answers (§11 T10): ``profile``'s language, a stamp of its entry point
    ``grammar``, and exactly the shipped ``data``'s size."""
    stamp, prefix = doc["grammar"], stamp_prefix(profile.grammar_module, grammar)
    return {
        "language": doc["language"] == profile.language,
        "grammar": admissible(_GRAMMAR, stamp) and stamp.startswith(prefix),
        "size": exact_int(doc["size"], len(data), len(data)),
    }


def require(ok: bool, reason: str) -> None:
    """D3's one refusal: ``ModelError(reason)`` unless ``ok``."""
    if not ok:
        raise ModelError(reason)


def require_all(checks: dict[str, bool], what: str) -> None:
    """``require`` over named ``checks``: the refusal names every check of ``what`` that failed."""
    failed = [name for name, ok in checks.items() if not ok]
    require(not failed, f"{what}: {failed}")


def _decoded(doc: bytes | str | Mapping[str, Any]) -> _Doc:
    raw = dict(doc) if isinstance(doc, Mapping) else decode_json(doc)
    require(isinstance(raw, dict) and _REQUIRED <= raw.keys() <= _KEYS, "not a model document")
    return raw


def exact_int(value: object, low: int, high: int) -> bool:
    """An exact ``int`` (never a ``bool``) within ``[low, high]``."""
    return type(value) is int and low <= value <= high


def _is_int_list(value: object) -> bool:
    return type(value) is list and set(map(type, value)) <= {int}


def _columns(raw: _Doc) -> int:
    """The node count: six int arrays of one length ``n``, ``1 <= n <= MAX_NODES``."""
    columns = [raw[name] for name in COLUMNS]
    require(all(map(_is_int_list, columns)), "a column is not a list of ints")
    n = len(columns[0])
    require(1 <= n <= MAX_NODES and {len(c) for c in columns} == {n}, "bad column lengths")
    return n


def _head_checks(raw: _Doc, n: int) -> dict[str, bool]:
    return {
        **frame_head(raw, MODEL_SCHEMA),
        "language": isinstance(raw["language"], str) and raw["language"] in PROFILES,
        "grammar": admissible(_GRAMMAR, raw["grammar"]),
        # The shipped bytes arrived in one frame; the UTF-8 encoding of a capped file's text may
        # exceed MAX_FILE_SIZE (each undecodable byte became a 3-byte U+FFFD).
        "size": exact_int(raw["size"], 0, FRAME_CAP),
        "node_count": exact_int(raw["node_count"], n, n),
    }


def frame_head(doc: Mapping[str, Any], schema: int) -> dict[str, bool]:
    """The head checks every worker document shares, a skeleton (D3) or an answer (D3',
    §4.1): its frame ``id``, its ``schema``, its ERROR-node count and its ``unmapped`` counts."""
    return {
        "id": type(doc.get("id", 0)) is int,
        "schema": exact_int(doc["schema"], schema, schema),
        "error_nodes": exact_int(doc["error_nodes"], 0, MAX_NODES),
        "unmapped": unmapped_ok(doc["unmapped"]),
    }


def _within(column: list[int], low: int, high: int) -> bool:
    return min(column, default=low) >= low and max(column, default=high) <= high


def _parents_precede(parent: list[int]) -> bool:
    """``parent[0] == -1`` and ``0 <= parent[i] < i`` for every other node."""
    rest = parent[1:]
    ordered = all(map(operator.lt, rest, range(1, len(parent))))
    return parent[0] == -1 and _within(rest, 0, len(rest)) and ordered


def _spans_inside(sb: list[int], eb: list[int], size: int) -> bool:
    """``0 <= sb[i] <= eb[i] <= size``."""
    return _within(sb, 0, size) and _within(eb, 0, size) and all(map(operator.le, sb, eb))


def _tree_checks(raw: _Doc, n: int) -> dict[str, bool]:
    return {
        "kind": _within(raw["kind"], 0, _LAST_KIND),
        "field": _within(raw["field"], 0, _LAST_FIELD),
        "parent": _parents_precede(raw["parent"]),
        "spans": _spans_inside(raw["sb"], raw["eb"], raw["size"]),
        "rows": _within(raw["sl"], 0, raw["size"]),
    }


def counts_ok(counts: object, name_ok: Callable[[Any], bool], low: int, high: int) -> bool:
    """A name -> count map: each name ``name_ok``, each count an exact int in ``[low, high]``."""
    return isinstance(counts, dict) and all(name_ok(k) and exact_int(v, low, high) for k, v in counts.items())


def unmapped_ok(unmapped: object) -> bool:
    """Grammar type name -> a positive count."""
    return counts_ok(unmapped, partial(admissible, UNMAPPED_TYPE), 1, MAX_NODES)


def _index(key: object, n: int) -> int:
    """A ``text``/``lit`` key (JSON's decimal string, or an int) as a node index."""
    index = int(key) if admissible(_INDEX, key) else key
    require(exact_int(index, 0, n - 1), f"bad node index {key!r}")
    return int(index)


def _entries(raw: _Doc, name: str) -> dict[object, Any]:
    entries = raw.get(name, {})
    require(isinstance(entries, dict), f"{name} is not an object")
    return entries


# ── text (§6.2: which kinds may carry text, and what) ────────────────────────


def _identifier_text(raw: _Doc, i: int, value: str) -> bool:
    return IDENTIFIER.fullmatch(value) is not None


def _keyword_text(raw: _Doc, i: int, value: str) -> bool:
    return value in DECLARATION_KEYWORDS


def _operator_text(raw: _Doc, i: int, value: str) -> bool:
    return value in OPERATOR_TOKENS


def _literal_text(raw: _Doc, i: int, value: str) -> bool:
    """M1: an identifier-shaped key in INDEX position; M4: a flag or an interpreter
    basename in ARGS/ARRAY position. Nothing else of a literal ever ships."""
    if raw["field"][i] == Field.INDEX and IDENTIFIER.fullmatch(value):
        return True
    return _in_list(raw, i) and shell_word(value) == value


def _in_list(raw: _Doc, i: int) -> bool:
    """Node ``i``'s parent is an ARGS container or an ARRAY (the root has no parent)."""
    parent = raw["parent"][i]
    return parent >= 0 and raw["kind"][parent] in LIST_KINDS


_TEXT_RULES: dict[Kind, Callable[[_Doc, int, str], bool]] = {
    Kind.NAME: _identifier_text,
    Kind.PARAM: _identifier_text,
    Kind.IMPORT: _identifier_text,
    Kind.KWARG: _identifier_text,
    Kind.OTHER: _keyword_text,
    Kind.BINOP: _operator_text,
    Kind.UNARY: _operator_text,
    Kind.LITERAL: _literal_text,
}


def _text_ok(raw: _Doc, i: int, value: object) -> bool:
    rule = _TEXT_RULES.get(raw["kind"][i])
    return rule is not None and _short_text(value) and rule(raw, i, value)


def _short_text(value: object) -> bool:
    """``_short_ascii``'s rule for one value: an ASCII ``str`` of at most ``MAX_TEXT_BYTES``."""
    return isinstance(value, str) and value.isascii() and len(value) <= MAX_TEXT_BYTES


# The kinds whose text is an identifier: the bulk of every document, checked as one column.
# The model's MAX_WORDS tally counts the words of these same kinds.
IDENTIFIER_KINDS = frozenset(kind for kind, rule in _TEXT_RULES.items() if rule is _identifier_text)

type _ColumnsOk = Callable[[_Doc, list[int], list[Any]], bool]
type _EntryOk = Callable[[_Doc, int, Any], bool]


def _keyed(raw: _Doc, name: str, n: int, columns_ok: _ColumnsOk, entry_ok: _EntryOk) -> dict[int, Any]:
    """``raw[name]`` (``text`` or ``lit``) keyed by node index, every entry within its rule.
    The columns are checked at once by ``columns_ok`` (in C where a builtin can); a document
    that fails is re-checked entry by entry by ``entry_ok``, which names the first entry at
    fault."""
    entries = _entries(raw, name)
    indices = _column_indices(list(entries), n)
    values = list(entries.values())
    if indices is None or not columns_ok(raw, indices, values):
        return _checked(raw, entries, n, name, entry_ok)
    return dict(zip(indices, values, strict=True))


def _checked(raw: _Doc, entries: dict[object, Any], n: int, name: str, entry_ok: _EntryOk) -> dict[int, Any]:
    """``_keyed`` one entry at a time: raises on the first entry outside its rule."""
    out: dict[int, Any] = {}
    for key, value in entries.items():
        i = _index(key, n)
        require(entry_ok(raw, i, value), f"{name} of node {i} breaks its rule")
        out[i] = value
    return out


def _column_indices(keys: list[object], n: int) -> list[int] | None:
    """Every key as a node index when all are canonical decimal strings within ``n`` nodes
    (JSON's object keys), else None."""
    if not set(map(type, keys)) <= {str} or not all(map(_INDEX.fullmatch, keys)):
        return None
    indices = list(map(int, keys))
    return indices if _within(indices, 0, n - 1) else None


def _texts_ok(raw: _Doc, indices: list[int], values: list[object]) -> bool:
    """Every value short ASCII text, and each within its kind's rule."""
    return _short_ascii(values) and _rules_hold(raw, indices, values)


def _short_ascii(values: list[object]) -> bool:
    """Every value an ASCII ``str`` of at most ``MAX_TEXT_BYTES`` (three passes in C)."""
    if not set(map(type, values)) <= {str}:
        return False
    return all(map(str.isascii, values)) and max(map(len, values), default=0) <= MAX_TEXT_BYTES


def _rules_hold(raw: _Doc, indices: list[int], values: list[Any]) -> bool:
    """Every identifier kind's text an identifier (one ``map``); every other entry within
    its own rule."""
    named = list(map(IDENTIFIER_KINDS.__contains__, map(raw["kind"].__getitem__, indices)))
    identifiers = compress(values, named)
    others = compress(zip(indices, values, strict=True), map(operator.not_, named))
    return all(map(IDENTIFIER.fullmatch, identifiers)) and all(
        _text_ok(raw, i, value) for i, value in others
    )


# ── lit (§6.2, D3, R3, W15 b) ────────────────────────────────────────────────


def _lit_entry_ok(entry: object, size: int) -> bool:
    """``[class, length]`` or ``[class, length, value]``."""
    if not _lit_shaped(entry):
        return False
    cls, length, *value = entry
    return _lit_class_ok(cls) and exact_int(length, 0, size) and _lit_value_ok(value)


def _lit_shaped(entry: object) -> TypeGuard[list[object]]:
    """A list of two or three items: a ``lit`` record's shape."""
    return type(entry) is list and len(entry) in (2, 3)


def _lit_class_ok(cls: object) -> bool:
    return isinstance(cls, str) and cls in LITERAL_CLASSES


def _lit_value_ok(value: list[object]) -> bool:
    """D3: a value is a boolean or a short plain number, or absent."""
    return all(admissible(LIT_VALUE, v) for v in value)


def _lits_ok(raw: _Doc, indices: list[int], records: list[object]) -> bool:
    """Every entry on a LITERAL, and every record within its rule."""
    on_literals = set(map(raw["kind"].__getitem__, indices)) <= {Kind.LITERAL}
    return on_literals and all(map(_lit_entry_ok, records, repeat(raw["size"])))


def _lit_ok(raw: _Doc, i: int, entry: object) -> bool:
    """One ``lit`` entry: on a LITERAL, and its record within its rule."""
    return raw["kind"][i] == Kind.LITERAL and _lit_entry_ok(entry, raw["size"])
