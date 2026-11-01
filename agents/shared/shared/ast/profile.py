"""Language profiles, the queries generated from them, and the grammar stamp (feature 0102).

LLD §6.3, D19: each profile is a ``NODE_MAP`` table (``shared.ast.profiles``) and its
tree-sitter query is GENERATED from that table by ``build_query`` — one source per fact.
``PROFILES`` is keyed by ``shared.language`` names, so ``profile_for`` needs no extension
table of its own; a profile's ``grammar_variants`` pick the grammar entry point per suffix
(``.tsx``), and ``GRAMMAR_PROFILES`` holds the profile as each entry point parses with it.
``GRAMMAR_VERSIONS`` is read once, here, and ``GRAMMAR_PACK_VERSION``
(part of the model-cache key, D5) changes when any of the ten packages changes (D15).

Nothing here imports ``tree_sitter`` or a grammar (D1): the query is TEXT, compiled only by
the spawned worker. The worker imports this module for its tables, so the two stamps are
LAZY (A16): importing it reads no distribution metadata and loads no
``importlib.metadata``; the parent's first access reads each package once, and every later
access reads nothing.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from shared.ast.profiles import (
    Capture,
    LanguageProfile,
    NodeKey,
    Subscript,
    c,
    cpp,
    frozen,
    go,
    java,
    js_ts,
    php,
    python,
    rust,
)
from shared.language import detect_language

if TYPE_CHECKING:  # the two stamps exist once read (``__getattr__``, A16)
    GRAMMAR_VERSIONS: Mapping[str, str]
    GRAMMAR_PACK_VERSION: str

__all__ = [
    "GRAMMAR_PACK_VERSION",
    "GRAMMAR_PROFILES",
    "GRAMMAR_VERSIONS",
    "PROFILES",
    "Capture",
    "LanguageProfile",
    "build_query",
    "owns_family",
    "profile_for",
]

# ── the nine v1 profiles (D-D, D-H) ──────────────────────────────────────────

PROFILES: Mapping[str, LanguageProfile] = frozen({
    p.language: p
    for p in (
        js_ts.JAVASCRIPT, js_ts.TYPESCRIPT, python.PYTHON, go.GO, java.JAVA, rust.RUST,
        php.PHP, c.C, cpp.CPP,
    )
})


# (language, grammar entry point) -> the profile with that entry point as its ``grammar_attr``:
# what the worker parses a request with, so its parser, query and stamp follow the variant.
GRAMMAR_PROFILES: Mapping[tuple[str, str], LanguageProfile] = frozen({
    (p.language, attr): replace(p, grammar_attr=attr)
    for p in PROFILES.values()
    for attr in p.grammar_attrs
})


def profile_for(path: str | Path) -> LanguageProfile | None:
    """The profile of ``path``'s language, or None when it has none (D19) or §6.4 holds it
    back (``disabled_until``): the one decision point, so the file is ``unsupported``."""
    profile = PROFILES.get(detect_language(str(path)))
    return None if profile is None or profile.disabled_until else profile


def owns_family(path: str | Path, family: str) -> bool | None:
    """D10 by extension alone, never a parse: whether ``path``'s profile owns ``family``
    (§6.3 ``owned_families``: C and C++ own no ``request``); None when it has no profile. The
    one ownership predicate of the consumer heads and the prefetch (§4.1 item 6)."""
    profile = profile_for(path)
    return None if profile is None else family in profile.owned_families


# ── query generation (LLD §6.3) ──────────────────────────────────────────────


def _pattern(key: NodeKey, body: str = "", capture: str = "") -> str:
    """``(type body)capture``, nested under its parent for a ``(parent, type)`` key (W1)."""
    node = f"({key[-1] if isinstance(key, tuple) else key}{body}){capture}"
    return f"({key[0]} {node})" if isinstance(key, tuple) else node


def _positional(index: int, capture: str) -> str:
    """The pattern body that captures the ``index``-th named child: anchored from the first."""
    return " ." + " (_) ." * index + f" (_) @{capture}"


def _patterns(key: NodeKey, row: Capture, kind: str) -> Iterator[str]:
    """One pattern capturing the node as ``@kind``, then one per mapped child as
    ``@kind.field``. Each child is its own pattern, so a node missing an optional field
    still ships, and the order of the fields in the table never matters."""
    yield _pattern(key, capture=f" @{kind}")
    for name, fld in row.fields.items():
        yield _pattern(key, f" {name}: (_) @{kind}.{fld.name.lower()}")
    for index, fld in row.positional.items():
        yield _pattern(key, _positional(index, f"{kind}.{fld.name.lower()}"))
    if row.subscript is not None:
        yield _pattern(key, _subscript_body(row.subscript))


def _subscript_body(spec: Subscript) -> str:
    """A36: the parameter a ``subscript`` row reads, as a pattern body — its type name the
    SUBSCRIPT's OBJECT, its array's index the INDEX — so its grammar names face the compile."""
    array = f"({spec.array} {spec.index}: (_) @subscript.index)"
    return f" ({spec.param} {spec.object}: (_) @subscript.object {spec.declarator}: {array})"


def build_query(node_map: Mapping[NodeKey, Capture]) -> str:
    """The tree-sitter query of a ``NODE_MAP``: capture names are ``kind`` or ``kind.field``.

    A ``kind=None`` row (transparent with its own fields, W1) captures nothing: the worker
    reads its field map from the table while it re-parents the row's children.
    """
    return "\n".join(
        pattern
        for key, row in node_map.items()
        if row.kind is not None
        for pattern in _patterns(key, row, row.kind.name.lower())
    )


# ── the grammar stamp (D5, D15) ──────────────────────────────────────────────


def _distribution(module: str) -> str:
    """The wheel that installs a grammar module (``tree_sitter_go`` -> ``tree-sitter-go``)."""
    return module.replace("_", "-")


def _installed(name: str) -> str:
    """``name``'s installed version; ``"absent"`` keeps a broken install from raising here
    (every parse then fails in the worker and falls back, tallied). ``importlib.metadata`` is
    imported here, on the parent's first stamp read, never by the worker (A16)."""
    import importlib.metadata

    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "absent"


# The ten packages (D15, O7): the tree-sitter core and the grammar of every profile.
_PACK = ("tree-sitter", *sorted({_distribution(p.grammar_module) for p in PROFILES.values()}))
# The two stamps, computed on first access (``__getattr__``), once, under this lock (A16).
_STAMPS = frozenset({"GRAMMAR_VERSIONS", "GRAMMAR_PACK_VERSION"})
_STAMP_LOCK = threading.Lock()


def _read_stamps() -> dict[str, object]:
    """``GRAMMAR_VERSIONS`` (package -> installed version) and ``GRAMMAR_PACK_VERSION`` (each
    version bound to its package, in a fixed order: any one change moves the stamp), read
    from the installed metadata: one read per package."""
    versions = frozen({name: _installed(name) for name in _PACK})
    pack = ";".join(f"{name}=={versions[name]}" for name in _PACK)
    return {"GRAMMAR_VERSIONS": versions, "GRAMMAR_PACK_VERSION": pack}


def _stamp() -> None:
    """Read the two stamps once, under the lock, and keep them as module attributes."""
    with _STAMP_LOCK:
        if "GRAMMAR_PACK_VERSION" not in globals():
            globals().update(_read_stamps())


def __getattr__(name: str) -> object:
    """PEP 562: a stamp's first access computes both (A16); later ones are plain attributes."""
    if name not in _STAMPS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    _stamp()
    return globals()[name]
