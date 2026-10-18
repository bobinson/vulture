"""``shared.ast``: the shared tree-sitter AST layer (feature 0102).

Isolated, spawned workers parse; the parent validates the shipped skeleton at the boundary,
caches a columnar ``FileModel`` and runs scope and flow analysis in pure Python. Consumers ask
``owns(path)`` and emit through one head (LLD §4, §5).

The public names are LAZY (D1): importing this package does no work and loads neither
``tree_sitter`` (only the worker parses) nor the validation phase, the audit runner or the
LLM client. Each name is imported from its home module on first access.
"""

from __future__ import annotations

import importlib

__all__ = [
    "GRAMMAR_PACK_VERSION",
    "MODEL_SCHEMA",
    "OWNED_CHECK_IDS",
    "DeclineRecord",
    "FamilyRule",
    "FileModel",
    "Flow",
    "FlowAnalysis",
    "Origin",
    "consume",
    "coverage",
    "get_model",
    "model_needed",
    "owns",
    "owns_lang",
]

# The worker document's schema (§6.2): part of the model-cache key with the grammar stamp (D5).
# 2 (A28 (9)): the worker ships the C++ stack constructor as a synthetic CALL (C3).
MODEL_SCHEMA = 2

# Public name -> the module of this package that defines it (LLD §5).
_HOMES: dict[str, str] = {
    "GRAMMAR_PACK_VERSION": "profile",
    "FileModel": "model",
    "owns_lang": "model",
    "get_model": "cache",
    "owns": "cache",
    "FlowAnalysis": "flow",
    "Origin": "flow",
    "Flow": "flow",
    "DeclineRecord": "declines",
    "FamilyRule": "consume",
    "OWNED_CHECK_IDS": "consume",
    "model_needed": "roles",  # beside PREFILTER (A27 (4))
}
# Public submodules reachable as attributes of the package without an import of their own.
_SUBMODULES = frozenset({"consume", "coverage"})


def _resolve(name: str) -> object:
    """The public ``name``, imported from its home module (or the submodule itself)."""
    if name in _SUBMODULES:
        return importlib.import_module(f"{__name__}.{name}")
    return getattr(importlib.import_module(f"{__name__}.{_HOMES[name]}"), name)


def __getattr__(name: str) -> object:
    """PEP 562: resolve a public name on first access, then keep it as a plain attribute."""
    if name not in _HOMES and name not in _SUBMODULES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = globals()[name] = _resolve(name)
    return value
