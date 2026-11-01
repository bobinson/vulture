"""Shared tools for audit agents.

The names below are LAZY (PEP 562): each is imported from its home module on first access.
Importing any submodule (``shared.tools.file_scanner``, ``shared.tools.membudget``) first
imports this package, so an eager import here would load every LLM tool wrapper — and with
them the agents SDK — into a process that only wanted the scanner. A name this package does
not export raises ``AttributeError``, which is what lets ``from shared.tools import
file_scanner`` fall through to the submodule import.
"""

from __future__ import annotations

import importlib

# Exported name -> the submodule of this package that defines it.
_HOMES: dict[str, str] = {
    "parse_ast": "ast_parser",
    "parse_ast_tool": "ast_parser",
    "check_dependencies": "dependency_checker",
    "check_dependencies_tool": "dependency_checker",
    "list_files": "file_lister",
    "list_files_tool": "file_lister",
    "read_file": "file_reader",
    "read_file_tool": "file_reader",
    "git_log": "git_history",
    "git_log_tool": "git_history",
    "search_pattern": "pattern_matcher",
    "search_pattern_tool": "pattern_matcher",
}
# ``ALL_TOOLS``: the LLM tool objects, in this order.
_ALL_TOOLS = (
    "read_file_tool",
    "list_files_tool",
    "search_pattern_tool",
    "parse_ast_tool",
    "check_dependencies_tool",
    "git_log_tool",
)

__all__ = ["ALL_TOOLS", *sorted(_HOMES)]


def _resolve(name: str) -> object:
    """The exported ``name``, imported from its home module (``ALL_TOOLS``: built from them)."""
    if name == "ALL_TOOLS":
        return [__getattr__(tool) for tool in _ALL_TOOLS]
    return getattr(importlib.import_module(f"{__name__}.{_HOMES[name]}"), name)


def __getattr__(name: str) -> object:
    """PEP 562: resolve an exported name on first access, then keep it as a plain attribute."""
    if name != "ALL_TOOLS" and name not in _HOMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = globals()[name] = _resolve(name)
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
