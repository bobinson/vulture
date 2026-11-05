"""Feature 0102, plan task 1.2: what the parse worker may import (D1, D2, D3; review M6).

The worker is the process that runs tree-sitter's native code over attacker-controlled bytes
(LLD §11 T4). D2 starts it isolated (``python -I``, an explicit ``sys.path``, a private cwd,
env ``{PATH, LANG}``); this file makes its import surface a checked fact rather than prose:

* statically — ``_worker.py`` parsed with the stdlib ``ast``: outside its own package it imports
  exactly ``{sys, json, struct, resource, importlib, tree_sitter}`` plus grammar modules (in
  practice by name, through ``importlib``), and ``ctypes`` only inside a ``try`` (``prctl``);
* dynamically — a fresh ``python -I`` that puts only the parent's ``shared`` root on
  ``sys.path`` (the D2 bootstrap minus ``main()``) imports ``shared.ast._worker`` without
  starting its loop and without loading the parent's machinery.

``struct`` is allowed but not required: the u32 frame layout is one fact (D19) and may reach
the worker through ``_frames``. Every other name of the set is the worker's own job — stdin and
stdout (``sys``), JSON frames (``json``, D3), rlimits (``resource``, D2), grammar modules by
name (``importlib``), the parser (``tree_sitter``, which no parent-side module imports, D1).
"""

from __future__ import annotations

import ast
import functools
import importlib
import itertools
import json
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType

from shared.ast import _frames, _validate, _worker
from shared.ast.profile import PROFILES
from shared.testing.timing import budget
from tests.unit.ast._support import SHARED_ROOT, isolated_python

_PACKAGE = "shared.ast"

_ISOLATED_SET = frozenset({"sys", "json", "struct", "resource", "importlib", "tree_sitter"})
_REQUIRED = _ISOLATED_SET - {"struct"}
_GRAMMARS = frozenset(profile.grammar_module for profile in PROFILES.values())
_TRY_ONLY = frozenset({"ctypes"})  # prctl(PR_SET_NO_NEW_PRIVS), D2
_DESERIALISERS = frozenset({"pickle", "_pickle", "marshal", "shelve", "dill", "cloudpickle", "joblib"})
# Builtins that would reopen what the import set closes: dynamic import, code execution, and
# `open` (§4: the worker never opens a file — the parent ships the bytes).
_FORBIDDEN_CALLS = frozenset({"__import__", "exec", "eval", "compile", "open"})
# Loaded by none of the isolated set (measured: tree_sitter, the nine grammars and
# importlib.metadata leave every one of these out), so any of them in the worker is a leak.
_PARENT_MACHINERY = (
    "shared.validate",
    "shared.audit_runner",
    "shared.tools",
    "shared.ast.pool",
    "shared.ast.cache",
    "litellm",
    "agents",
    "openai",
    "subprocess",
    "pickle",
)


def _absolute(node: ast.ImportFrom) -> str:
    """An ``ImportFrom``'s module, relative levels resolved against ``shared.ast``."""
    if node.level == 0:
        return node.module or ""
    base = _PACKAGE.split(".")[: 3 - node.level]
    return ".".join(base + ([node.module] if node.module else []))


def _imported(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    return [_absolute(node)] if isinstance(node, ast.ImportFrom) else []


def _collect(node: ast.AST, in_try: bool, out: list[tuple[str, bool]]) -> None:
    out.extend((name, in_try) for name in _imported(node))
    inner = in_try or isinstance(node, (ast.Try, ast.TryStar))
    for child in ast.iter_child_nodes(node):
        _collect(child, inner, out)


@functools.cache
def _tree(module: ModuleType) -> ast.Module:
    """``module``'s source, parsed once."""
    return ast.parse(Path(module.__file__).read_text(encoding="utf-8"))


def _imports(module: ModuleType) -> list[tuple[str, bool]]:
    """``(absolute module, inside a try)`` for every import statement in ``module``'s source."""
    out: list[tuple[str, bool]] = []
    _collect(_tree(module), False, out)
    return out


def _under(root: str, name: str) -> bool:
    """``name`` is the module ``root`` or a module inside it (never a sibling: ``shared_x``
    is not under ``shared``)."""
    return name == root or name.startswith(root + ".")


_is_package = functools.partial(_under, "shared")
_in_shared_ast = functools.partial(_under, _PACKAGE)


def _package_imports(records: list[tuple[str, bool]]) -> set[str]:
    return {name for name, _ in records if _is_package(name)}


def _external(records: list[tuple[str, bool]]) -> set[str]:
    """Top-level names imported from outside ``shared`` (``__future__`` is a compiler directive)."""
    tops = {name.split(".")[0] for name, _ in records if not _is_package(name)}
    return tops - {"__future__"}


def test_worker_imports_exactly_the_isolated_set() -> None:
    names = _external(_imports(_worker))
    assert names - (_ISOLATED_SET | _GRAMMARS | _TRY_ONLY) == set()
    assert _REQUIRED - names == set()


def test_ctypes_is_imported_only_inside_a_try() -> None:
    """``prctl`` is best effort (D2: "prctl if available"): ctypes may not exist on a platform."""
    guarded = [in_try for name, in_try in _imports(_worker) if name.split(".")[0] in _TRY_ONLY]
    assert all(guarded)


def test_worker_package_imports_stay_inside_shared_ast() -> None:
    """The worker reaches ``shared`` only through ``shared.ast`` (frames, limits, kinds, profiles),
    never the pool that spawns it or the cache that reads source files."""
    package = _package_imports(_imports(_worker))
    outside = set(itertools.filterfalse(_in_shared_ast, package))
    assert (outside, package & {"shared.ast.pool", "shared.ast.cache"}) == (set(), set())


def _callees(module: ModuleType) -> list[ast.expr]:
    return [node.func for node in ast.walk(_tree(module)) if isinstance(node, ast.Call)]


def _called_builtins(module: ModuleType) -> set[str]:
    """Names called bare (``open(...)``, ``__import__(...)``); attribute calls are not builtins."""
    return {func.id for func in _callees(module) if isinstance(func, ast.Name)}


def test_worker_calls_no_dynamic_import_execution_or_open() -> None:
    assert _called_builtins(_worker) & _FORBIDDEN_CALLS == set()


def test_wire_modules_import_no_deserialiser() -> None:
    """D3: JSON frames only — on both sides of the boundary."""
    wire = (_frames, _validate, _worker)
    found = {m.__name__: sorted(_external(_imports(m)) & _DESERIALISERS) for m in wire}
    assert found == {m.__name__: [] for m in wire}


def _isolated_import_probe(
    cwd: Path, watched: Sequence[str] = _PARENT_MACHINERY
) -> tuple[int | None, str, str]:
    """Run D2's bootstrap minus ``main()`` with stdin held OPEN: a worker loop started by the
    import would block reading it and never print. ``(returncode or None if it hung, out, err)``;
    ``out`` ends with the worker's file and the ``watched`` modules loaded."""
    probe = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(SHARED_ROOT)!r})\n"
        "import shared.ast._worker as w\n"
        f"print(json.dumps([w.__file__, [m for m in {tuple(watched)!r} if m in sys.modules]]))\n"
    )
    with isolated_python(probe, cwd, stderr=subprocess.PIPE, text=True) as proc:
        try:
            code = proc.wait(timeout=budget(30.0))
        except subprocess.TimeoutExpired:
            proc.kill()
            code = None
        return code, proc.stdout.read(), proc.stderr.read()


def test_isolated_import_loads_this_worker_and_none_of_the_parent_machinery(tmp_path: Path) -> None:
    """D2's bootstrap minus ``main()``: under ``-I`` with only the parent's ``shared`` root on
    ``sys.path``, the import resolves to THIS checkout's worker, returns (importing does not start
    the loop), and loads no module of the parent's audit machinery (D1, §4)."""
    code, out, err = _isolated_import_probe(tmp_path)
    assert code == 0, err or "the import never returned: does importing _worker start its loop?"
    worker_file, loaded = json.loads(out.strip().splitlines()[-1])
    assert (Path(worker_file).resolve(), loaded) == (Path(_worker.__file__).resolve(), [])


# ── A16: the worker never loads the distribution-metadata machinery ──────────
#
# ``GRAMMAR_VERSIONS`` / ``GRAMMAR_PACK_VERSION`` are the parent's, computed lazily, once
# (A16); the worker, which parses attacker-controlled bytes, never imports
# ``importlib.metadata``. Statically: no statement that runs when the worker is imported —
# in ``_worker.py`` or in any ``shared`` module that import reaches, followed transitively,
# parent packages included — loads it (a function body runs only when called, so a lazy
# import in the parent's code is allowed). Dynamically: the isolated import above leaves it
# out of ``sys.modules`` (measured: ``tree_sitter`` and the nine grammars never load it).

_METADATA = "importlib.metadata"
_DEFERRED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _loaded(node: ast.AST) -> list[str]:
    """What one import statement loads: ``import a.b`` -> ``a.b``; ``from a import b`` ->
    ``a`` and ``a.b`` (``b`` may be a submodule)."""
    if isinstance(node, ast.ImportFrom):
        base = _absolute(node)
        return [base, *(f"{base}.{alias.name}" for alias in node.names)]
    return _imported(node)


def _run_on_import(node: ast.AST) -> Iterator[ast.AST]:
    """``node``'s descendants that run when their module is imported (not a function body)."""
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, _DEFERRED):
            yield child
            yield from _run_on_import(child)


def _is_module(name: str) -> bool:
    try:
        importlib.import_module(name)
    except ImportError:
        return False
    return True


def _with_parents(name: str) -> set[str]:
    """``name`` and every package above it: importing ``a.b.c`` runs ``a`` and ``a.b`` first."""
    parts = name.split(".")
    return {".".join(parts[:k]) for k in range(1, len(parts) + 1)}


def _next_modules(names: set[str]) -> set[str]:
    """The ``shared`` modules among ``names``, with their parent packages."""
    return {m for name in filter(_is_package, names) for m in _with_parents(name) if _is_module(m)}


def _import_time_loads(name: str) -> set[str]:
    tree = _tree(importlib.import_module(name))
    return {loaded for node in _run_on_import(tree) for loaded in _loaded(node)}


def _worker_import_closure() -> dict[str, set[str]]:
    """Every ``shared`` module importing the worker runs, each with what it loads then."""
    found: dict[str, set[str]] = {}
    pending = [_worker.__name__]
    while pending:
        name = pending.pop()
        found[name] = _import_time_loads(name)
        pending.extend(_next_modules(found[name]) - found.keys() - set(pending))
    return found


def _loads_metadata(names: set[str]) -> bool:
    return any(map(functools.partial(_under, _METADATA), names))


def test_worker_never_imports_importlib_metadata(tmp_path: Path) -> None:
    """A16: neither statically (the worker's import-time import set) nor dynamically (the
    isolated import of the worker, through this module's probe) is ``importlib.metadata``
    loaded in the worker."""
    closure = _worker_import_closure()
    static = sorted(filter(lambda module: _loads_metadata(closure[module]), closure))

    code, out, err = _isolated_import_probe(tmp_path, (_METADATA,))

    assert code == 0, err
    _, loaded = json.loads(out.strip().splitlines()[-1])
    assert (static, loaded) == ([], []), f"followed {sorted(closure)}"
