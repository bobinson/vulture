"""Feature 0102: what the ``tests/unit/ast`` modules share. Not a test module.

One home for facts and steps several modules would otherwise each restate:

* the v1 grammar table of LLD §6.3 and a per-session cache of the installed grammars. The
  test process may load them; D1 keeps ``tree_sitter`` out of the library's parent side only;
* the D2 spawn shape (``python -I -c``, a private cwd, env ``{PATH, LANG}``) and the D3 request
  frames, built independently of ``shared.ast._frames``;
* the per-audit reset and a fixed pool size, which ``conftest.py`` and the pool tests apply;
* the hook workers of ``_workers/`` and the patched wall timeout the pool, cache and coverage
  modules share (A33: one home for a helper more than one module uses);
* a model built through a real worker the way plan task 1.5's ``get_model`` builds it, minus
  its cache — with the grammar entry point the file's suffix selects (A13, A14:
  ``profile.grammar_for``) — and the cwe ``ast_v1`` fixtures read through it once (by path,
  read-only).

RED until ``shared.ast`` exists: importing this module fails with ``ModuleNotFoundError``.
"""

from __future__ import annotations

import functools
import importlib
import json
import os
import struct
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import tree_sitter

from shared.ast import FileModel, limits
from shared.ast import pool as ast_pool
from shared.ast._validate import validate_model
from shared.ast.pool import get_pool, reset_pool_for_tests
from shared.ast.profile import LanguageProfile, profile_for
from shared.tools.file_scanner import clear_caches, read_file_safe

# ── grammars (LLD §6.3) ──────────────────────────────────────────────────────

# The nine v1 profiles (D-D, D-H), keyed by ``shared.language`` names, and the grammar wheel
# and entry point §6.3 gives each.
GRAMMARS: dict[str, tuple[str, str]] = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "python": ("tree_sitter_python", "language"),
    "go": ("tree_sitter_go", "language"),
    "java": ("tree_sitter_java", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
}
LANGUAGES = tuple(GRAMMARS)
# The .tsx/.jsx variant of the shared JS/TS map (LLD §6.3).
TSX_GRAMMAR = ("tree_sitter_typescript", "language_tsx")


@functools.cache
def grammar(module: str, attr: str) -> tree_sitter.Language:
    """An installed grammar, loaded once per test session."""
    return tree_sitter.Language(getattr(importlib.import_module(module), attr)())


def profile_grammar(profile: LanguageProfile) -> tree_sitter.Language:
    """The grammar a profile names."""
    return grammar(profile.grammar_module, profile.grammar_attr)


# ── the D2 spawn and the D3 wire ─────────────────────────────────────────────

# D2: the parent's ``shared`` root, the one entry the worker bootstrap puts on ``sys.path``
# (the pool's own; test_0102_worker_pool.py pins it, and the bootstrap, to D2's text).
SHARED_ROOT = Path(ast_pool.SHARED_ROOT)


def worker_env() -> dict[str, str]:
    """D2: a worker's whole environment."""
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}


def isolated_python(script: str, cwd: Path, **streams: Any) -> subprocess.Popen[Any]:
    """``python -I -c script`` started the way D2 starts a worker: in ``cwd``, with env
    ``{PATH, LANG}`` and piped stdin and stdout; ``streams`` sets stderr (and ``text``)."""
    return subprocess.Popen(
        [sys.executable, "-I", "-c", script],
        cwd=cwd,
        env=worker_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        **streams,
    )


def frame(payload: bytes) -> bytes:
    """D3's unit on the wire: a big-endian u32 length, then the bytes."""
    return struct.pack(">I", len(payload)) + payload


def request_frames(header: dict[str, object], body: bytes) -> bytes:
    """One D3 request: the JSON header frame, then the file-bytes frame."""
    return frame(json.dumps(header).encode()) + frame(body)


# ── one audit on a pool of a known size (§4, D20) ────────────────────────────


def new_audit() -> None:
    """The per-audit reset: the pool's workers (and, until plan task 2.4, the breaker stub) via
    ``reset_pool_for_tests()``; the process-default AuditContext (and the breaker on it) via
    ``clear_caches()`` (D20)."""
    reset_pool_for_tests()
    clear_caches()


def workers_of(count: int) -> Callable[..., int]:
    """A stand-in for ``shared.ast.pool.worker_count`` that sizes every pool at ``count``."""

    def worker_count(*_args: object, **_kwargs: object) -> int:
        return count

    return worker_count


@contextmanager
def one_audit(patch: Any) -> Iterator[None]:
    """One audit on a W = 1 pool, the compose shape (§4): ``patch`` (a ``MonkeyPatch``) pins
    the pool size, and a fresh pool and audit start on entry; none is left behind on exit."""
    patch.setattr(ast_pool, "worker_count", workers_of(1))
    new_audit()
    try:
        yield
    finally:
        new_audit()


# ── hook workers and a short wall timeout (D2, D10) ──────────────────────────

# The hostile stand-ins for a worker (``crash.py``, ``hang.py``, ...), next to this file.
WORKERS = Path(__file__).resolve().parent / "_workers"
TRIP_S = 0.3  # WALL_TIMEOUT_S patched for the breaker: twenty hangs in about six seconds


def hook_command(name: str, *argv: str) -> list[str]:
    """The command of the hook worker ``_workers/<name>``, run the way D2 runs a worker
    (``python -I``), with ``argv``."""
    return [sys.executable, "-I", str(WORKERS / name), *argv]


def wall_timeout(patch: Any, seconds: float) -> None:
    """Shorten the per-file wall timeout where the pool reads it (D18: a constant of
    limits.py); ``patch`` is a ``MonkeyPatch``, which undoes it."""
    patch.setattr(limits, "WALL_TIMEOUT_S", seconds)
    patch.setattr(ast_pool, "WALL_TIMEOUT_S", seconds, raising=False)


# ── models through a real worker ─────────────────────────────────────────────

# agents/: this file is agents/shared/tests/unit/ast/_support.py.
AST_V1 = Path(__file__).resolve().parents[4] / "cwe" / "tests" / "corpus" / "fixtures" / "ast_v1"

# One fixture per v1 profile, plus a parse-error file (cwe_22_17.js: a model with an
# ERROR node is still a model) and the multi-line / U+2028 fixtures.
STRUCTURE_FIXTURES = (
    "cwe_22_1.js", "cwe_22_16.js", "cwe_22_17.js", "cwe_22_20.js", "cwe_22_21.ts",
    "cwe_22_15.py", "cwe_78_18.py", "cwe_22_go_3.go", "cwe_22_java_1.java",
    "cwe_22_rs_2.rs", "cwe_22_php_3.php", "cwe_22_c_1.c", "cwe_22_cpp_1.cpp",
)


def write(path: Path, data: str | bytes) -> Path:
    """``data`` (a ``str`` is written as UTF-8) at ``path``, its directory created."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


def parse_model(text: str, language: str, grammar: str | None = None) -> FileModel:
    """``text`` through a real worker and the boundary validator into a model, parsed with
    the grammar entry point ``grammar`` (None: the language's own)."""
    doc = get_pool().parse(language, text.encode("utf-8"), grammar)
    assert isinstance(doc, dict), f"the worker fell back ({doc!r}); these tests need a model"
    return FileModel.from_doc(validate_model(doc), text)


def model_of_path(path: Path) -> tuple[FileModel, str]:
    """The model of a file on disk and the text it was built from (the one decode), parsed
    with the entry point its suffix selects (A13, A14: ``profile.grammar_for``, so a ``.tsx``
    file is parsed as TSX, as ``get_model`` parses it)."""
    text = read_file_safe(path)
    profile = profile_for(path)
    assert text is not None and profile is not None, path
    return parse_model(text, profile.language, profile.grammar_for(path)), text


@functools.cache
def fixture_model(name: str) -> tuple[FileModel, str]:
    """An ``ast_v1`` fixture's model, built once: a model is immutable."""
    return model_of_path(AST_V1 / name)


def only_call(m: FileModel) -> int:
    """The model's one CALL."""
    (call,) = m.calls()
    return call


def failing(nodes: Iterable[int], broken: Callable[[int], bool]) -> list[int]:
    """The nodes for which ``broken`` holds: empty while an invariant is kept."""
    return [i for i in nodes if broken(i)]
