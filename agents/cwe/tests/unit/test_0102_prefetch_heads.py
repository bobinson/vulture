"""Feature 0102, A44 (2) (LLD §4.1 item 6, plan task 3.9, tests 28-31): the cwe heads under parse
prefetch.

Each migrated skill — ``input_validation`` (CWE-22) and ``injection`` (CWE-918, CWE-78) — loops
over its files under ``_ast_head.ast_walk(files, <its skip predicate>, <its rules>)``, which
filters with the skill's own skip predicate and wraps ``shared.ast.prefetch.walk``. The real
head, ``_ast_head._family_model``, calls ``prefetch.advance(path)`` and then ``owns_answer(path)``;
``profile.owns_family`` (today's ``_ast_head._owned``) is the one ownership predicate of the
head and the prefetch. Pinned here, through both skills on real workers (a four-slot pool, so
tickets are issued):

* **Equivalence (test 28).** Over an ``ast_v1`` copy the two skills, on two threads of one audit
  as the runner submits them, give identical findings (ids aside), ``ast_coverage``
  (``tallies.cache`` included) and decline lines with ``PREFETCH_AHEAD`` 0, with its default,
  and on the library path (``owns`` in place of ``owns_answer``).
* **The regex seams stay pure (test 29).** Under ``relative_gate._regex_tier()`` and under the
  conftest ``regex_tier`` fixture, which replace ``ast_spans`` / ``ast_answers`` / ``_answer``
  above ``advance``, no ticket is issued and nothing is parsed: A7's denominator is pure regex.
* **The walk (test 30).** It yields the files the former skip-filtered loop visited, in the
  same order, and a file the skill skips is never sent to a worker.
* **One door (test 31).** ``advance`` is reached only through the real ``_answer`` (each call
  right before ``owns_answer`` of the same file; never under a regex seam), and the head and
  the prefetch decide ownership through ``profile.owns_family``.

RED until task 3.9: ``limits.PREFETCH_AHEAD``, ``WorkerPool.issue``, ``cache.owns_answer``,
``_ast_head.ast_walk``, ``shared.ast.prefetch`` and ``profile.owns_family`` do not exist.
"""

from __future__ import annotations

import contextvars
import importlib
import json
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager, nullcontext
from operator import itemgetter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import shared
from cwe_agent.skills import _ast_head, injection_check, input_validation_check
from shared.ast import cache as ast_cache
from shared.ast import context as ast_context
from shared.ast import limits
from shared.ast import pool as pool_mod
from shared.ast import profile as ast_profile
from shared.ast.pool import WorkerPool, reset_pool_for_tests
from shared.tools.file_scanner import clear_caches, scan_code_files
from tests import _ast_v1
from tests._neutral import neutral_dir

_SKILLS = (input_validation_check.check_input_validation, injection_check.check_injection)
# agents/shared/tests/perf: the relative gate, a script beside the bench, not a package.
_PERF = Path(shared.__file__).resolve().parents[1] / "tests" / "perf"

# The two suites' ``tests`` packages collide, so the shared suite's helpers are not importable
# here and the few this module needs are copied: ``_four_workers`` is ``_support.workers_of(4)``,
# ``_prefetch`` and ``_set_ahead`` are ``_prefetch.prefetch_mod`` and ``set_ahead``, and ``_Calls``
# is a lighter ``_prefetch.Spy`` (with ``pool_spies`` and ``shipped`` in ``_pool_calls``).


def _four_workers(*_args: object, **_kwargs: object) -> int:
    return 4


@pytest.fixture
def pool4(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A fresh four-slot process pool (three tickets at most) and an empty model cache."""
    monkeypatch.setattr(pool_mod, "worker_count", _four_workers)
    reset_pool_for_tests()
    ast_cache.clear()
    yield
    reset_pool_for_tests()
    ast_cache.clear()
    clear_caches()


def _prefetch() -> ModuleType:
    """``shared.ast.prefetch`` (plan 3.9), imported when a test needs it."""
    return importlib.import_module("shared.ast.prefetch")


def _set_ahead(patch: pytest.MonkeyPatch, ahead: int) -> None:
    """``PREFETCH_AHEAD`` patched in ``limits`` and wherever ``prefetch`` bound it."""
    patch.setattr(limits, "PREFETCH_AHEAD", ahead)
    patch.setattr(_prefetch(), "PREFETCH_AHEAD", ahead, raising=False)


class _Calls:
    """Calls to stand-ins, in order: ``(name, the argument each records)``."""

    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    def wrap(
        self, name: str, real: Callable[..., Any],
        pick: Callable[[tuple[Any, ...]], Any] = itemgetter(0),
    ) -> Callable[..., Any]:
        """``real`` recording each call as ``(name, pick(its arguments))`` — its first argument
        unless ``pick`` says otherwise — then running."""

        def stand_in(*args: Any, **kwargs: Any) -> Any:
            self.log.append((name, pick((*args, *kwargs.values()))))
            return real(*args, **kwargs)

        return stand_in

    def count(self, name: str) -> int:
        return sum(called == name for called, _ in self.log)


def _pool_calls(patch: pytest.MonkeyPatch) -> _Calls:
    """Every ``WorkerPool.issue`` and ``WorkerPool.parse``, recorded with the bytes shipped
    (their argument after the pool and the language)."""
    calls = _Calls()
    for name in ("issue", "parse"):
        patch.setattr(WorkerPool, name, calls.wrap(name, getattr(WorkerPool, name), itemgetter(2)))
    return calls


# ── 28. the prefetched run is the synchronous and the library run ────────────


def _comparable(row: dict[str, Any]) -> str:
    """A row as sorted JSON, without the ``id`` the runner would hash its slot into."""
    return json.dumps({key: value for key, value in row.items() if key != "id"}, sort_keys=True)


def _audited(root: Path) -> dict[str, Any]:
    """Both skills over ``root`` on two threads of a new audit, each submitted through
    ``copy_context().run`` as the runner submits it: the rows, ``ast_coverage`` and the decline
    lines."""
    ast_context.enter(root)
    audit = ast_context.current()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(contextvars.copy_context().run, skill, str(root))
                   for skill in _SKILLS]
        rows = [row for future in futures for row in future.result()["findings"]]
    return {"findings": sorted(map(_comparable, rows)),
            "ast_coverage": audit.coverage.snapshot(root),
            "declines": audit.ledger.lines(root)}


def _run(root: Path, ahead: int | None, library: bool) -> dict[str, Any]:
    """One cold audit of ``root``: ``PREFETCH_AHEAD`` patched to ``ahead`` (None: its default),
    and on the library path (``owns`` answering for ``owns_answer``) when ``library``."""
    with pytest.MonkeyPatch.context() as patch:
        if ahead is not None:
            _set_ahead(patch, ahead)
        if library:
            patch.setattr(ast_cache, "owns_answer", ast_cache.owns)
        clear_caches()
        ast_cache.clear()
        return contextvars.Context().run(_audited, root)


_RUNS: dict[str, tuple[int | None, bool]] = {
    "PREFETCH_AHEAD 0": (0, False),
    "PREFETCH_AHEAD default": (None, False),
    "library path": (0, True),
}


def _evidence(run: dict[str, Any]) -> dict[str, bool]:
    """What a comparison of runs needs before it means anything: AST rows, owned files and
    declines."""
    return {"ast rows": any('"ast": {' in row for row in run["findings"]),
            "parsed": run["ast_coverage"]["files"]["parsed"] > 0,
            "declines": any(line.startswith("ast_decline ") for line in run["declines"])}


def test_prefetched_run_equals_the_synchronous_and_library_runs(
    request: pytest.FixtureRequest, pool4: None
) -> None:
    """Test 28 (D14, A41 (8)): both skills over an ``ast_v1`` copy give identical findings (ids
    aside), ``ast_coverage`` (``tallies.cache`` included) and decline lines with
    ``PREFETCH_AHEAD`` 0, with its default, and on the library path."""
    root = _ast_v1.copy_fixtures(request)
    runs = {name: _run(root, *how) for name, how in _RUNS.items()}
    reference = runs["PREFETCH_AHEAD default"]
    evidence = _evidence(reference)
    assert (evidence, runs) == (dict.fromkeys(evidence, True), dict.fromkeys(runs, reference))


# ── 29. the regex seams issue nothing ────────────────────────────────────────


@contextmanager
def _relative_gate_seam(_request: pytest.FixtureRequest, patch: pytest.MonkeyPatch) -> Iterator[None]:
    """``relative_gate._regex_tier()``: each skill module's AST head answers as for a fallback
    file while the block runs."""
    patch.syspath_prepend(str(_PERF))
    with importlib.import_module("relative_gate")._regex_tier():
        yield


def _conftest_seam(request: pytest.FixtureRequest, _patch: pytest.MonkeyPatch) -> AbstractContextManager[None]:
    """The conftest ``regex_tier`` fixture: ``_ast_head._answer`` answers as for a fallback."""
    request.getfixturevalue("regex_tier")
    return nullcontext()


_SEAMS: dict[str, Callable[[pytest.FixtureRequest, pytest.MonkeyPatch], AbstractContextManager[None]]] = {
    "relative_gate._regex_tier": _relative_gate_seam,
    "conftest regex_tier": _conftest_seam,
}


@pytest.mark.parametrize("seam", sorted(_SEAMS))
def test_the_regex_seams_issue_nothing(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, pool4: None, seam: str
) -> None:
    """Test 29 (A7's denominator): under each regex seam both skills over an ``ast_v1`` copy
    send nothing to a worker — no ticket issued, no parse — and still emit their rows."""
    calls = _pool_calls(monkeypatch)
    root = _ast_v1.copy_fixtures(request)
    with _SEAMS[seam](request, monkeypatch):
        rows = _ast_v1.migrated_rows(root)
    assert (bool(rows), calls.log) == (True, [])


# ── 30. the walk is the skill's former loop ──────────────────────────────────

# A tree each skill walks: sources of four languages, each holding a sink of every family, and
# the files a skill skips — a test file, a file under ``__tests__``, prose and a generated
# skill module — holding the same sinks, so a skipped file the prefetch reached would be sent.
_SINKS_JS = (
    'const fs = require("fs");\n'
    "function handler(req, res) {\n"
    "  fs.readFile(req.query.f, () => res.end());\n"
    "  fetch(req.query.u);\n"
    '  require("child_process").exec("ls " + req.query.c);\n'
    "}\n"
)
_TREE: dict[str, str] = {
    "app.js": _SINKS_JS,
    "routes/files.ts": _SINKS_JS,
    "views.py": "def view(request):\n    return open(request.args['f']).read()\n",
    "main.go": 'package main\n\nimport "os"\n\nfunc main() { os.ReadFile(os.Args[1]) }\n',
    "app.test.js": _SINKS_JS + "// a skipped copy\n",
    "__tests__/helper.js": _SINKS_JS + "// another skipped copy\n",
    "README.md": "Call `fs.readFile(req.query.f)` only with a constant.\n",
    "skills/path_check.py": "def check(request):\n    return open(request.args['f'])\n",
}
_SKIPPED = ("app.test.js", "__tests__/helper.js", "README.md", "skills/path_check.py")
# Each skill: its module, its entry point, its skip predicate and its rules.
_WALKERS: dict[str, tuple[ModuleType, str, str, tuple[str, ...]]] = {
    "input_validation": (input_validation_check, "check_input_validation", "_skip_file",
                         ("_RULE_22",)),
    "injection": (injection_check, "check_injection", "_is_excluded_file",
                  ("_RULE_918", "_RULE_78")),
}


def _tree(request: pytest.FixtureRequest) -> Path:
    root = neutral_dir(request) / "tree"
    for name, text in _TREE.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def _recording_walk(real: Callable[..., Any], seen: list[Path]) -> Callable[..., Any]:
    """``ast_walk`` recording every file it yields, in order."""

    @contextmanager
    def walk(*args: Any, **kwargs: Any) -> Iterator[list[Path]]:
        with real(*args, **kwargs) as walked:
            files = list(walked)
            seen.extend(files)
            yield files

    return walk


def _walked_directly(module: ModuleType, root: Path, skip: str, rules: tuple[str, ...]) -> list[Path]:
    """``_ast_head.ast_walk`` over the scanner's files with the skill's predicate and rules."""
    files = scan_code_files(str(root))
    walk = _ast_head.ast_walk(files, getattr(module, skip), tuple(getattr(module, r) for r in rules))
    with walk as walked:
        return list(walked)


def _unskipped(root: Path, skip: Callable[[Path], bool]) -> list[Path]:
    """The files the former loop visited: the scanner's, less those ``skip`` drops."""
    return [path for path in scan_code_files(str(root)) if not skip(path)]


def _sent(calls: _Calls, root: Path) -> list[bytes]:
    """The bytes of every skipped file a worker was sent."""
    skipped = {(root / name).read_bytes() for name in _SKIPPED}
    return [data for _, data in calls.log if data in skipped]


def _recorded(patch: pytest.MonkeyPatch, module: ModuleType) -> tuple[list[Path], _Calls]:
    """The files ``module``'s ``ast_walk`` yields and those its ``_analyze_file`` is called
    with, each recorded in order."""
    walked: list[Path] = []
    patch.setattr(module, "ast_walk", _recording_walk(module.ast_walk, walked))
    analysed = _Calls()
    patch.setattr(module, "_analyze_file", analysed.wrap("analyse", module._analyze_file))
    return walked, analysed


@pytest.mark.parametrize("skill", sorted(_WALKERS))
def test_the_walk_yields_the_skills_files_in_order(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, pool4: None, skill: str
) -> None:
    """Test 30: the skill's loop runs under ``ast_walk``, which yields — and the skill analyses —
    the files its former skip-filtered loop visited, in the same order; a skipped file is never
    sent to a worker."""
    module, check, skip, rules = _WALKERS[skill]
    root = _tree(request)
    expected = _unskipped(root, getattr(module, skip))
    walked, analysed = _recorded(monkeypatch, module)
    calls = _pool_calls(monkeypatch)
    getattr(module, check)(str(root))
    observed = {"direct": _walked_directly(module, root, skip, rules), "walked": walked,
                "analysed": [path for _, path in analysed.log], "skipped sent": _sent(calls, root)}
    assert observed == {"direct": expected, "walked": expected, "analysed": expected,
                        "skipped sent": []}


# ── 31. advance is reached only through the real _answer ─────────────────────


def _spied(patch: pytest.MonkeyPatch, calls: _Calls, home: ModuleType, name: str) -> None:
    """``home.name`` replaced by a recording stand-in there and wherever the head bound it."""
    stand_in = calls.wrap(name, getattr(home, name))
    patch.setattr(home, name, stand_in)
    if hasattr(_ast_head, name):
        patch.setattr(_ast_head, name, stand_in)


def _pairs(log: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    """Each ``advance`` with the call right after it: ``(that call's name, same file?)``."""
    after = zip(log, [*log[1:], ("end", None)])
    return [(nxt, str(path == other)) for (name, path), (nxt, other) in after if name == "advance"]


def _real_head(_request: pytest.FixtureRequest, _patch: pytest.MonkeyPatch) -> AbstractContextManager[None]:
    return nullcontext()


_HEADS: dict[str, Callable[[pytest.FixtureRequest, pytest.MonkeyPatch], AbstractContextManager[None]]] = {
    "the real head": _real_head,
    **_SEAMS,
}


@pytest.mark.parametrize("head", sorted(_HEADS))
def test_advance_is_reached_only_through_the_real__answer(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, pool4: None, head: str
) -> None:
    """Test 31: through the real head each ``advance(path)`` is followed at once by
    ``owns_answer(path)`` — the head's ``_family_model`` — and under a regex seam ``advance`` is
    never called."""
    calls = _Calls()
    _spied(monkeypatch, calls, _prefetch(), "advance")
    _spied(monkeypatch, calls, ast_cache, "owns_answer")
    root = _ast_v1.copy_fixtures(request)
    with _HEADS[head](request, monkeypatch):
        _ast_v1.migrated_rows(root)
    pairs = _pairs(calls.log)
    real = head == "the real head"
    assert (bool(pairs), set(pairs)) == ((True, {("owns_answer", "True")}) if real else (False, set()))


# The modules that may hold the ownership predicate under its own name.
_HOLDERS = ("shared.ast.cache", "shared.ast.prefetch", "cwe_agent.skills._ast_head")


# A staged tree for the predicate's callers: owned files, each holding a sink key of a walked
# family, so the first file's advance looks ahead (default ``PREFETCH_AHEAD``) past it.
_ASKED_OF = ("cwe_22_1.js", "cwe_22_2.js", "cwe_918_1.js")


def _predicate_callers(patch: pytest.MonkeyPatch) -> set[str]:
    """``profile.owns_family`` replaced by a stand-in recording the module of each caller, in
    ``profile`` and in every module that bound the name."""
    real = ast_profile.owns_family
    callers: set[str] = set()

    def owns_family(*args: Any, **kwargs: Any) -> Any:
        callers.add(sys._getframe(1).f_globals.get("__name__", ""))
        return real(*args, **kwargs)

    patch.setattr(ast_profile, "owns_family", owns_family)
    for holder in map(importlib.import_module, _HOLDERS):
        if hasattr(holder, "owns_family"):
            patch.setattr(holder, "owns_family", owns_family)
    return callers


def test_profile_owns_family_is_the_heads_and_the_prefetchs_one_predicate(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, pool4: None
) -> None:
    """Test 31, its ownership half: ``_ast_head._owned`` answers what ``profile.owns_family``
    answers (True, False — C owns no ``request`` — and None for a language with no profile), and
    over a run of staged ``ast_v1`` files both the head and the prefetch ask it."""
    samples = [(Path("a.js"), "path"), (Path("a.c"), "request"), (Path("a.rb"), "path")]
    agree = [(_ast_head._owned(p, f), ast_profile.owns_family(p, f)) for p, f in samples]
    callers = _predicate_callers(monkeypatch)
    _ast_v1.migrated_rows(_ast_v1.stage(request, _ASKED_OF))
    observed = {"answers": agree, "head asks": "cwe_agent.skills._ast_head" in callers,
                "prefetch asks": bool({"shared.ast.cache", "shared.ast.prefetch"} & callers)}
    assert observed == {"answers": [(True, True), (False, False), (None, None)],
                        "head asks": True, "prefetch asks": True}
