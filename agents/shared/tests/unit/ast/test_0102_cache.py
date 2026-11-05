"""Feature 0102, plan task 1.5 (LLD D5, §4, §5, §6.2, §8.7, §10.2; O1): the model
cache, ``get_model`` and ``owns``.

The model cache is the one process-wide store of parsed ``FileModel`` objects,
shared by the concurrent audits of an agent process (§4). Pinned here:

* **Key (D5, A14)** = ``(resolved_path, size, mtime_ns, GRAMMAR_PACK_VERSION,
  MODEL_SCHEMA, language, grammar entry point)`` (``_audit.model_cache_key``). A hit is
  the same immutable object; every spelling of one file under ONE grammar (``str``,
  ``Path``, ``..``, relative, a symlink of the same suffix) is one entry, while a name whose
  suffix selects another entry point (a ``.tsx`` symlink to a ``.ts`` file) is a second
  entry, parsed again under that grammar (A14); a new mtime at the same size, or a new size
  at the same mtime, re-parses.
* **``clear_caches()`` keeps the models (D5, binding).** The plan's 1.5 bullet
  "``clear_caches()`` empties the model cache" contradicts D5, which says the
  model cache is NOT cleared by ``file_scanner.clear_caches()``: the key already
  carries size and mtime, and clearing it at every audit start would empty the
  models the other audits are mid-use of. §3 wins, so this file pins D5. The
  explicit hook ``shared.ast.cache.clear()`` evicts COMPLETED entries only.
* **Byte budget (D5).** LRU by weight; least-recently-used entries are evicted,
  only as many as needed, until ``bytes <= budget``; a model heavier than the
  whole budget is served, not stored (a budget is never a coverage loss,
  invariant 1); the budget is ``min(128 MB, 25 % of the deployment limit)``.
* **An analysis is charged to its model (A35).** Building ``model.analysis()`` adds
  ``analysis.bytes_estimate`` (computed once, at build) to that model's entry; the cache then
  evicts least-recently-used entries until ``bytes <= budget``; a model served but not stored
  keeps its analysis for its own lifetime, outside the accounting.
* **Single-flight (D5, review focus 3).** Requests for one file in the same
  instant on a one-worker pool: one parse, one object for every requester.
* **``clear()`` against an in-flight leader (plan 1.5).** ``clear()`` returns
  while a parse is in flight, leaves the in-flight entry intact (a later request
  still joins the leader) and strands no waiter; the worst case is one
  redundant parse. A leader whose parse raises releases its waiters too, and
  ``get_model`` never raises (§5).
* **Negative outcomes are per audit (A18, A31 (5)).** Exactly ``too_deep``,
  ``ir_too_large``, ``bad_model``, ``worker_error``, ``timeout`` and ``worker_crashed`` are
  memoised in the audit's ``declined`` map, under the key, as the bare reason string;
  ``spawn_failed`` (a breaker fault) is not memoised, and ``circuit_open`` needs no memo.
* **Every ``None`` path tallies on the current context (plan 1.5).**
  ``unsupported`` (Ruby, O1; decided before the file is read, so before its
  size matters), ``too_large`` (above ``MAX_FILE_SIZE``, decided before the
  worker), ``parse_error`` (``owns`` on a model with an ERROR node), each pool
  ``FallbackReason``, and ``bad_model`` (a document the boundary validator
  rejects). The parent ships the text it decoded, encoded once (§4, T5).
* **Immutability.** A cached model raises ``FrozenInstanceError`` on any
  attribute write or delete: one audit can never poison another's model.

Real workers and grammars throughout: the parse spy (``_analysis.PoolSpy``, the one spy
on the pool) wraps the real ``WorkerPool.parse`` (counting, delaying, gating); only the
fallback-reason and ``bad_model`` tests replace the worker's answer. The module runs on
one W = 1 pool (the compose default; review focus 3), ``conftest.py``'s ``real_pool``: no
test here needs a fresh worker, only an empty model cache.

Read API. Tallies are read through the one read API the design gives,
``shared.ast.context.current().coverage.snapshot(root)`` (§10.2; the call shape
of plan task 0.5), reached lazily through ``_analysis.coverage_snapshot`` so the
tests that read no tally do not wait for the context module. The cache's ``budget``
and ``bytes`` are read off the one ``ModelCache`` (§5) in ``shared.ast.cache``, found
by type so no instance name is assumed; the attribute names are the plan's own ("``bytes <=
budget``") and those of feature 0103's read cache.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, get_args

import pytest

from shared.ast import FileModel, get_model, limits, owns
from shared.ast import cache as ast_cache
from shared.ast.pool import FallbackReason, WorkerPool, get_pool
from shared.tools.file_scanner import MAX_FILE_SIZE as READ_CAP
from shared.tools.file_scanner import clear_caches, read_file_safe
from shared.tools.membudget import deployment_memory_limit
from tests.unit.ast._analysis import (
    FAMILIES,
    PoolSpy,
    context_mod,
    coverage_snapshot,
    current_context,
    in_audit,
    spy_pool,
)
from tests.unit.ast._audit import CRASH_HOOK, faults_until_open, model_cache_key
from tests.unit.ast._support import (
    GRAMMARS,
    TRIP_S,
    TSX_GRAMMAR,
    hook_command,
    wall_timeout,
    write,
)

pytestmark = pytest.mark.usefixtures("real_pool")

_CLEAN_JS = "function handler(req) { const p = req.query.f; fs.readFile(p); }\n"
_BROKEN_JS = "function handler(req) {\n  fs.readFile(req.query.f);\n}\nconst broken = ;\n"
_RUBY = "def show\n  File.open(params[:file]) { |f| send_data f.read }\nend\n"
_GO = 'package main\n\nimport "os"\n\nfunc main() { os.ReadFile(os.Args[1]) }\n'
# Same size, six bytes each; the second carries one ERROR node.
_SIX_CLEAN = "f(a);\n"
_SIX_BROKEN = "f(a;)\n"
# A BOM, CRLF, a lone CR, an invalid UTF-8 byte and a U+2028 inside a literal:
# what reaches the worker is the parent's decoded text, never these raw bytes.
_HOSTILE_BYTES = (
    b"\xef\xbb\xbf// bom\r\nconst a = 1;\r// lone carriage return\n"
    b"// invalid \xff byte\nconst s = \"\xe2\x80\xa8\";\nfs.readFile(p);\n"
)
_MODEL_CACHE_CAP = 128 * 1024 * 1024  # D5: min(128 MB, 25 % of the deployment limit)
# Room for two equal models and not three: b and c evict a, the touched pair
# survives, a evicts the least recent (c), and c evicts a again.
_LRU_SEQUENCE = ("b", "c", "c", "b", "a", "b", "c")
_LRU_PARSES = [True, True, False, False, True, False, True]

_SLOW_PARSE_S = 0.2  # review focus 3: the worker answers 200 ms late
_SETTLE_S = 0.2  # long enough for a just-started thread to reach its wait
_PROMPT_S = 10.0  # an operation that must not wait for an in-flight parse
_HANG_S = 60.0  # a request still running after this is a hang
_POLL_S = 0.05  # how often a wait for the leader checks that it is still running
_UNSET = object()


class _Call:
    """``fn()`` on its own daemon thread. ``result()`` fails on a hang and on an
    exception: ``get_model`` and ``owns`` never raise (§5)."""

    def __init__(self, fn: Callable[[], Any]) -> None:
        self.value: Any = _UNSET
        self._thread = threading.Thread(target=self._run, args=(fn,), daemon=True)
        self._thread.start()

    def _run(self, fn: Callable[[], Any]) -> None:
        try:
            self.value = fn()
        except BaseException as exc:  # recorded so the test reports it, not a silent thread death
            self.value = exc

    def done(self, timeout: float = _HANG_S) -> bool:
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def running(self) -> bool:
        return self._thread.is_alive()

    def result(self) -> Any:
        assert self.done(), f"hang: {self._thread.name} still running after {_HANG_S}s"
        assert not isinstance(self.value, BaseException), f"raised: {self.value!r}"
        return self.value


@pytest.fixture(autouse=True)
def _empty_cache() -> Iterator[None]:
    """An empty model cache around every test, on the module's one-worker pool."""
    ast_cache.clear()
    yield
    ast_cache.clear()


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[PoolSpy]:
    """Every ``WorkerPool.parse`` goes through a ``PoolSpy`` wrapping the real one."""
    probe = spy_pool(monkeypatch)
    yield probe
    probe.gate.set()


# ── helpers ──────────────────────────────────────────────────────────────────


def _rewrite(path: Path, text: str, mtime_ns: int) -> None:
    path.write_bytes(text.encode("utf-8"))
    os.utime(path, ns=(mtime_ns, mtime_ns))


def _js_of_size(size: int) -> str:
    """Valid JavaScript of exactly ``size`` bytes: one long comment, then a call."""
    tail = "f(a);\n"
    return "//" + "a" * (size - len(tail) - 3) + "\n" + tail


def _same_shape_js(tag: str) -> str:
    """Forty calls whose identifiers differ only in the one-letter ``tag``, so
    every tag yields a model of the same weight."""
    return "".join(f"call_{tag}_{i:03d}(arg_{tag});\n" for i in range(40))


def _write_same_shape(root: Path, tags: str) -> dict[str, Path]:
    return {tag: write(root / f"{tag}.js", _same_shape_js(tag)) for tag in tags}


def _fallback(root: Path) -> dict[str, int]:
    return dict(coverage_snapshot(root)["files"]["fallback"])


def _cache_tallies(root: Path) -> dict[str, int]:
    return dict(coverage_snapshot(root)["tallies"]["cache"])


def _moved(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """The counters that changed, by how much."""
    return {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}


def _measured(path: Path, root: Path) -> tuple[FileModel | None, dict[str, int]]:
    """``get_model(path)`` and the fallback tallies it moved, both read on the
    calling thread (a thread's context is its own)."""
    before = _fallback(root)
    model = get_model(path)
    return model, _moved(before, _fallback(root))


def _model_cache() -> Any:
    """The one ``ModelCache`` (D5: one cache), found by type."""
    found = [v for v in vars(ast_cache).values() if isinstance(v, ast_cache.ModelCache)]
    assert len(found) == 1, f"D5 names one model cache; shared.ast.cache holds {len(found)}"
    return found[0]


def _parsed(spy: PoolSpy, cache: Any, path: Path) -> bool:
    """Request ``path`` (a model must come back); True when that took a parse.
    The budget holds after every request."""
    calls = len(spy.calls)
    assert isinstance(get_model(path), FileModel), path
    assert cache.bytes <= cache.budget, (cache.bytes, cache.budget)
    return len(spy.calls) > calls


def _weight_of(spy: PoolSpy, cache: Any, path: Path) -> int:
    """What one model of ``path`` adds to an empty cache."""
    assert cache.bytes == 0, cache.bytes
    assert _parsed(spy, cache, path)
    assert cache.bytes > 0, "a cached model weighs nothing"
    return cache.bytes


def _distinct(models: list[Any]) -> int:
    return len({id(model) for model in models})


def _all_models(models: list[Any]) -> bool:
    return all(isinstance(model, FileModel) for model in models)


def _released(barrier: threading.Barrier, fn: Callable[[], Any]) -> Any:
    barrier.wait(_HANG_S)
    return fn()


def _together(fn: Callable[[], Any], requesters: int) -> list[Any]:
    """``fn`` on ``requesters`` threads released by one barrier, in the same instant."""
    barrier = threading.Barrier(requesters)
    calls = [_Call(functools.partial(_released, barrier, fn)) for _ in range(requesters)]
    return [call.result() for call in calls]


def _leading(spy: PoolSpy, fn: Callable[[], Any]) -> _Call:
    """Start ``fn`` and wait until it is inside the worker call: the in-flight leader. A
    leader that ends without reaching the worker fails at once, not after ``_HANG_S``."""
    call = _Call(fn)
    deadline = time.monotonic() + _HANG_S
    while not spy.entered.wait(_POLL_S):
        assert call.running() or spy.entered.is_set(), "the leader ended before the worker"
        assert time.monotonic() < deadline, "the leader never reached the worker"
    return call


def _settled(fn: Callable[[], Any]) -> _Call:
    """Start ``fn`` and give it time to reach its wait on the in-flight leader."""
    call = _Call(fn)
    time.sleep(_SETTLE_S)
    return call


def _repeat(path: Path, rounds: int) -> list[FileModel | None]:
    return [get_model(path) for _ in range(rounds)]


def _requests(paths: list[Path], rounds: int) -> list[Any]:
    """Each path requested ``rounds`` times on its own thread; every answer, flattened."""
    calls = [_Call(functools.partial(_repeat, path, rounds)) for path in paths]
    return [model for call in calls for model in call.result()]


def _clear_until(stop: threading.Event) -> int:
    rounds = 0
    while not stop.is_set():
        ast_cache.clear()
        rounds += 1
        time.sleep(0)
    return rounds


# ── the key ──────────────────────────────────────────────────────────────────


def test_hit_is_the_same_object(tmp_path: Path, spy: PoolSpy) -> None:
    path = write(tmp_path / "a.js", _CLEAN_JS)

    first = get_model(path)
    second = get_model(path)

    assert isinstance(first, FileModel), first
    observed = (first.language, first.error_nodes, second is first, spy.languages())
    assert observed == ("javascript", 0, True, ["javascript"])


def test_hit_and_miss_are_tallied(tmp_path: Path, spy: PoolSpy) -> None:
    """§10.2 ``tallies.cache``: one miss for the parse, one hit for the reuse."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    before = _cache_tallies(tmp_path)

    get_model(path)
    get_model(path)

    assert _moved(before, _cache_tallies(tmp_path)) == {"misses": 1, "hits": 1}


def test_key_is_the_resolved_path(tmp_path: Path, spy: PoolSpy) -> None:
    """D5 keys on the RESOLVED path: every spelling of one file is one entry."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    (tmp_path / "sub").mkdir()
    link = tmp_path / "link.js"
    link.symlink_to(path)
    spellings = [path, str(path), tmp_path / "sub" / ".." / "a.js", link, Path(os.path.relpath(path))]

    models = list(map(get_model, spellings))

    assert isinstance(models[0], FileModel), models
    assert (_distinct(models), len(spy.calls)) == (1, 1), models


def test_same_size_new_mtime_reparses(tmp_path: Path, spy: PoolSpy) -> None:
    path = write(tmp_path / "a.js", _SIX_CLEAN)
    first = get_model(path)
    stat = path.stat()
    _rewrite(path, _SIX_BROKEN, stat.st_mtime_ns + 1_000_000_000)
    assert path.stat().st_size == stat.st_size
    # The next audit's start: it drops the path-keyed READ cache, so the new
    # bytes are read; the model is re-parsed because the key's mtime moved.
    clear_caches()

    second = get_model(path)

    assert isinstance(second, FileModel), second
    observed = (second is first, len(spy.calls), first.error_nodes, second.error_nodes > 0)
    assert observed == (False, 2, 0, True)


def test_new_size_same_mtime_reparses(tmp_path: Path, spy: PoolSpy) -> None:
    """Restoring the old mtime (``touch -r``) cannot keep a stale model: size is in the key."""
    path = write(tmp_path / "a.js", _SIX_CLEAN)
    first = get_model(path)
    stat = path.stat()
    grown = _SIX_CLEAN + "g(b);\n"
    _rewrite(path, grown, stat.st_mtime_ns)
    assert path.stat().st_mtime_ns == stat.st_mtime_ns
    clear_caches()

    second = get_model(path)

    assert isinstance(second, FileModel), second
    assert (second is first, len(spy.calls), second.size) == (False, 2, len(grown.encode("utf-8")))


def test_clear_caches_keeps_completed_models(tmp_path: Path, spy: PoolSpy) -> None:
    """D5 (binding over the plan's 1.5 bullet): ``file_scanner.clear_caches()``,
    run at every audit start, does not empty the model cache shared by the
    other concurrent audits; the key's size and mtime handle staleness."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    first = get_model(path)

    clear_caches()

    assert (get_model(path) is first, len(spy.calls)) == (True, 1)


def test_a_warm_read_cache_never_feeds_a_new_key(tmp_path: Path, spy: PoolSpy) -> None:
    """A9: a skill read the file earlier in this audit, then the file changed. The scanner's
    read cache is keyed by path alone, so it may still hold the old text; the model keyed by
    the new stat is built from the bytes that stat describes. No ``clear_caches()`` between."""
    path = write(tmp_path / "a.js", _SIX_CLEAN)
    read_file_safe(path)
    grown = _SIX_BROKEN + "g(b);\n"
    _rewrite(path, grown, path.stat().st_mtime_ns + 1_000_000_000)

    model = get_model(path)

    assert isinstance(model, FileModel), model
    observed = (spy.calls, model.size, model.error_nodes > 0, get_model(path) is model)
    assert observed == ([("javascript", grown.encode("utf-8"))], len(grown), True, True)


def test_a_file_changed_during_its_read_is_served_not_stored(
    tmp_path: Path, spy: PoolSpy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A9: the file is stat'ed again after the read. A change in between leaves the model
    served but not cached under the key of the stat seen before the read, so the next
    request parses the file as it is now."""
    path = write(tmp_path / "a.js", _SIX_CLEAN)
    read = ast_cache.read_file_uncached

    def read_then_rewrite(target: Path) -> str | None:
        text = read(target)
        monkeypatch.setattr(ast_cache, "read_file_uncached", read)
        _rewrite(path, _SIX_BROKEN, path.stat().st_mtime_ns + 1_000_000_000)
        return text

    monkeypatch.setattr(ast_cache, "read_file_uncached", read_then_rewrite)
    first = get_model(path)
    stored = _model_cache().bytes
    second = get_model(path)

    assert isinstance(first, FileModel) and isinstance(second, FileModel), (first, second)
    observed = (first.error_nodes, stored, second.error_nodes > 0, len(spy.calls))
    assert observed == (0, 0, True, 2)


def test_cache_clear_evicts_completed_models(tmp_path: Path, spy: PoolSpy) -> None:
    path = write(tmp_path / "a.js", _CLEAN_JS)
    first = get_model(path)

    ast_cache.clear()
    second = get_model(path)

    assert isinstance(second, FileModel), second
    assert (second is first, len(spy.calls)) == (False, 2)


# ── the byte budget ──────────────────────────────────────────────────────────


def test_budget_is_128mb_or_a_quarter_of_the_deployment_limit() -> None:
    assert _model_cache().budget == min(_MODEL_CACHE_CAP, deployment_memory_limit() // 4)


def test_eviction_keeps_bytes_within_budget(
    tmp_path: Path, spy: PoolSpy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Room for two models, three files: the least recently used goes first,
    only as many as needed, and ``bytes <= budget`` after every request."""
    cache = _model_cache()
    files = _write_same_shape(tmp_path, "abc")
    weight = _weight_of(spy, cache, files["a"])
    monkeypatch.setattr(cache, "budget", weight * 5 // 2)
    before = _cache_tallies(tmp_path)

    parses = [_parsed(spy, cache, files[tag]) for tag in _LRU_SEQUENCE]

    evictions = _moved(before, _cache_tallies(tmp_path)).get("evictions")
    assert (parses, evictions) == (_LRU_PARSES, 3)


def test_model_heavier_than_the_budget_is_served_not_stored(
    tmp_path: Path, spy: PoolSpy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Served: a model comes back and nothing is tallied as a fallback. Not
    stored: the next request parses again, and the cache stays empty."""
    cache = _model_cache()
    path = write(tmp_path / "a.js", _same_shape_js("a"))
    weight = _weight_of(spy, cache, path)
    ast_cache.clear()
    monkeypatch.setattr(cache, "budget", weight // 2)
    before = _fallback(tmp_path)

    parses = [_parsed(spy, cache, path), _parsed(spy, cache, path)]

    assert (parses, cache.bytes, _moved(before, _fallback(tmp_path))) == ([True, True], 0, {})


# ── single flight and clear() ────────────────────────────────────────────────


@pytest.mark.parametrize("requesters", [2, 8], ids=["two_skills", "eight_audits"])
def test_single_flight(tmp_path: Path, spy: PoolSpy, requesters: int) -> None:
    """Review focus 3: the same file requested in the same instant on a
    one-worker pool whose worker answers 200 ms late: one parse, one object."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.delay_s = _SLOW_PARSE_S

    models = _together(functools.partial(get_model, path), requesters)

    assert _all_models(models), models
    assert (len(spy.calls), _distinct(models)) == (1, 1), "(parses, distinct objects)"


def test_clear_during_an_inflight_leader_never_strands_a_waiter(
    tmp_path: Path, spy: PoolSpy
) -> None:
    """A co-tenant's ``clear()`` while a leader parses: ``clear()`` does not wait
    for the parse, the in-flight entry survives it (a later request joins the
    same leader), and every requester gets a model; at most one redundant parse."""
    request = functools.partial(get_model, write(tmp_path / "a.js", _CLEAN_JS))
    spy.close_gate()
    leader = _leading(spy, request)
    waiter = _settled(request)

    clearing = _Call(ast_cache.clear)
    assert clearing.done(_PROMPT_S), "clear() blocked behind an in-flight parse"
    late = _settled(request)
    parses_while_held = len(spy.calls)
    spy.gate.set()

    models = [leader.result(), waiter.result(), late.result()]
    assert (parses_while_held, _all_models(models)) == (1, True), models
    assert len(spy.calls) <= 2, f"{len(spy.calls)} parses: more than one redundant parse"


def test_an_inflight_parse_does_not_block_other_files(tmp_path: Path, spy: PoolSpy) -> None:
    """The in-flight marker is per key: the cache lock is not held across a parse."""
    slow = write(tmp_path / "slow.js", _CLEAN_JS)
    other = write(tmp_path / "other.js", _SIX_CLEAN)
    spy.close_gate(slow.read_bytes())
    leader = _leading(spy, functools.partial(get_model, slow))

    quick = _Call(functools.partial(get_model, other))

    assert quick.done(_PROMPT_S), "a request for another file waited for an unrelated parse"
    spy.gate.set()
    assert _all_models([quick.result(), leader.result()])


def test_a_failing_leader_releases_its_waiters(tmp_path: Path, spy: PoolSpy) -> None:
    """The leader's in-flight marker is released in a ``finally``: a leader whose
    parse raises returns ``None`` (``get_model`` never raises, §5) and tallies a
    fallback, and its waiter resolves (re-leading or falling back), never hangs."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.fail_first = True
    spy.close_gate()
    leader = _leading(spy, functools.partial(_measured, path, tmp_path))
    waiter = _settled(functools.partial(get_model, path))

    spy.gate.set()
    model, moved = leader.result()

    assert (model, sum(moved.values()) >= 1) == (None, True), f"None must tally: {moved}"
    assert isinstance(waiter.result(), FileModel | None)


def test_clear_storm_never_strands_a_request(tmp_path: Path, spy: PoolSpy) -> None:
    """``clear()`` in a tight loop against six requesters over three files: no
    hang, no exception, and every request gets a model (a ``None`` here would be
    a coverage loss no fallback bucket records, invariant 1)."""
    paths = list(_write_same_shape(tmp_path, "abc").values())
    stop = threading.Event()
    storm = _Call(functools.partial(_clear_until, stop))

    try:
        models = _requests(paths * 2, rounds=8)
    finally:
        stop.set()

    assert (storm.result() > 0, len(models), _all_models(models)) == (True, 48, True), models


# ── immutability ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["language", "grammar", "size", "error_nodes", "unmapped"])
def test_cached_model_is_frozen(tmp_path: Path, name: str) -> None:
    """Every public attribute of §5's ``FileModel``."""
    model = get_model(write(tmp_path / "a.js", _CLEAN_JS))
    assert isinstance(model, FileModel), model

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(model, name, 0)


def test_cached_model_takes_no_new_attribute(tmp_path: Path) -> None:
    """No audit can hang its own state on a shared model. A frozen dataclass
    raises ``FrozenInstanceError``; with ``slots=True`` (the §5 dataclass form)
    CPython 3.12 raises ``TypeError`` for a non-field name instead."""
    model = get_model(write(tmp_path / "a.js", _CLEAN_JS))
    assert isinstance(model, FileModel), model

    with pytest.raises((AttributeError, TypeError)):
        model.poison = 0  # type: ignore[attr-defined]


def test_cached_model_attribute_cannot_be_deleted(tmp_path: Path) -> None:
    model = get_model(write(tmp_path / "a.js", _CLEAN_JS))
    assert isinstance(model, FileModel), model

    with pytest.raises(dataclasses.FrozenInstanceError):
        del model.language


# ── declines and their tallies ───────────────────────────────────────────────


@pytest.mark.parametrize("name", ["cwe_22_18.rb", "show.erb", "Gemfile", "Program.cs", "Main.kt"])
def test_unsupported_language_is_none_and_tallied(
    tmp_path: Path, spy: PoolSpy, name: str
) -> None:
    """O1: Ruby (and every other language without a v1 profile, D17) is
    ``unsupported``; no worker is asked."""
    path = write(tmp_path / name, _RUBY)

    observed = (*_measured(path, tmp_path), owns(path), spy.calls)

    assert observed == (None, {"unsupported": 1}, None, [])


def test_unsupported_is_decided_before_size(tmp_path: Path, spy: PoolSpy) -> None:
    """``get_model`` = ``profile_for`` → read → …: an oversized Ruby file is
    ``unsupported``, never ``too_large``."""
    path = write(tmp_path / "big.rb", "#" * (max(limits.MAX_FILE_SIZE, READ_CAP) + 1))

    assert (*_measured(path, tmp_path), spy.calls) == (None, {"unsupported": 1}, [])


def test_go_has_a_v1_profile(tmp_path: Path, spy: PoolSpy) -> None:
    """O1's other half: the Go one-liner is AST-owned, so Go is not ``unsupported``."""
    model = get_model(write(tmp_path / "cwe_22_go_3.go", _GO))

    assert isinstance(model, FileModel), model
    assert (model.language, spy.languages()) == ("go", ["go"])


def test_too_large_is_none_and_tallied_before_the_worker(tmp_path: Path, spy: PoolSpy) -> None:
    """One byte over every size cap (the layer's and the reader's)."""
    path = write(tmp_path / "big.js", _js_of_size(max(limits.MAX_FILE_SIZE, READ_CAP) + 1))

    observed = (*_measured(path, tmp_path), owns(path), spy.calls)

    assert observed == (None, {"too_large": 1}, None, [])


def test_file_at_the_size_cap_is_parsed(tmp_path: Path, spy: PoolSpy) -> None:
    size = min(limits.MAX_FILE_SIZE, READ_CAP)
    path = write(tmp_path / "at_cap.js", _js_of_size(size))
    assert path.stat().st_size == size

    model, moved = _measured(path, tmp_path)

    assert (isinstance(model, FileModel), moved, len(spy.calls)) == (True, {}, 1)


@pytest.mark.parametrize("reason", get_args(FallbackReason))
def test_pool_fallback_is_none_and_tallied(tmp_path: Path, spy: PoolSpy, reason: str) -> None:
    """Each pool answer that is a ``FallbackReason`` lands in its own §10.2 bucket."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.answer = reason

    assert (*_measured(path, tmp_path), owns(path)) == (None, {reason: 1}, None)


_HOSTILE_DOCUMENTS: dict[str, dict[str, Any]] = {
    "empty": {},
    "unknown_kind": {"schema": 1, "kind": "evil"},
    "future_schema": {"schema": 999, "language": "javascript"},
    "pickle_in_text": {"schema": 1, "text": {"0": "cos\nsystem\n(S'id'\ntR."}},
}


@pytest.mark.parametrize("document", _HOSTILE_DOCUMENTS.values(), ids=_HOSTILE_DOCUMENTS.keys())
def test_document_the_validator_rejects_is_bad_model(
    tmp_path: Path, spy: PoolSpy, document: dict[str, Any]
) -> None:
    """The worker may be compromised (§11 T10): ``get_model`` validates what it
    gets back before building a model."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.answer = document

    assert _measured(path, tmp_path) == (None, {"bad_model": 1})


def test_a_document_for_other_bytes_is_refused(tmp_path: Path, spy: PoolSpy) -> None:
    """§11 T10: a well-formed document of OTHER bytes — what a compromised worker could
    send — is bound to the request it answers and refused: its size and rows are not those
    of the shipped file. ``get_model`` returns None and never raises."""
    other = get_pool().parse("javascript", b"f(a);\n" * 50)
    assert isinstance(other, dict), other
    path = write(tmp_path / "a.js", _SIX_CLEAN)
    spy.answer = other

    assert (get_model(path), _model_cache().bytes) == (None, 0)


def test_depth_bomb_is_too_deep_through_the_real_worker(tmp_path: Path) -> None:
    """§8.7 ``MAX_DEPTH``: twice the cap of nested unary operators, parsed by the
    real worker, comes back ``too_deep`` and is tallied by ``get_model``."""
    path = write(tmp_path / "bomb.js", "const deep =\n" + "!" * (2 * limits.MAX_DEPTH) + "x;\n")

    assert _measured(path, tmp_path) == (None, {"too_deep": 1})


def _missing(root: Path) -> Path:
    return root / "missing.js"


def _directory(root: Path) -> Path:
    directory = root / "dir.js"
    directory.mkdir()
    return directory


def _dangling_link(root: Path) -> Path:
    link = root / "dangling.js"
    link.symlink_to(root / "absent.js")
    return link


def _self_loop(root: Path) -> Path:
    link = root / "loop.js"
    link.symlink_to(link)
    return link


@pytest.mark.parametrize(
    "make", [_missing, _directory, _dangling_link, _self_loop], ids=lambda make: make.__name__.strip("_")
)
def test_unreadable_path_is_none_and_never_raises(
    tmp_path: Path, spy: PoolSpy, make: Callable[[Path], Path]
) -> None:
    path = make(tmp_path)

    assert (get_model(path), owns(path), spy.calls) == (None, None, [])


# ── owns ─────────────────────────────────────────────────────────────────────


def test_owns_is_the_cached_model_of_a_clean_file(tmp_path: Path, spy: PoolSpy) -> None:
    path = write(tmp_path / "a.js", _CLEAN_JS)

    owned = owns(path)

    assert isinstance(owned, FileModel), owned
    assert (owned is get_model(path), len(spy.calls)) == (True, 1)


def test_owns_declines_a_parse_error(tmp_path: Path, spy: PoolSpy) -> None:
    """§5: ``owns`` is ``get_model`` only when ``error_nodes == 0``; a model with
    an ERROR node is still built and cached, and the file is ``parse_error``."""
    path = write(tmp_path / "bad.js", _BROKEN_JS)
    before = _fallback(tmp_path)

    owned = owns(path)
    moved = _moved(before, _fallback(tmp_path))
    model = get_model(path)

    assert isinstance(model, FileModel), model
    observed = (owned, moved, model.error_nodes > 0, len(spy.calls))
    assert observed == (None, {"parse_error": 1}, True, 1)


# ── what reaches the worker ──────────────────────────────────────────────────


def test_ships_the_decoded_text_encoded_once(tmp_path: Path, spy: PoolSpy) -> None:
    """§4 / T5: the parent reads through ``read_file_safe`` (size cap,
    ``errors="replace"``, newline handling) and ships that text as UTF-8; the
    model's spans index the same buffer."""
    path = write(tmp_path / "hostile.js", _HOSTILE_BYTES)

    model = get_model(path)

    shipped = (read_file_safe(path) or "").encode("utf-8")
    assert isinstance(model, FileModel), model
    observed = (shipped != _HOSTILE_BYTES, spy.calls, model.size)
    assert observed == (True, [("javascript", shipped)], len(shipped))


# ── the key carries the grammar (A14); negative outcomes are per audit (A18) ──
#
# A14 (Phase-1 close-out): the key is ``(resolved path, size, mtime_ns,
# GRAMMAR_PACK_VERSION, MODEL_SCHEMA, language, grammar entry point)``, so one file
# reached under two grammars is two entries. A18: a refused or failed parse is recorded
# in the audit's ``declined`` map under that key and never enters this cache; the same
# key again in the same audit is None with NO pool call, NO second breaker fault and NO
# second fallback tally, and the next audit (a new ``context.enter``, or
# ``context.reset_default()``) asks the pool again.

# The unbound ``WorkerPool.parse`` as defined, before any test patches it.
_REAL_PARSE = WorkerPool.parse
# TypeScript that parses clean under both of its grammar entry points.
_TS = "const limit: number = 10;\nf(limit);\n"
# A18's refused or failed parses, as the pool answers them; ``bad_model`` as the boundary
# validator decides it, from a document it rejects.
_DECLINED_ANSWERS: dict[str, Any] = {
    "too_deep": "too_deep",
    "ir_too_large": "ir_too_large",
    "worker_error": "worker_error",
    "timeout": "timeout",
    "worker_crashed": "worker_crashed",
    "bad_model": {},
}
# The two faults the breaker counts (D10), each made by a real hook worker (its argv).
_FAULT_HOOKS = {"timeout": ("hang.py",), "worker_crashed": CRASH_HOOK}


def _entry_point(model: FileModel) -> str:
    """``<module>.<entry point>`` of a model's grammar stamp (``...@<version>``)."""
    return model.grammar.split("@")[0]


def _on_pool(
    target: WorkerPool, _asked: WorkerPool, language: str, data: bytes, grammar: str | None
) -> Any:
    return _REAL_PARSE(target, language, data, grammar)


def _route(spy: PoolSpy, pool: WorkerPool) -> None:
    """From now on every parse the spy records is answered by ``pool`` (a hook worker's)."""
    spy.real = functools.partial(_on_pool, pool)


def test_key_carries_language_and_entry_point(tmp_path: Path, spy: PoolSpy) -> None:
    """A14: a ``.tsx`` symlink to a ``.ts`` file is parsed under ``language_tsx`` and the
    file's own name under ``language_typescript``: two keys, two pool calls, two models with
    different grammar stamps, and each name hits its own entry afterwards."""
    ts = write(tmp_path / "view.ts", _TS)
    tsx = tmp_path / "view.tsx"
    tsx.symlink_to(ts)

    models = list(map(get_model, (ts, tsx, ts, tsx)))

    assert _all_models(models), models
    stamps = list(map(_entry_point, models[:2]))
    observed = (len(spy.calls), _distinct(models), models[2] is models[0], models[3] is models[1])
    assert (observed, stamps) == (
        (2, 2, True, True),
        [".".join(GRAMMARS["typescript"]), ".".join(TSX_GRAMMAR)],
    )


def _declined_after(path: Path) -> dict[Any, Any]:
    get_model(path)
    return dict(current_context().declined)


def test_a_declined_parse_is_recorded_under_the_model_cache_key(
    tmp_path: Path, spy: PoolSpy
) -> None:
    """A18 with A14: the audit's ``declined`` map holds a refused parse under D5's key —
    resolved path, size, mtime_ns, the two stamps, the language and the grammar entry
    point — with its reason."""
    path = write(tmp_path / "view.tsx", _TS)
    spy.answer = "too_deep"

    declined = in_audit(tmp_path, _declined_after, path)

    key = model_cache_key(path, "typescript", TSX_GRAMMAR[1])
    assert declined == {key: "too_deep"}


@pytest.mark.parametrize("reason", _DECLINED_ANSWERS)
def test_a_declined_key_is_not_reparsed_in_the_same_audit(
    tmp_path: Path, spy: PoolSpy, reason: str
) -> None:
    """A18, per reason: after the first refusal, a second ``get_model`` and an ``owns`` of
    the key return None with no pool call, and the file is tallied once."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.answer = _DECLINED_ANSWERS[reason]
    before = _fallback(tmp_path)

    answers = (get_model(path), get_model(path), owns(path))

    observed = (answers, len(spy.calls), _moved(before, _fallback(tmp_path)))
    assert observed == ((None, None, None), 1, {reason: 1})


def test_memoised_reasons_are_exactly_the_six_ruled() -> None:
    """A31 (5): the A18 cases above cover exactly the six memoised reasons."""
    assert set(_DECLINED_ANSWERS) == {
        "too_deep", "ir_too_large", "bad_model", "worker_error", "timeout", "worker_crashed",
    }


def _spawn_failed_thrice(root: Path, path: Path) -> tuple[Any, dict[str, int], dict[Any, Any]]:
    before = _fallback(root)
    answers = (get_model(path), get_model(path), owns(path))
    return answers, _moved(before, _fallback(root)), dict(current_context().declined)


def test_spawn_failed_is_not_memoised(tmp_path: Path, spy: PoolSpy) -> None:
    """A31 (5): ``spawn_failed`` is a breaker fault, not a property of the file, so it is not
    memoised: a second ``get_model`` and an ``owns`` ask the pool again, the audit's
    ``declined`` map stays empty, and the path is still tallied once (A8)."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.answer = "spawn_failed"

    observed = in_audit(tmp_path, _spawn_failed_thrice, tmp_path, path)

    assert (observed, len(spy.calls)) == (((None, None, None), {"spawn_failed": 1}, {}), 3)


def _declined_fault(spy: PoolSpy, root: Path, hook: list[str]) -> dict[str, Any]:
    """Three ``owns`` of one file answered by ``hook``, then the crashes the audit's breaker
    still takes before it opens."""
    path = write(root / "a.js", _CLEAN_JS)
    _route(spy, WorkerPool(cmd=hook))
    before = _fallback(root)
    answers = [owns(path) for _ in range(3)]
    tallied = _moved(before, _fallback(root))
    seen = {"answers": answers, "parses": len(spy.calls), "tallied": tallied}
    crashing = WorkerPool(cmd=hook_command(*CRASH_HOOK))
    _route(spy, crashing)
    return {**seen, "faults_left": faults_until_open(crashing)}


@pytest.mark.parametrize("reason", _FAULT_HOOKS)
def test_a_declined_fault_counts_once_on_the_breaker(
    tmp_path: Path, spy: PoolSpy, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    """A18 / D10 through real hook workers — a hang the wall timeout ends, a crash: three
    ``owns`` of the file make one pool call, one fallback tally and ONE breaker fault, so
    the audit's breaker then takes ``CIRCUIT_BREAK_AFTER - 1`` more crashes to open."""
    wall_timeout(monkeypatch, TRIP_S)

    observed = in_audit(tmp_path, _declined_fault, spy, tmp_path, hook_command(*_FAULT_HOOKS[reason]))

    assert observed == {
        "answers": [None, None, None],
        "parses": 1,
        "tallied": {reason: 1},
        "faults_left": ["worker_crashed"] * (limits.CIRCUIT_BREAK_AFTER - 1),
    }


def _in_a_new_audit(path: Path, rounds: int) -> list[FileModel | None]:
    return in_audit(path.parent, _repeat, path, rounds)


def _after_reset_default(path: Path, rounds: int) -> list[FileModel | None]:
    context_mod().reset_default()
    return _repeat(path, rounds)


def test_the_next_audit_retries_a_declined_key(tmp_path: Path, spy: PoolSpy) -> None:
    """A18: nothing negative enters the cross-audit cache. A new ``context.enter`` and
    ``context.reset_default()`` each start an audit that asks the pool again, once, while
    the audit that declined the key still does not; the cache holds no entry for it."""
    path = write(tmp_path / "a.js", _CLEAN_JS)
    spy.answer = "timeout"
    parses: list[int] = []

    for step in (_repeat, _in_a_new_audit, _repeat, _after_reset_default):
        step(path, 2)
        parses.append(len(spy.calls))

    assert (parses, _model_cache().bytes) == ([1, 2, 2, 3], 0)


# ── an analysis is charged to its model's entry (A35) ────────────────────────
#
# A35 (2026-10-17): a model's cache charge covers its analysis. When ``model.analysis()`` is
# first built, its footprint — ``analysis.bytes_estimate``, computed once at build — is added
# to that model's cache entry, and the cache evicts least-recently-used entries to stay within
# ``model_cache_budget``. A model served but not stored keeps its analysis only for its own
# lifetime: nothing in the accounting moves. The estimate's band against ``tracemalloc`` is
# ``test_0102_bytes_estimate.py``'s.


def _analysed(cache: Any, model: FileModel | None) -> int:
    """Build ``model``'s analysis; the accounted bytes after it, which the budget holds."""
    assert isinstance(model, FileModel), model
    model.analysis()
    assert cache.bytes <= cache.budget, (cache.bytes, cache.budget)
    return cache.bytes


def _asked(analysis: Any) -> None:
    """``analysis`` asked every family's candidates, as a consumer asks them."""
    for family in FAMILIES:
        analysis.candidates(family)


def test_an_analysis_is_charged_to_its_model_once(tmp_path: Path) -> None:
    """A35: building a stored model's analysis adds ``analysis.bytes_estimate`` to the
    accounted bytes (beside another stored model, so the growth is that model's entry), and
    asking for the analysis again, or asking it every family's candidates, charges nothing
    more: the estimate is computed once, at build."""
    cache = _model_cache()
    files = _write_same_shape(tmp_path, "ab")
    get_model(files["a"])
    model = get_model(files["b"])
    assert isinstance(model, FileModel), model
    before = cache.bytes

    analysis = model.analysis()
    charged = cache.bytes - before
    _asked(analysis)

    assert charged > 0, "A35: building the analysis charged nothing to its model's entry"
    observed = (cache.bytes - before, model.analysis() is analysis, analysis.bytes_estimate)
    assert observed == (charged, True, charged)


def test_an_analysis_charge_evicts_the_least_recently_used_entry(
    tmp_path: Path, spy: PoolSpy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A35: room for one model with its analysis and one bare model, not for two analysed
    models. Building b's analysis evicts a's entry — the least recently used, its model and
    its analysis — so ``bytes <= budget`` after every step, a parses again and b's entry is
    kept; the accounted bytes are then the two models and b's analysis, exactly."""
    cache = _model_cache()
    files = _write_same_shape(tmp_path, "ab")
    bare = _weight_of(spy, cache, files["a"])
    full = _analysed(cache, get_model(files["a"]))
    monkeypatch.setattr(cache, "budget", full + bare + (full - bare) // 2)

    stored_b = _parsed(spy, cache, files["b"])  # a with its analysis, then b
    b = get_model(files["b"])
    _analysed(cache, b)  # b with its analysis: a's entry evicted
    reparsed_a = _parsed(spy, cache, files["a"])  # b with its analysis, then a
    kept_b = get_model(files["b"]) is b

    assert (stored_b, reparsed_a, kept_b) == (True, True, True), (
        "A35: building an analysis evicted no least-recently-used entry"
    )
    assert cache.bytes == 2 * bare + b.analysis().bytes_estimate


def _heavier_than_the_budget(
    root: Path, _spy: PoolSpy, cache: Any, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """The budget shrinks to what the cache holds, so a heavier model is served, never
    stored (D5)."""
    monkeypatch.setattr(cache, "budget", cache.bytes)
    return write(root / "heavy.js", _same_shape_js("h") * 3)


def _rewritten_first(path: Path, parse: Callable[..., Any], *args: Any) -> Any:
    """``parse(*args)`` once ``path`` was rewritten: the file changes between its read and the
    re-stat that follows the parse (A9)."""
    _rewrite(path, _SIX_BROKEN, path.stat().st_mtime_ns + 1_000_000_000)
    return parse(*args)


def _changed_during_its_read(
    root: Path, spy: PoolSpy, _cache: Any, _monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Every parse the spy sees is preceded by a rewrite of the file, so its model is served
    and never stored (A9)."""
    path = write(root / "changed.js", _SIX_CLEAN)
    spy.real = functools.partial(_rewritten_first, path, spy.real)
    return path


@pytest.mark.parametrize(
    "serve",
    [_heavier_than_the_budget, _changed_during_its_read],
    ids=lambda serve: serve.__name__.strip("_"),
)
def test_a_served_not_stored_models_analysis_is_not_charged(
    tmp_path: Path,
    spy: PoolSpy,
    monkeypatch: pytest.MonkeyPatch,
    serve: Callable[[Path, PoolSpy, Any, pytest.MonkeyPatch], Path],
) -> None:
    """A35: a model served but not stored keeps its analysis for its own lifetime. The
    analysis carries its estimate, yet building it moves no accounted byte and evicts
    nothing, and the model is still not stored (the next request parses again)."""
    cache = _model_cache()
    kept_path = write(tmp_path / "kept.js", _same_shape_js("k"))
    kept = get_model(kept_path)
    path = serve(tmp_path, spy, cache, monkeypatch)
    served = get_model(path)
    assert isinstance(served, FileModel), served
    before = cache.bytes

    analysis = served.analysis()

    stored = (cache.bytes - before, get_model(kept_path) is kept, _parsed(spy, cache, path))
    assert (analysis.bytes_estimate > 0, *stored) == (True, 0, True, True)
