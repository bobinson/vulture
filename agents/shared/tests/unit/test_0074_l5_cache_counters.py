"""Feature 0074 T5.4 — per-RUN L5 cache hit / miss / store counters.

Whether the L5 verdict cache is doing anything was unobservable: a run that
re-judged every finding and a run that replayed every verdict logged the same.
Each validate run now counts its own lookups and stores and emits ONE line,
``l5_cache run_id=%s hits=%d misses=%d stores=%d``. The counters are
run-scoped: eight audit generators share one interpreter, so two concurrent
runs must never see each other's counts.
"""

from __future__ import annotations

import logging
import threading

from shared.validate import l5_cache

_VERDICT = {"exploitable": 0.2, "reasoning": "guarded", "model": "m", "language": "py"}


def _lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("l5_cache run_id=")]


def test_miss_then_store_then_hit_in_one_run(caplog) -> None:
    key = l5_cache.cache_key(file_path="a.py", line_start=3, line_end=3,
                             check_id="c", model="m")
    with caplog.at_level(logging.INFO, logger=l5_cache.__name__):
        with l5_cache.counting("run-1") as counts:
            assert l5_cache.lookup(key) is None
            l5_cache.store(key, **_VERDICT)
            assert l5_cache.lookup(key) is not None
    assert (counts.hits, counts.misses, counts.stores) == (1, 1, 1)
    assert _lines(caplog) == ["l5_cache run_id=run-1 hits=1 misses=1 stores=1"]


def test_lookups_outside_a_run_count_nowhere(caplog) -> None:
    key = l5_cache.cache_key(file_path="b.py", line_start=1, line_end=1,
                             check_id="c", model="m")
    with caplog.at_level(logging.INFO, logger=l5_cache.__name__):
        assert l5_cache.lookup(key) is None
        l5_cache.store(key, **_VERDICT)
    assert _lines(caplog) == []


def test_concurrent_runs_keep_separate_counts(caplog) -> None:
    """Two runs interleaved on two threads: each counts only its own calls."""
    barrier = threading.Barrier(2)
    results: dict[str, tuple[int, int, int]] = {}

    def run(run_id: str, misses: int) -> None:
        with l5_cache.counting(run_id) as counts:
            barrier.wait()
            for i in range(misses):
                l5_cache.lookup(f"{run_id}-{i}")
            barrier.wait()
        results[run_id] = (counts.hits, counts.misses, counts.stores)

    with caplog.at_level(logging.INFO, logger=l5_cache.__name__):
        threads = [threading.Thread(target=run, args=("run-a", 2)),
                   threading.Thread(target=run, args=("run-b", 5))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert results == {"run-a": (0, 2, 0), "run-b": (0, 5, 0)}
    assert sorted(_lines(caplog)) == [
        "l5_cache run_id=run-a hits=0 misses=2 stores=0",
        "l5_cache run_id=run-b hits=0 misses=5 stores=0",
    ]


def test_pool_workers_count_into_their_run() -> None:
    """The L5 pool submits through ``contextvars.copy_context()``; a worker
    thread's lookups must land in the run that dispatched it."""
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    with l5_cache.counting("run-pool") as counts:
        with ThreadPoolExecutor(max_workers=3) as pool:
            for i in range(6):
                pool.submit(contextvars.copy_context().run, l5_cache.lookup, f"k{i}")
    assert (counts.hits, counts.misses, counts.stores) == (0, 6, 0)


def test_validate_emits_one_line_per_run(caplog) -> None:
    """One ``l5_cache`` line per validate run, carrying the run's id."""
    from shared.validate import validate

    rows = [{"title": "t", "severity": "low", "category": "CWE-79",
             "file_path": "x.py", "line_start": 1, "provenance": "skill"}]
    with caplog.at_level(logging.INFO, logger=l5_cache.__name__):
        validate(rows, "", audit_id="run-v")
    assert _lines(caplog) == ["l5_cache run_id=run-v hits=0 misses=0 stores=0"]
