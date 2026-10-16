"""Feature 0074 — the run-scoped body-truncation counter behind ``llm_sweep``.

Every request body the generate path cuts goes through ONE choke point,
``_enforce_body_byte_cap`` (the pre-send byte cap, labelled ``batch`` /
``build_source_context``, and the halving after a provider size rejection,
labelled ``size_retry``). The sweep's ``body_truncations`` reads a counter
incremented there rather than predicting cuts from batch sizes.

The counter is run-scoped, like ``l5_cache.counting``: one interpreter drives
several audit generators, each in its own context, so two runs must never see
each other's cuts; a batch call runs in an asyncio task and the L5/skill pools
submit through ``contextvars.copy_context()``, so work in a copied context
counts into the run that started it; outside a run nothing is counted.

Contract under test: ``shared.audit_runner.count_body_truncations()`` is a
context manager yielding an object whose ``count`` is the number of bodies cut
inside it.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
from concurrent.futures import ThreadPoolExecutor

from shared import audit_runner
from shared.audit_runner import _enforce_body_byte_cap, _halve_source_context

_CAP = 400


def _body(files: int = 6, lines: int = 12) -> str:
    """An inlined-source body in the batch format: whole file blocks."""
    return "\n\n".join(
        f"--- src/f{i}.py ---\n" + "\n".join(f"v{i}_{j} = {j}" for j in range(lines))
        for i in range(files)
    )


def _cut() -> None:
    out = _enforce_body_byte_cap(_body(), max_bytes=_CAP, label="batch")
    assert len(out.encode("utf-8")) <= _CAP


def test_counts_every_cut_inside_a_run() -> None:
    with audit_runner.count_body_truncations() as counter:
        _cut()
        assert _halve_source_context(_body(files=12, lines=20)), "halving must cut"
        # Under the cap: returned unchanged, not a truncation.
        assert _enforce_body_byte_cap("x = 1\n", max_bytes=_CAP, label="batch") == "x = 1\n"
        # Cap disabled / empty text: nothing cut.
        assert _enforce_body_byte_cap("", max_bytes=_CAP, label="batch") == ""
    assert counter.count == 2


def test_cuts_outside_a_run_count_nowhere() -> None:
    _cut()  # must not raise with no run in scope
    with audit_runner.count_body_truncations() as counter:
        pass
    assert counter.count == 0


def test_count_is_frozen_when_the_run_ends() -> None:
    with audit_runner.count_body_truncations() as counter:
        _cut()
    _cut()
    assert counter.count == 1


def test_concurrent_runs_keep_separate_counts() -> None:
    """Two runs interleaved on two threads, each in its own context."""
    barrier = threading.Barrier(2)
    results: dict[str, int] = {}

    def run(run_id: str, cuts: int) -> None:
        with audit_runner.count_body_truncations() as counter:
            barrier.wait()
            for _ in range(cuts):
                _cut()
            barrier.wait()
        results[run_id] = counter.count

    threads = [
        threading.Thread(target=contextvars.copy_context().run, args=(run, "run-a", 1)),
        threading.Thread(target=contextvars.copy_context().run, args=(run, "run-b", 3)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == {"run-a": 1, "run-b": 3}


def test_pool_workers_count_into_their_run() -> None:
    """A worker thread running in a copied context counts into the run."""
    with audit_runner.count_body_truncations() as counter:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(contextvars.copy_context().run, _cut) for _ in range(5)]
            for f in futures:
                f.result()
    assert counter.count == 5


def test_asyncio_tasks_count_into_their_run() -> None:
    """The sweep sends each batch through ``asyncio.wait_for`` — a task with a
    COPY of the context. A cut inside it must reach the run's counter."""

    async def batch() -> None:
        _cut()

    async def sweep() -> None:
        for _ in range(3):
            await asyncio.wait_for(batch(), timeout=5)

    with audit_runner.count_body_truncations() as counter:
        asyncio.run(sweep())
    assert counter.count == 3

