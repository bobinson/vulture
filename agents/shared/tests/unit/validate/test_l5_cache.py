"""L5 verdict cache (l5_cache.py) — concurrency regression.

The L5 judge runs batches on a ThreadPoolExecutor (concurrency=5), so the
module-level SQLite connection is used by several threads at once. With an
UNSYNCHRONIZED shared connection, concurrent execute() raises SQLITE_MISUSE
("bad parameter or other API misuse"); the error is swallowed and the
write/read is silently dropped, so concurrently-stored verdicts become
unretrievable and the cache never actually caches. lookup()/store() must
serialize access to the shared connection.

(conftest._isolate_l5_cache points the cache at a fresh per-test file and
resets the module globals, so these tests are hermetic.)
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from shared.validate import l5_cache


def _key(i: int) -> str:
    return l5_cache.cache_key(
        file_path=f"f{i}.py", line_start=i, line_end=i, check_id="cwe.x", model="m"
    )


def test_store_lookup_roundtrip_single_thread():
    k = _key(1)
    assert l5_cache.lookup(k) is None
    l5_cache.store(k, exploitable=0.7, reasoning="reaches sink", model="m", language="py")
    got = l5_cache.lookup(k)
    assert got is not None
    assert got["exploitable"] == 0.7
    assert got["reasoning"] == "reaches sink"


def test_concurrent_store_then_lookup_loses_nothing():
    # Each task stores a verdict then immediately reads it back. With the
    # unsynchronized shared connection, concurrent execute() collisions drop
    # writes/reads -> some lookups miss. Serialized access -> zero misses.
    n = 240
    keys = [_key(i) for i in range(n)]

    def work(i: int):
        l5_cache.store(keys[i], exploitable=0.5, reasoning="r", model="m", language="py")
        return l5_cache.lookup(keys[i])

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(work, range(n)))

    misses = [i for i, r in enumerate(results) if r is None]
    assert not misses, f"{len(misses)}/{n} cache ops lost to concurrency (SQLITE_MISUSE)"
