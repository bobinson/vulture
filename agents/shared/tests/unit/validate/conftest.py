"""Per-test isolation for the validate package tests.

Feature 0046's L5 LLM judge maintains a SQLite-backed verdict cache
at `~/.vulture/l5_cache.db` so re-audits of unchanged code skip the
LLM call. That same cache must NOT bleed between unit tests — a
verdict stored during one test would short-circuit the LLM mock in
the next.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_l5_cache(tmp_path, monkeypatch):
    """Point the L5 cache at a fresh per-test SQLite file."""
    cache_file = tmp_path / "l5_cache.db"
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(cache_file))
    # Reset the module-level connection so the new env var is picked up.
    from shared.validate import l5_cache
    monkeypatch.setattr(l5_cache, "_CONN", None)
    monkeypatch.setattr(l5_cache, "_DB_PATH", None)
    monkeypatch.setattr(l5_cache, "_DISABLED", False)
    yield
