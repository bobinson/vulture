"""A per-test quote store for tests that drive the lineage evidence ladder.

The ladder (``shared.lineage_checks``) reads stored evidence quotes through
``shared.quote_store``, whose connection lives in the L5 cache database at
``VULTURE_L5_CACHE_PATH``. A test that stores or reads a quote points that path
at its own ``tmp_path`` and drops the shared connection on both sides, so no
quote leaks between tests or into the developer's real cache.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from shared import quote_store

if TYPE_CHECKING:
    import pytest


def local_quote_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Fixture body: ``yield from local_quote_store(monkeypatch, tmp_path)``."""
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "cache" / "l5_cache.db"))
    quote_store.reset_for_tests()
    yield
    quote_store.reset_for_tests()
