"""Fixtures shared by the feature 0102 ``tests/unit/ast`` modules.

``shared.ast`` is imported inside the fixture, never at the top: this conftest loads before
every module of the package, ``test_0102_imports.py`` included, and a top-level import would
fail the collection of modules that do not need the layer.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(scope="module")
def real_pool() -> Iterator[None]:
    """One audit on one real-worker pool for a whole module: W = 1 (the compose shape, §4), a
    fresh process-default context and pool on entry, none left behind. Workers are spawned
    once per module, not per test; a test that needs a fresh worker resets the pool itself."""
    from tests.unit.ast._support import one_audit

    with pytest.MonkeyPatch.context() as patch, one_audit(patch):
        yield
