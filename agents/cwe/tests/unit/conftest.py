"""Shared CWE unit-test fixtures.

``corpus_runner`` and ``promote_signatures`` are put on ``sys.path`` by
``tests/conftest.py``, one level up, for the unit and e2e suites alike.
"""
import pytest


@pytest.fixture(autouse=True)
def reset_catalog_caches():
    """Reset lru_cache singletons so tests don't see stale state across runs.

    Both _build_keyword_index (catalog_detector) and _parent_children_index
    (catalog) use @lru_cache(maxsize=1); cache_clear resets them.
    """
    from cwe_agent.catalog import _parent_children_index
    from cwe_agent.skills.catalog_detector import _build_keyword_index
    _build_keyword_index.cache_clear()
    _parent_children_index.cache_clear()
    yield
