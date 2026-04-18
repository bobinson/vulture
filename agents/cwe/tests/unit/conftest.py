"""Shared CWE unit-test fixtures."""
import pytest


@pytest.fixture(autouse=True)
def reset_catalog_caches():
    """Reset module-level caches so tests don't see stale state from earlier
    tests in the same pytest run. Two caches matter:
      - catalog_detector._KEYWORD_INDEX_CACHE (manual singleton)
      - catalog._parent_children_index (lru_cache, added in Task 2)
    """
    from cwe_agent.skills import catalog_detector as cd
    cd._KEYWORD_INDEX_CACHE = None
    try:
        from cwe_agent.catalog import _parent_children_index
        _parent_children_index.cache_clear()
    except ImportError:
        pass
    yield
