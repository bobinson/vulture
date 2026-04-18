"""Shared ASVS unit-test fixtures."""
import pytest


@pytest.fixture(autouse=True)
def reset_catalog_caches():
    """Reset lru_cache singletons so tests don't see stale state across runs."""
    from asvs_agent.catalog import load_catalog
    load_catalog.cache_clear()
    try:
        from asvs_agent.skills.asvs_requirements_check import _keyword_fallback_index
        _keyword_fallback_index.cache_clear()
    except (ImportError, AttributeError):
        pass
    yield
