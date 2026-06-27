"""Shared CWE unit-test fixtures."""
import sys
from pathlib import Path

import pytest

# Feature 0057 Phase 5 — make the corpus runner (tests/corpus/corpus_runner.py)
# and the promotion script (scripts/promote_signatures.py) importable by their
# bare module names from the corpus/promotion tests (T16-T21). The modules are
# implemented by the harness author in a later step; until then the corpus tests
# RED with "No module named corpus_runner" / "promote_signatures", which is the
# intended TDD failure. These dirs are not packages, so they are added to
# sys.path rather than imported as packages.
_AGENT_ROOT = Path(__file__).resolve().parents[2]  # agents/cwe/
for _p in (_AGENT_ROOT / "tests" / "corpus", _AGENT_ROOT / "scripts"):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)


@pytest.fixture(autouse=True)
def reset_catalog_caches():
    """Reset lru_cache singletons so tests don't see stale state across runs.

    Both _build_keyword_index (catalog_detector) and _parent_children_index
    (catalog) use @lru_cache(maxsize=1); cache_clear resets them.
    """
    from cwe_agent.skills.catalog_detector import _build_keyword_index
    from cwe_agent.catalog import _parent_children_index
    _build_keyword_index.cache_clear()
    _parent_children_index.cache_clear()
    yield
