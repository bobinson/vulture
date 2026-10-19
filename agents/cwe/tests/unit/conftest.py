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


@pytest.fixture
def regex_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    """Feature 0102 (A43 (2)): the AST head answers every rule on every file as for a file the
    AST tier falls back on (``_ast_head._answer``, the one point ``ast_answers`` and
    ``ast_spans`` reach), so each dispatcher runs its renamed regex body
    (``_check_command_regex``, ``_check_ssrf_regex``, ``_check_path_traversal_regex``) on every
    line - the tier that still owns each file the AST tier does not parse (D10). A pre-0102
    test whose pinned behaviour the AST tier replaced on parsed files keeps pinning the regex
    tier through this fixture, its inputs and assertions unchanged; what the AST tier does on
    the same input is pinned in ``test_0102_regex_pinned_counterparts.py``. A test seam, not a
    flag."""
    from cwe_agent.skills import _ast_head

    def fallback(*_args: object) -> _ast_head.AstAnswer:
        return _ast_head.FALLBACK

    monkeypatch.setattr(_ast_head, "_answer", fallback)
