"""One implementation of the shared suite's environment and cache isolation.

``tests/conftest.py`` applies it to every test; a module- or class-scoped
fixture that runs a pipeline once (before any function-scoped autouse fixture
exists) calls it with its own ``pytest.MonkeyPatch`` so the shared run sees the
same documented defaults a single test would.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Not VULTURE_-prefixed, but read at import time into ``_CUSTOM_BASE_URL`` and
# at call time by the LLM client: a developer's gateway must not decide a test.
_EXTRA_NAMES = ("OPENAI_BASE_URL",)


def isolate(monkeypatch: Any, cache_dir: Path) -> None:
    """Documented defaults, no custom endpoint, a private empty L5 cache
    (``cache_dir/.vulture/l5_cache.db``)."""
    from shared import audit_runner
    from shared.llm import provider
    from shared.validate import l5_cache

    for name in [n for n in os.environ if n.startswith("VULTURE_")] + list(_EXTRA_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    # The cache's documented default is ``~/.vulture/l5_cache.db``; HOME moves
    # it under ``cache_dir`` without adding a VULTURE_* name to the test's env,
    # and a test that sets VULTURE_L5_CACHE_PATH itself still wins.
    monkeypatch.setenv("HOME", str(cache_dir))
    monkeypatch.setattr(l5_cache, "_CONN", None)
    monkeypatch.setattr(l5_cache, "_DB_PATH", None)
    monkeypatch.setattr(l5_cache, "_DISABLED", False)
