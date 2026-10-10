"""One implementation of the shared suite's environment and cache isolation.

``tests/conftest.py`` applies it to every test; a module- or class-scoped
fixture that runs a pipeline once (before any function-scoped autouse fixture
exists) calls it with its own ``pytest.MonkeyPatch`` so the shared run sees the
same documented defaults a single test would.
"""

from __future__ import annotations

import os
import site
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
    from shared.llm.cooldown import cooldown_manager
    from shared.validate import l5_cache

    for name in [n for n in os.environ if n.startswith("VULTURE_")] + list(_EXTRA_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    # The cache's documented default is ``~/.vulture/l5_cache.db``; HOME moves
    # it under ``cache_dir`` without adding a VULTURE_* name to the test's env,
    # and a test that sets VULTURE_L5_CACHE_PATH itself still wins.
    #
    # Python derives the USER SITE from HOME as well, so moving HOME alone hid
    # every `pip install --user` package from a test's subprocess (the agent-log
    # and USE_LLM token subprocess tests failed with ModuleNotFoundError when the
    # deps lived there). PYTHONUSERBASE pins the ORIGINAL user base for children;
    # `site.getuserbase()` is read before HOME moves and is cached per process.
    monkeypatch.setenv("PYTHONUSERBASE", site.getuserbase())
    monkeypatch.setenv("HOME", str(cache_dir))
    monkeypatch.setattr(l5_cache, "_CONN", None)
    monkeypatch.setattr(l5_cache, "_DB_PATH", None)
    monkeypatch.setattr(l5_cache, "_DISABLED", False)
    # Process-global model cooldowns. A test that drives the LLM tier into
    # failures leaves its model in cooldown, and every later test asking for that
    # model is silently served the fallback chain's next model instead (for
    # `gpt-4o`, an Anthropic one, which moves the batch source into the system
    # turn). No test may start with another test's cooldowns.
    cooldown_manager.reset()
