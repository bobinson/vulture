"""Environment and cache isolation for the shared unit suite (and, by import,
the e2e suite: ``tests/e2e/conftest.py`` re-exports this one fixture).

Importing ``litellm`` runs ``dotenv.load_dotenv()`` at module import time
(``litellm/__init__.py``). Because the virtualenv lives INSIDE the repository,
``find_dotenv`` walks up from ``site-packages`` and reaches the developer's
top-level ``.env`` — so a real config file is injected into ``os.environ``
during COLLECTION, before any test runs, no matter what directory pytest was
invoked from or which worktree the code is checked out in.

That turns a developer convenience into a test-ordering bug. ``.env`` here
carries ``VULTURE_OBLIGATION_MODE=enforce``; the L5 promotion gate reads it, so
``_verdict_to_check`` labelled a promoting verdict ``JUDGE_UNCITED`` instead of
``JUDGE_CITED``. The failure mode is deceptive in three ways:

  * it depends on whether a ``.env`` happens to exist on the machine, so CI and
    a laptop disagree about the same commit;
  * ``pytest tests/unit/validate`` PASSES (nothing there imports litellm) while
    ``pytest tests/unit`` fails, which reads like an ordering problem inside the
    validate package rather than an import side effect outside it;
  * ``monkeypatch`` then snapshots ``enforce`` as the pristine value and
    faithfully RESTORES it after every test that patches it, so the stack trace
    of the mutation points at pytest's own ``undo()`` rather than at a culprit.

Every test must exercise the DOCUMENTED defaults. For each test, every
``VULTURE_*`` variable and ``OPENAI_BASE_URL`` are removed, the import-time
``_CUSTOM_BASE_URL`` copies are blanked, and the persistent L5 verdict cache is
pointed at the test's own ``tmp_path`` (through ``HOME``, so no ``VULTURE_*``
name is added) with its connection state reset BEFORE the test runs (it defaults to ``~/.vulture/l5_cache.db``, which outlives the
process: a verdict cached by an earlier run would answer before a stub judge is
asked, and a stub's verdicts would leak into the developer's real cache). A
test that depends on a variable sets it explicitly; ``monkeypatch.setenv`` in
the test still wins because this fixture runs first.

The implementation is ``tests.support.isolation.isolate`` so a module-scoped
fixture that runs a pipeline once can apply the identical isolation.
"""

from __future__ import annotations

import pytest

from tests.support.isolation import isolate


@pytest.fixture(autouse=True)
def _isolate_vulture_env(monkeypatch, tmp_path):
    """Run every test against documented defaults, not the developer's ``.env``.

    Everything goes through ``monkeypatch`` so it is undone at teardown, and so
    it composes with tests that set a variable themselves.
    """
    isolate(monkeypatch, tmp_path)
    yield
