"""Environment isolation for the shared unit suite.

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

Unit tests must exercise the DOCUMENTED defaults. Every ``VULTURE_*`` variable
is therefore removed for each test; a test that depends on one sets it
explicitly (the suite already does this via ``monkeypatch.setenv``, which still
wins because this fixture runs first).

Scope note: the same import side effect can reach any suite that imports
litellm. This conftest fixes the shared suite, where it produced an observable
failure.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_vulture_env(monkeypatch):
    """Run every test against documented defaults, not the developer's ``.env``.

    Deletion goes through ``monkeypatch`` so it is undone at teardown, and so it
    composes with tests that set a variable themselves: autouse fixtures declared
    in a parent conftest run before those in a child conftest and before the test
    body, so an explicit ``setenv`` still takes effect.
    """
    for name in [k for k in os.environ if k.startswith("VULTURE_")]:
        monkeypatch.delenv(name, raising=False)
    yield
