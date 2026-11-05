"""Fixtures and import paths shared by every CWE test suite (unit, e2e)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests._ast_v1 import Finding

# Feature 0057 Phase 5 — make the corpus runner (agents/cwe/tests/corpus/corpus_runner.py)
# and the promotion script (agents/cwe/scripts/promote_signatures.py) importable by their
# bare module names. These dirs are not packages, so they are added to sys.path rather
# than imported as packages. Done here, above unit/ and e2e/, so both suites (and the
# shared test-support modules beside this file) see the same names.
_AGENT_ROOT = Path(__file__).resolve().parents[1]  # agents/cwe/
for _p in (_AGENT_ROOT / "tests" / "corpus", _AGENT_ROOT / "scripts"):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)


@pytest.fixture(scope="session")
def ast_v1_rows(request: pytest.FixtureRequest) -> list[Finding]:
    """Every row the two migrated skills emit on one neutral copy of ``ast_v1``.

    One scan per session: the 0102 contract modules all read the same rows.
    Imported here, not at the top: this conftest loads before every CWE test
    module, and must not load the skills ahead of them.
    """
    from tests import _ast_v1

    return _ast_v1.migrated_rows(_ast_v1.copy_fixtures(request))
