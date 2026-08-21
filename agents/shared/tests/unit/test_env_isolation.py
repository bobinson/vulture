"""The unit suite must not inherit configuration from a developer's ``.env``.

``litellm`` calls ``dotenv.load_dotenv()`` at import time, and because the
virtualenv lives inside the repository that walk reaches the top-level ``.env``.
Before ``tests/unit/conftest.py`` existed, that injected
``VULTURE_OBLIGATION_MODE=enforce`` during collection and flipped the L5
promotion label from ``JUDGE_CITED`` to ``JUDGE_UNCITED`` — but only when a test
that imports litellm ran first, so ``pytest tests/unit/validate`` passed while
``pytest tests/unit`` failed on the same commit.

These tests pin the property the rest of the suite silently depends on: the
gating variables read their DOCUMENTED defaults regardless of the machine.
"""

from __future__ import annotations

import os
from pathlib import Path

from shared.validate.llm_judge import _promotion_closure_required
from shared.validate.refutation import obligation_mode


def test_no_vulture_env_leaks_into_a_test():
    """No ``VULTURE_*`` variable survives into a test.

    Fails if the autouse isolation fixture is removed on any machine that has a
    ``.env`` or exports these vars — which is exactly the configuration that
    produced the original divergence between local and CI runs.
    """
    leaked = sorted(k for k in os.environ if k.startswith("VULTURE_"))
    assert leaked == [], f"developer configuration leaked into the suite: {leaked}"


def test_obligation_gate_reads_its_documented_default():
    """``observe`` is the shipping default; ``enforce`` must be opt-in per test."""
    assert obligation_mode() == "observe"


def test_promotion_closure_is_off_by_default():
    """The L5 promotion gate tracks the obligation mode, so it is off under
    ``observe``. This is the single value whose leak retagged the verdicts."""
    assert _promotion_closure_required() is False


def test_the_isolation_fixture_still_exists():
    """Structural guard: catches deletion of the fixture even on a machine with
    no ``.env``, where the assertions above would pass vacuously."""
    conftest = Path(__file__).parent / "conftest.py"
    src = conftest.read_text()
    assert "autouse=True" in src and "VULTURE_" in src, (
        "tests/unit/conftest.py must keep the autouse fixture that strips "
        "VULTURE_* from the environment; without it the suite's result depends "
        "on whether a .env exists on the machine"
    )
