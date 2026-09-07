"""An agent's surviving INSTRUCTIONS literal must equal its fragment.

Feature 0089 Phase 2.5. Every agent now passes
`instructions=domain_instructions("domains/<agent>")`, so the FRAGMENT is what
production sends. Several agents still define an `INSTRUCTIONS` constant that
nothing in production reads:

* `soc2`, `chaos_engineering`, `do178c`, `ssdf` — one reference, its own
  definition. Dead.
* `cwe`, `asvs` — dead in production, but existing unit tests import the
  constant and assert on its content (`"Self-Learning" in INSTRUCTIONS`,
  `"ASVS v5.0.0" in INSTRUCTIONS`). Those tests are the business contract and
  are not rewritten here.
* `xss` — reads `INSTRUCTIONS.md`, which its own comment documents as the
  intended arrangement.

The hazard is not the duplication itself but SILENT DIVERGENCE: edit the
fragment and the stale literal still satisfies its tests, so `cwe`'s suite would
stay green while production sent something else — the two-authorities condition
this feature exists to remove, reintroduced where the linter cannot see it
because a Python constant is not a fragment.

This does not delete anything. It makes the duplicate safe by asserting the two
agree, so a divergence fails here instead of shipping. Deleting the constants
and repointing those tests at `domain_instructions()` is the follow-up that
retires this file.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

_AGENTS = {
    "cwe": ("cwe", "cwe_agent"),
    "asvs": ("asvs", "asvs_agent"),
    "soc2": ("soc2", "soc2_agent"),
    "chaos": ("chaos_engineering", "chaos_agent"),
    "do178c": ("do178c", "do178c_agent"),
    "ssdf": ("ssdf", "ssdf_agent"),
    "xss": ("xss", "xss_agent"),
}
_ROOT = Path(__file__).resolve().parents[4]


def _agent_module(pkg_dir: str, module: str):
    path = _ROOT / "agents" / pkg_dir
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    try:
        return importlib.import_module(f"{module}.agent")
    except Exception as exc:  # a missing optional dep is not this test's subject
        pytest.skip(f"{module} not importable here: {type(exc).__name__}")


@pytest.mark.parametrize("name", sorted(_AGENTS))
def test_surviving_literal_matches_the_fragment_production_sends(name: str):
    from shared.prompt.manifests.generate import domain_instructions

    pkg_dir, module = _AGENTS[name]
    mod = _agent_module(pkg_dir, module)
    literal = getattr(mod, "INSTRUCTIONS", None)
    if literal is None:
        pytest.skip(f"{name} defines no INSTRUCTIONS constant — nothing to diverge")
    rendered = domain_instructions(f"domains/{'chaos' if name == 'chaos' else name}")
    assert literal == rendered, (
        f"{name}: the INSTRUCTIONS literal and domains/{name} have diverged. "
        "Production sends the FRAGMENT; the literal only satisfies that agent's "
        "own tests, so this divergence would ship silently."
    )


def test_the_subject_is_not_empty():
    """Guards the vacuous pass: all-skipped would satisfy the test above."""
    present = 0
    for name, (pkg_dir, module) in _AGENTS.items():
        try:
            mod = _agent_module(pkg_dir, module)
        except Exception:
            continue
        if getattr(mod, "INSTRUCTIONS", None):
            present += 1
    assert present >= 4, (
        f"only {present} agents still define INSTRUCTIONS; if they were all "
        "deleted, delete this file too rather than leaving it asserting nothing"
    )
