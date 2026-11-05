"""The coverage figures the CWE agent states in prose are PINNED to the values
the code computes, so they cannot go stale again.

Every count comes from the same source ``tests/corpus/report_coverage.py``
uses; nothing is counted twice and nothing is hand-typed here:

  * declared CWE-ID ``category`` literals -> ``skill_category_cwe_ids()``
  * corpus-trusted signature CWE-IDs      -> ``trusted_signature_cwe_ids()``
  * N (corpus-VERIFIED)                   -> the generated VERIFIED_CWES.md header
  * dedicated skills                      -> ``SKILL_MAP`` minus the catalog path
  * dedicated-skill CWEs                  -> ``catalog_detector._DEDICATED_SKILL_CWES``

The surfaces checked are ``SKILLS.md``, ``config.AGENT_INFO["description"]``,
the CWE GENERATE prompt fragment (``shared/prompt/fragments/domains/cwe.md``)
and its byte oracle ``agent.INSTRUCTIONS``. A change to the fragment is a
prompt change for every model family: it also bumps the generate manifest
version and re-captures the goldens.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import report_coverage

from cwe_agent.agent import INSTRUCTIONS
from cwe_agent.config import AGENT_INFO
from cwe_agent.skills import SKILL_MAP
from cwe_agent.skills.catalog_detector import _DEDICATED_SKILL_CWES

_AGENT_DIR = Path(__file__).resolve().parents[2]
_SKILLS_MD = _AGENT_DIR / "cwe_agent" / "skills" / "SKILLS.md"
_GOLDEN = _AGENT_DIR / "tests" / "corpus" / "VERIFIED_CWES.md"
_FRAGMENT = (_AGENT_DIR.parent / "shared" / "shared" / "prompt" / "fragments"
             / "domains" / "cwe.md")


def _verified_n() -> int:
    m = re.search(r"\*\*N = (\d+)\*\*", _GOLDEN.read_text(encoding="utf-8"))
    assert m, "VERIFIED_CWES.md has no `**N = <n>**` header"
    return int(m.group(1))


def _claims() -> dict[str, tuple[re.Pattern, int]]:
    return {
        "categories": (re.compile(r"(~?)(\d+) (?:declared|distinct) CWE-ID"),
                       len(report_coverage.skill_category_cwe_ids())),
        "verified": (re.compile(r"\bN\s*=\s*(~?)(\d+)"), _verified_n()),
        "skills": (re.compile(r"(~?)(\d+) dedicated (?:regex )?skills"), len(SKILL_MAP) - 1),
        "signatures": (re.compile(r"(~?)(\d+) (?:corpus-)?trusted signature"),
                       len(report_coverage.trusted_signature_cwe_ids())),
        "dedicated_cwes": (re.compile(r"all (~?)(\d+) dedicated-skill CWEs"),
                           len(_DEDICATED_SKILL_CWES)),
    }


_SURFACES = {
    "SKILLS.md": lambda: _SKILLS_MD.read_text(encoding="utf-8"),
    "AGENT_INFO.description": lambda: AGENT_INFO["description"],
    "agent.INSTRUCTIONS": lambda: INSTRUCTIONS,
    "prompt fragment domains/cwe.md": lambda: _FRAGMENT.read_text(encoding="utf-8"),
}


def _stated(text: str) -> list[tuple[str, re.Match, int]]:
    """Every count claim in ``text``, with the value it must equal."""
    return [(claim, m, value) for claim, (pattern, value) in _claims().items()
            for m in pattern.finditer(text)]


def _stale(text: str) -> list[tuple[str, str, int]]:
    """Every claim in ``text`` that is approximate (``~``) or not the computed value."""
    return [(claim, m.group(0), value) for claim, m, value in _stated(text)
            if m.group(1) or int(m.group(2)) != value]


@pytest.mark.parametrize("surface", sorted(_SURFACES))
def test_every_stated_count_equals_the_computed_value(surface: str) -> None:
    wrong = _stale(_SURFACES[surface]())
    assert wrong == [], f"{surface}: stale or approximate count claims {wrong}"


@pytest.mark.parametrize("surface", sorted(_SURFACES))
@pytest.mark.parametrize("claim", ["categories", "verified"])
def test_the_headline_counts_are_stated(surface: str, claim: str) -> None:
    pattern, _ = _claims()[claim]
    assert pattern.search(_SURFACES[surface]()), f"{surface} no longer states the {claim} count"
