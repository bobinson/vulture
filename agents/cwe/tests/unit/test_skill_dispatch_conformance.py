"""Every implemented skill must actually be dispatched.

`ALL_CATEGORIES` (cwe_agent/config.py) is the dispatch list; `SKILL_MAP`
(cwe_agent/skills/__init__.py) is the registry of implemented skills. Nothing
tied them together, and they silently drifted: SKILL_MAP grew to 24 while
ALL_CATEGORIES stayed at 22, so `secrets` and `plaintext_transmission` were
fully implemented, imported, and never run.

On OWASP juice-shop that cost 41 findings, 6 of them critical — an inline RSA
private key (lib/insecurity.ts:21), BIP-39 mnemonic seed phrases, three Solana
keypairs, and every CWE-319 plaintext-transmission row. The agent shipped
working detectors for weaknesses it then reported as absent.

The old test asserted `len(ALL_CATEGORIES) == 22`, a magic number that encoded
the broken state — it would have had to be *edited* to let the bug be fixed.
This asserts the relationship instead, so the two lists cannot diverge again
regardless of how many skills exist.
"""

from cwe_agent.config import AGENT_INFO, ALL_CATEGORIES
from cwe_agent.skills import SKILL_MAP


def test_every_implemented_skill_is_dispatched():
    undispatched = sorted(set(SKILL_MAP) - set(ALL_CATEGORIES))
    assert not undispatched, (
        f"skills implemented in SKILL_MAP but absent from ALL_CATEGORIES, so "
        f"they never run: {undispatched}"
    )


def test_no_dispatched_category_lacks_a_skill():
    orphans = sorted(set(ALL_CATEGORIES) - set(SKILL_MAP))
    assert not orphans, (
        f"categories dispatched with no implementing skill: {orphans}"
    )


def test_dispatch_list_and_registry_are_the_same_set():
    """The invariant, stated once: they are two views of one thing."""
    assert set(ALL_CATEGORIES) == set(SKILL_MAP)


def test_no_duplicate_categories():
    assert len(ALL_CATEGORIES) == len(set(ALL_CATEGORIES)), \
        "ALL_CATEGORIES contains duplicates"


def test_agent_info_skills_match_dispatch_list():
    """/info must advertise exactly what the agent runs."""
    assert len(AGENT_INFO["skills"]) == len(ALL_CATEGORIES), (
        f"AGENT_INFO advertises {len(AGENT_INFO['skills'])} skills but "
        f"{len(ALL_CATEGORIES)} are dispatched"
    )


def test_config_schema_enum_tracks_the_dispatch_list():
    """The config schema must not offer a category the agent cannot run."""
    enum = AGENT_INFO["config_schema"]["properties"]["categories"]["items"]["enum"]
    assert set(enum) == set(ALL_CATEGORIES)


def test_the_two_previously_undispatched_skills_are_present():
    """Regression pin for the specific drift that was found."""
    for name in ("secrets", "plaintext_transmission"):
        assert name in SKILL_MAP, f"{name} missing from SKILL_MAP"
        assert name in ALL_CATEGORIES, f"{name} implemented but not dispatched"
