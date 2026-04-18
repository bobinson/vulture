"""Catalog-JSON assertions (separate from catalog_detector runtime tests)."""
from cwe_agent.catalog import get_cwe, load_catalog


def test_catalog_has_observed_examples_for_cwe_369():
    entry = get_cwe("369")
    assert entry is not None
    assert "observed_examples" in entry
    refs = [o["reference"] for o in entry["observed_examples"]]
    assert any(r.startswith("CVE-") for r in refs)


def test_catalog_keywords_mined_from_cve_descriptions():
    """CVE descriptions in Observed_Examples carry dangerous-function names
    that the original tech_words whitelist misses. After Task 1's regex
    expansion + Observed_Examples mining, at least one of these tokens must
    appear in the keyword set for CWE-676 (Use of Potentially Dangerous
    Function)."""
    entry = get_cwe("676")
    assert entry is not None
    kws = set(entry["keywords"])
    assert "strcpy" in kws or "sprintf" in kws or "strcat" in kws or "gets" in kws


def test_catalog_keywords_exclude_shared_generic_tokens():
    """Keywords must not contain tokens from the runtime _GENERIC_TOKENS
    blocklist — extraction and runtime must stay in sync."""
    from cwe_agent.skills.catalog_detector import _GENERIC_TOKENS
    catalog = load_catalog()
    offenders: dict[str, set[str]] = {}
    for cwe_id, entry in catalog.items():
        leaked = set(entry.get("keywords", [])) & _GENERIC_TOKENS
        if leaked:
            offenders[cwe_id] = leaked
    assert not offenders, f"{len(offenders)} CWEs leak generic tokens: {list(offenders.items())[:3]}"
