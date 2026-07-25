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


def test_generic_tokens_sync_between_extractor_and_runtime():
    """The extraction-time and runtime _GENERIC_TOKENS frozensets must be
    identical. They are intentionally duplicated (script cannot import from
    the agent module cleanly) — this test fails loudly on divergence."""
    import importlib.util
    import pathlib
    from cwe_agent.skills.catalog_detector import _GENERIC_TOKENS as runtime_set
    repo_root = pathlib.Path(__file__).resolve().parents[4]
    script_path = repo_root / "scripts" / "extract_cwe_catalog.py"
    spec = importlib.util.spec_from_file_location("extract_cwe_catalog", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._GENERIC_TOKENS == runtime_set, (
        "extract_cwe_catalog._GENERIC_TOKENS diverged from "
        "catalog_detector._GENERIC_TOKENS — update both in the same commit."
    )
