"""Tests for the ASVS catalog extraction pipeline."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
DATA = REPO / "agents" / "asvs" / "asvs_agent" / "data"
CATALOG = DATA / "asvs_catalog.json"


def _load_catalog() -> dict:
    return json.loads(CATALOG.read_text())


def test_catalog_has_345_requirements():
    assert len(_load_catalog()) == 345


def test_catalog_has_17_chapters():
    c = _load_catalog()
    assert len({e["chapter_id"] for e in c.values()}) == 17


def test_catalog_level_distribution():
    """ASVS 5.0.0: 70 L1-entry, 183 L2-entry, 92 L3-entry = 345 total."""
    c = _load_catalog()
    by_level = {1: 0, 2: 0, 3: 0}
    for e in c.values():
        by_level[e["level"]] += 1
    assert by_level[1] == 70
    assert by_level[2] == 183
    assert by_level[3] == 92
    assert sum(by_level.values()) == 345


def test_catalog_v3_4_2_has_httponly_cwe_mapping():
    """V3.4.2 (HttpOnly cookies) maps to CWE-1004 per our crosswalk."""
    c = _load_catalog()
    assert "1004" in c["V3.4.2"]["cwe_ids"]


def test_catalog_detectability_sums_to_345():
    c = _load_catalog()
    counts = {"static": 0, "runtime": 0, "policy": 0}
    for e in c.values():
        counts[e["detectability"]] += 1
    assert sum(counts.values()) == 345
    assert counts["static"] >= 150


def test_catalog_entries_have_required_fields():
    c = _load_catalog()
    required = {"req_id", "chapter_id", "chapter_name", "section_id",
                "section_name", "level", "description", "detectability",
                "cwe_ids", "keywords", "severity"}
    for req_id, entry in c.items():
        assert required.issubset(entry.keys()), f"{req_id} missing fields"


def test_generic_tokens_sync_between_extractor_and_skill():
    """Extractor and runtime _GENERIC_TOKENS must be identical.

    Divergence silently causes the runtime to strip tokens the extractor
    retained (or vice versa), producing wrong specific-keyword counts
    in the fallback index.
    """
    import importlib.util
    from asvs_agent.skills.asvs_requirements_check import (
        _GENERIC_TOKENS as runtime_set,
    )
    spec = importlib.util.spec_from_file_location(
        "extract_asvs_catalog",
        REPO / "scripts" / "extract_asvs_catalog.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._GENERIC_TOKENS == runtime_set


def test_catalog_extractor_is_deterministic(tmp_path):
    out = tmp_path / "out.json"
    cmd = [
        sys.executable,
        str(REPO / "scripts" / "extract_asvs_catalog.py"),
        "--source", str(DATA / "asvs_source.json"),
        "--crosswalk", str(DATA / "asvs_cwe_crosswalk.json"),
        "--detectability", str(DATA / "asvs_detectability.json"),
        "--output", str(out),
    ]
    subprocess.check_call(cmd)
    h1 = hashlib.sha256(out.read_bytes()).hexdigest()
    subprocess.check_call(cmd)
    h2 = hashlib.sha256(out.read_bytes()).hexdigest()
    assert h1 == h2
