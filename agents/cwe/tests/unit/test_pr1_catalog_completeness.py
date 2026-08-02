"""Catalog completeness guards for the CWE extraction pipeline.

Background
----------
The generated catalog is the single runtime source of CWE metadata. An id that
is absent from it is unreachable no matter how good the detector is, and an id
that is present but *unenrichable* (no name/description) is worse than absent:
it lets a skill emit a category that cannot be explained to a user.

Two independent mechanisms used to drop software-relevant ids:

1. A manual ``HARDWARE_CWE_IDS`` exclusion list, which listed an id that MITRE
   itself tags ``Not Language-Specific``.
2. A heuristic that read "no ``Applicable_Platforms/Language`` element at all"
   as "has no software language". Combined with a lone ICS/OT *domain* tag —
   which MITRE applies to many ordinary software weaknesses — that silently
   excluded language-agnostic Class weaknesses.

These tests pin both, plus the general invariant that every shipped entry is
enrichable. All XML inputs here are synthetic.
"""

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from cwe_agent.catalog import get_cwe, load_catalog

_REPO_ROOT = Path(__file__).resolve().parents[4]
_EXTRACTOR = _REPO_ROOT / "scripts" / "extract_cwe_catalog.py"


def _load_extractor():
    """Import the extraction script by path (it is a script, not a package)."""
    spec = importlib.util.spec_from_file_location("_cwe_extractor", _EXTRACTOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


extractor = _load_extractor()
NS = extractor.NS

# Total entries produced from the pinned upstream CWE v4.19.1 XML.
EXPECTED_CATALOG_SIZE = 851

# Software-relevant ids that the two defects above were excluding. Each must be
# present AND enrichable, not merely present.
RECOVERED_IDS = ["15", "1068", "1110", "1329", "1357"]


def _is_bare(entry: dict) -> bool:
    """True when an entry has no human-readable content to enrich a finding."""
    return not entry.get("name", "").strip() or not entry.get(
        "description", ""
    ).strip()


def _weakness_xml(body: str) -> ET.Element:
    """Build a synthetic <Weakness> element for platform-filter tests."""
    return ET.fromstring(
        '<Weakness xmlns="http://cwe.mitre.org/cwe-7" ID="99999" '
        f'Name="Synthetic" Abstraction="Base">{body}</Weakness>'
    )


class TestRecoveredEntries:
    """The previously-dropped ids resolve at runtime and carry real content."""

    @pytest.mark.parametrize("cwe_id", RECOVERED_IDS)
    def test_entry_is_reachable(self, cwe_id):
        assert get_cwe(cwe_id) is not None, (
            f"CWE-{cwe_id} is absent from the catalog; any skill emitting it "
            f"would produce an unresolvable category"
        )

    @pytest.mark.parametrize("cwe_id", RECOVERED_IDS)
    def test_entry_is_enrichable(self, cwe_id):
        entry = get_cwe(cwe_id)
        assert entry["name"].strip(), f"CWE-{cwe_id} has no name"
        assert entry["description"].strip(), f"CWE-{cwe_id} has no description"
        assert entry["keywords"], f"CWE-{cwe_id} has no keywords"

    def test_recovered_ids_have_relationships(self):
        """Relationship data is what lets a Class/Pillar id roll up."""
        for cwe_id in RECOVERED_IDS:
            assert get_cwe(cwe_id)["related_weaknesses"], (
                f"CWE-{cwe_id} has no related_weaknesses"
            )


class TestExclusionList:
    """The manual hardware list must not shadow software-relevant ids."""

    def test_not_language_specific_id_is_not_excluded(self):
        assert 1329 not in extractor.HARDWARE_CWE_IDS

    def test_excluded_ids_stay_out_of_catalog(self):
        catalog = load_catalog()
        leaked = sorted(
            i for i in extractor.HARDWARE_CWE_IDS if str(i) in catalog
        )
        assert leaked == [], f"hardware-only ids leaked into catalog: {leaked}"


class TestPlatformHeuristic:
    """Pin the empty-Language defect and the behaviour it must not break."""

    def test_absent_language_element_is_software_applicable(self):
        """No <Language> at all means language-agnostic, never hardware-only."""
        w = _weakness_xml(
            "<Applicable_Platforms>"
            '<Technology Class="ICS/OT"/>'
            "</Applicable_Platforms>"
        )
        assert extractor._is_software_applicable(w) is True
        assert extractor._is_hardware_only(w) is False

    def test_not_language_specific_is_software_applicable(self):
        w = _weakness_xml(
            "<Applicable_Platforms>"
            '<Language Class="Not Language-Specific"/>'
            '<Technology Class="ICS/OT"/>'
            "</Applicable_Platforms>"
        )
        assert extractor._is_hardware_only(w) is False

    def test_named_language_is_software_applicable(self):
        w = _weakness_xml(
            "<Applicable_Platforms>"
            '<Language Name="C"/>'
            "</Applicable_Platforms>"
        )
        assert extractor._is_software_applicable(w) is True

    def test_hardware_technology_without_software_language_excluded(self):
        """A real silicon-level technology with a non-software language class
        is still filtered out — the fix must not disable the guard."""
        w = _weakness_xml(
            "<Applicable_Platforms>"
            '<Language Class="Compiled"/>'
            '<Technology Name="Processor Hardware"/>'
            "</Applicable_Platforms>"
        )
        assert extractor._is_software_applicable(w) is False
        assert extractor._is_hardware_only(w) is True


class TestCatalogInvariants:
    """Whole-catalog guards against silent regeneration drift."""

    def test_catalog_size(self):
        assert len(load_catalog()) == EXPECTED_CATALOG_SIZE

    def test_every_entry_is_enrichable(self):
        """No shipped entry may be a bare id with nothing to explain it."""
        bad = [key for key, entry in load_catalog().items() if _is_bare(entry)]
        assert bad == [], f"entries missing name/description: {sorted(bad)[:10]}"

    def test_keys_match_entry_ids(self):
        mismatched = [
            key for key, entry in load_catalog().items() if entry.get("id") != key
        ]
        assert mismatched == [], f"key/id mismatch: {sorted(mismatched)[:10]}"
