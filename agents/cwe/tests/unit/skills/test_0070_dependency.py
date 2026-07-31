"""Feature 0070 — dependency skill precision.

Two defects, both measured on a real application tree:

1. **CWE-937 is a CWE _Category_, not a Weakness.** The known-vulnerable
   component finding was labelled ``CWE-937``, which the OWASP **2025** edition
   maps to *nothing* (2025 A03 lists 447/1035/1104/1329/1357/1395) and which the
   CWE catalog cannot enrich (``enrich_finding(f, "937")`` adds no name and no
   description). Net effect: the single highest-value supply-chain signal the
   skill produces was invisible to A03, leaving A03 to report ``found`` on
   CWE-1104 alone. ``CWE-1395`` (*Dependency on Vulnerable Third-Party
   Component*) is the Weakness for exactly this finding, is in A03's 2025 set,
   and IS enrichable.

2. **CWE-1104 fired once per floating dependency spec.** Three npm manifests in
   one measured tree produced 244 ``low`` rows carrying one bit of information each
   ("this manifest uses caret ranges"), 70 of them literal duplicates across
   manifests. Rolled up per manifest the same information is 3 rows — provided
   the rollup keeps the count and the package list.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from cwe_agent.skills.dependency_check import check_dependency_security


def _cats(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_dependency_security(str(root))["findings"]


# A pinned-but-vulnerable pair straight out of the bundled catalog.
_VULN_LOCK = json.dumps({
    "name": "x",
    "lockfileVersion": 2,
    "packages": {"node_modules/lodash": {"version": "3.10.1"}},
})


# ---------------------------------------------------------------------------
# (1) CWE-1395 remap
# ---------------------------------------------------------------------------
class TestKnownVulnerableIsAWeaknessNotACategory:
    def test_premise_1395_is_in_owasp_2025_a03_and_937_is_not(self):
        """Guard the premise: the remap only helps if 1395 is mapped and 937
        is not. If a future edition file changes, this test says so."""
        from shared.owasp.mapping import load_edition

        edition = load_edition("2025")
        mapped: set[int] = set()
        for cat in edition.categories:
            mapped |= {int(c) for c in cat.cwes}
        assert 1395 in mapped, "CWE-1395 must be mapped by OWASP 2025"
        assert 937 not in mapped, (
            "CWE-937 is a Category, not a Weakness — OWASP 2025 must not map it"
        )

    def test_premise_1395_enriches_and_937_does_not(self):
        from cwe_agent.catalog import enrich_finding

        assert enrich_finding({}, "1395").get("cwe_name"), "1395 must be enrichable"
        assert not enrich_finding({}, "937").get("cwe_name"), (
            "937 is a Category — the catalog cannot enrich it"
        )

    def test_known_vulnerable_component_is_cwe_1395(self):
        f = _run({"package-lock.json": _VULN_LOCK})
        hits = _cats(f, "CWE-1395")
        assert hits, "a known-vulnerable pinned dependency must be reported as CWE-1395"
        assert any("lodash" in h["title"] for h in hits)

    def test_cwe_937_is_never_emitted(self):
        f = _run({"package-lock.json": _VULN_LOCK})
        assert not _cats(f, "CWE-937"), (
            "CWE-937 is a CWE Category; emitting it maps to nothing in OWASP 2025"
        )

    def test_remapped_finding_is_enriched(self):
        """The whole point of moving off a Category id: enrichment now lands."""
        hits = _cats(_run({"package-lock.json": _VULN_LOCK}), "CWE-1395")
        assert hits[0].get("cwe_name"), "remapped finding must carry catalog metadata"

    def test_remap_is_label_only_no_new_or_lost_rows(self):
        """One CVE match in, one row out — the remap must not change counts."""
        f = _run({"package-lock.json": _VULN_LOCK})
        assert len(_cats(f, "CWE-1395")) == 1
        assert all(
            h["check_id"].startswith("cwe.dependency.known_vulnerable.")
            for h in _cats(f, "CWE-1395")
        )


# ---------------------------------------------------------------------------
# (2) CWE-1104 rollup
# ---------------------------------------------------------------------------
_MANY = {f"pkg{i}": f"^1.{i}.0" for i in range(12)}


class TestUnpinnedRollup:
    def test_one_finding_per_manifest_not_per_dependency(self):
        f = _run({"package.json": json.dumps({"dependencies": _MANY})})
        hits = _cats(f, "CWE-1104")
        assert len(hits) == 1, (
            f"12 floating specs in one manifest must roll up to 1 finding, got {len(hits)}"
        )

    def test_rollup_carries_the_instance_count(self):
        hits = _cats(_run({"package.json": json.dumps({"dependencies": _MANY})}), "CWE-1104")
        assert hits[0].get("instance_count") == 12
        assert "12" in hits[0]["description"], "the count must be human-readable too"

    def test_rollup_names_the_packages(self):
        hits = _cats(_run({"package.json": json.dumps({"dependencies": _MANY})}), "CWE-1104")
        blob = hits[0]["title"] + hits[0]["description"]
        for pkg in _MANY:
            assert pkg in blob, f"rollup lost package {pkg}"

    def test_large_manifest_states_the_remainder_but_drops_no_package(self):
        """Rolling up must not lose what the individual rows carried: beyond the
        spec-listing limit the tail is named, just without its version spec."""
        deps = {f"p{i:03d}": "^1.0.0" for i in range(120)}
        hits = _cats(_run({"package.json": json.dumps({"dependencies": deps})}), "CWE-1104")
        assert len(hits) == 1
        assert hits[0]["instance_count"] == 120
        desc = hits[0]["description"]
        assert re.search(r"\band \d+ more\b", desc), (
            "an abbreviated package list must say how many are listed by name only"
        )
        for pkg in deps:
            assert pkg in desc, f"rollup dropped package {pkg}"

    def test_each_manifest_gets_its_own_rollup(self):
        f = _run({
            "package.json": json.dumps({"dependencies": {"a": "^1.0.0"}}),
            "frontend/package.json": json.dumps({"dependencies": {"b": "~2.0.0"}}),
            "requirements.txt": "flask\nrequests>=2.0\n",
        })
        hits = _cats(f, "CWE-1104")
        assert len(hits) == 3, f"expected one rollup per manifest, got {len(hits)}"
        assert len({h["file_path"] for h in hits}) == 3

    def test_requirements_txt_rolls_up_too(self):
        hits = _cats(_run({"requirements.txt": "flask\nrequests>=2.0\ndjango==4.2.1\n"}), "CWE-1104")
        assert len(hits) == 1
        assert hits[0]["instance_count"] == 2
        blob = hits[0]["description"]
        assert "flask" in blob and "requests" in blob
        assert "django" not in blob, "an exactly-pinned dep must not be in the rollup"

    def test_fully_pinned_manifest_yields_nothing(self):
        assert not _cats(_run({"package.json": json.dumps({"dependencies": {"a": "1.0.0"}})}), "CWE-1104")

    def test_rollup_spans_the_member_lines(self):
        body = (
            '{\n  "dependencies": {\n    "alpha": "1.0.0",\n'
            '    "beta": "^2.0.0",\n    "gamma": "~3.0.0"\n  }\n}\n'
        )
        hits = _cats(_run({"package.json": body}), "CWE-1104")
        assert len(hits) == 1
        assert hits[0]["line_start"] == 4, "must start at the first unpinned dep, not line 1"
        assert hits[0]["line_end"] == 5, "must span to the last unpinned dep"

    def test_title_is_stable_across_manifest_edits(self):
        """The count lives in the description, not the title: the backend
        fingerprints on (title, file_path, category), so a title carrying N
        would make every dependency bump look like a brand-new finding."""
        a = _cats(_run({"package.json": json.dumps({"dependencies": {"a": "^1.0.0"}})}), "CWE-1104")
        b = _cats(_run({"package.json": json.dumps({"dependencies": _MANY})}), "CWE-1104")
        assert a[0]["title"] == b[0]["title"]

    def test_untrusted_specs_are_not_swallowed_by_the_rollup(self):
        f = _run({"package.json": json.dumps({"dependencies": {
            "x": "git+https://github.com/evil/x.git",
            "y": "file:../vendor/y",
            "z": "^1.0.0",
        }})})
        assert len(_cats(f, "CWE-1357")) == 2, "CWE-1357 stays per-dependency"
        assert len(_cats(f, "CWE-1104")) == 1

# The former single-tree aggregate class was removed: it pinned one repository's
# exact paths and counts (244 -> 3 rows, 11 CWE-1395 rows). Every property it
# proved is covered hermetically above — `test_rollup_carries_the_instance_count`,
# `test_each_manifest_gets_its_own_rollup`, `test_rollup_names_the_packages` and
# `test_untrusted_specs_are_not_swallowed_by_the_rollup` — without binding the
# suite to a particular scan target.
