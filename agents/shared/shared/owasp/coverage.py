"""Build a per-category OWASP coverage manifest from detected CWE ids.

The manifest is the OWASP agent's "crystal clear reporting" deliverable: for
every category it states how many CWEs OWASP maps and how many the current
audit actually found, and it records the upstream CWE-stage status so a
partial/failed/absent detection run is visible rather than silently reported
as clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shared.owasp.mapping import Edition

# CWE-stage provenance values carried into the manifest.
STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUS_ABSENT = "absent"


@dataclass(frozen=True)
class CategoryCoverage:
    id: str
    name: str
    mapped_count: int
    found_cwes: list[int]
    source_url: str

    @property
    def found_count(self) -> int:
        return len(self.found_cwes)

    @property
    def status(self) -> str:
        return "found" if self.found_cwes else "clean-or-undetected"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "mapped_count": self.mapped_count,
            "found_cwes": [f"CWE-{c}" for c in self.found_cwes],
            "found_count": self.found_count,
            "status": self.status,
            "source_url": self.source_url,
        }


@dataclass(frozen=True)
class CoverageManifest:
    edition_id: str
    categories: list[CategoryCoverage]
    cwe_stage_status: str
    # Detected CWEs that no category in this edition maps. Previously these
    # were silently dropped — the manifest reported only the intersection with
    # each category — so an audit could detect a weakness the taxonomy does not
    # place and the OWASP view would look complete without it. Reporting the
    # residue keeps "we found nothing there" distinguishable from "we found
    # something unmappable", without inventing a mapping for it.
    unmapped_cwes: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "edition": self.edition_id,
            "cwe_stage_status": self.cwe_stage_status,
            "categories": [c.to_dict() for c in self.categories],
            "unmapped_cwes": [f"CWE-{c}" for c in self.unmapped_cwes],
            "unmapped_count": len(self.unmapped_cwes),
        }


def build_manifest(
    edition: Edition,
    detected_cwes: set[int],
    cwe_stage_status: str = STATUS_COMPLETED,
) -> CoverageManifest:
    """Build a manifest covering every category in ``edition``.

    Args:
        edition: The OWASP edition to report against.
        detected_cwes: CWE ids found by the upstream CWE stage.
        cwe_stage_status: Provenance of the CWE stage (completed/partial/failed/absent).
    """
    cats = [
        CategoryCoverage(
            id=c.id,
            name=c.name,
            mapped_count=len(c.cwes),
            found_cwes=sorted(detected_cwes & c.cwes),
            source_url=c.source_url,
        )
        for c in edition.categories
    ]
    mapped_universe: set[int] = set()
    for c in edition.categories:
        mapped_universe |= c.cwes
    unmapped = sorted(detected_cwes - mapped_universe)
    return CoverageManifest(edition.edition_id, cats, cwe_stage_status, unmapped)
