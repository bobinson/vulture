"""Build a per-category OWASP coverage manifest from detected CWE ids.

The manifest is the OWASP agent's "crystal clear reporting" deliverable: for
every category it states how many CWEs OWASP maps and how many the current
audit actually found, and it records the upstream CWE-stage status so a
partial/failed/absent detection run is visible rather than silently reported
as clean.
"""

from __future__ import annotations

from dataclasses import dataclass

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

    def to_dict(self) -> dict:
        return {
            "edition": self.edition_id,
            "cwe_stage_status": self.cwe_stage_status,
            "categories": [c.to_dict() for c in self.categories],
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
    return CoverageManifest(edition.edition_id, cats, cwe_stage_status)
