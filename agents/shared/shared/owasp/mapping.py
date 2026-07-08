"""Load OWASP Top 10 editions and resolve CWE IDs to their categories.

The OWASP Top 10 is, by OWASP's own methodology, a data-driven grouping over
CWE (each category maps to a published set of CWEs). These editions are the
single source of truth for the CWE->OWASP-category relationship in Vulture.
Adding a future edition requires only a new JSON file plus one registry line.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

_CWE_RE = re.compile(r"^CWE-(\d+)$")
_EDITIONS_PKG = "shared.owasp.editions"


class UnknownEditionError(ValueError):
    """Raised when an edition id is not present in the registry."""


@dataclass(frozen=True)
class Category:
    """One OWASP Top 10 category and the CWE ids mapped to it."""

    id: str
    slug: str
    name: str
    cwes: frozenset[int]
    source_url: str


@dataclass(frozen=True)
class Edition:
    """A full OWASP Top 10 edition (10 categories)."""

    edition_id: str
    title: str
    categories: tuple[Category, ...]

    def map_cwe(self, cwe_id: int) -> list[Category]:
        """Return every category whose CWE membership includes ``cwe_id``.

        A CWE may belong to more than one category, so the return type is
        always a list (empty when the CWE is not mapped in this edition).
        """
        return [c for c in self.categories if cwe_id in c.cwes]


def parse_cwe_id(category_field: str) -> int | None:
    """Extract the integer id from a ``"CWE-<n>"`` string, else ``None``."""
    if not category_field:
        return None
    m = _CWE_RE.match(category_field.strip())
    return int(m.group(1)) if m else None


def _read_json(filename: str) -> dict:
    return json.loads(resources.files(_EDITIONS_PKG).joinpath(filename).read_text("utf-8"))


@lru_cache(maxsize=1)
def _registry() -> dict:
    return _read_json("registry.json")


def available_editions() -> list[str]:
    """Sorted list of edition ids known to the registry (e.g. ``["2021", "2025"]``)."""
    return sorted(_registry()["editions"].keys())


@lru_cache(maxsize=8)
def load_edition(edition_id: str | None = None) -> Edition:
    """Load an edition by id; ``None`` selects the registry default.

    Raises:
        UnknownEditionError: if ``edition_id`` is not in the registry.
    """
    reg = _registry()
    eid = edition_id or reg["default"]
    filename = reg["editions"].get(eid)
    if filename is None:
        raise UnknownEditionError(
            f"unknown OWASP edition {eid!r}; available: {available_editions()}"
        )
    doc = _read_json(filename)
    cats = tuple(
        Category(
            id=c["id"],
            slug=c["slug"],
            name=c["name"],
            cwes=frozenset(c["cwes"]),
            source_url=c["source_url"],
        )
        for c in doc["categories"]
    )
    return Edition(edition_id=doc["edition"], title=doc["title"], categories=cats)
