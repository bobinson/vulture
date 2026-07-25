"""CI floor: every OWASP category (all editions) has a detectable CWE.

The detectable set is DERIVED from the CWE agent's own skill sources — not a
hardcoded list — so it cannot silently drift out of sync with the skills
(feature 0063). We count only CWE ids that appear as emitted finding
categories (``"category": "CWE-N"``) or in the signatures/catalog detector
config, not incidental mentions in comments/docstrings.
"""

import pathlib
import re

import pytest
from shared.owasp.mapping import available_editions, load_edition

_SKILLS_DIR = pathlib.Path(__file__).resolve().parents[2] / "cwe_agent" / "skills"

# Match the CWE id in an emitted finding's category field, e.g.
#   "category": "CWE-89"   or   'category': 'CWE-799'
_EMITTED_RE = re.compile(r"""["']category["']\s*:\s*["']CWE-(\d+)["']""")
# Signature/registry entries declare their CWE as e.g. cwe="CWE-489" / "CWE-489".
_SIGNATURE_RE = re.compile(r"""["']CWE-(\d+)["']""")


def _detected_cwes() -> set[int]:
    ids: set[int] = set()
    for py in _SKILLS_DIR.rglob("*.py"):
        text = py.read_text("utf-8")
        for m in _EMITTED_RE.finditer(text):
            ids.add(int(m.group(1)))
        # signatures/registry.py declares corpus-trusted CWEs without the
        # "category" key shape; include those literal CWE-N declarations too.
        if py.parent.name == "signatures":
            for m in _SIGNATURE_RE.finditer(text):
                ids.add(int(m.group(1)))
    return ids


def test_detected_set_is_nonempty():
    # Guards the derivation itself: if the regex or path breaks, fail loudly
    # rather than passing every category vacuously.
    assert len(_detected_cwes()) >= 50


@pytest.mark.parametrize("edition_id", available_editions())
def test_every_category_has_a_detectable_cwe(edition_id):
    detected = _detected_cwes()
    ed = load_edition(edition_id)
    blind = [f"{c.id} {c.name}" for c in ed.categories if not (c.cwes & detected)]
    assert not blind, (
        f"OWASP Top 10:{edition_id} categories with NO detectable CWE: {blind}. "
        f"Add a detector in the CWE agent for one of that category's mapped CWEs."
    )
