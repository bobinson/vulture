"""Feature 0074 P-1 (AC33) — the LLM-family provenance list shared with Go.

``backend/internal/handler/testdata/llm_provenance_family_0074.json`` is read by
``llm_family_parity_0074_test.go`` and by the Python tests through here, so the
two languages classify the same spellings.
"""

from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURE = _REPO_ROOT / "backend" / "internal" / "handler" / "testdata" / "llm_provenance_family_0074.json"


def cases() -> list[dict]:
    """Every ``{provenance, is_llm}`` row of the shared fixture."""
    return json.loads(FIXTURE.read_text())


def llm_family_variants() -> list[str]:
    """The spellings Go's ``isLLMProvenance`` calls LLM-authored."""
    return [c["provenance"] for c in cases() if c["is_llm"]]
