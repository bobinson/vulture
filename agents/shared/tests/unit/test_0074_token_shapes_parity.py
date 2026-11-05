"""0074 verification item 1: the agent's masker covers every token shape the
backend's defence-in-depth masker (Go ``textutil.MaskTokenShapes``) is pinned to,
from the same fixture, and leaves the same benign text alone. All values are
synthetic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.llm.errors import mask_secret_values

_FIXTURE = (Path(__file__).resolve().parents[4]
            / "backend/internal/textutil/testdata/token_shapes_0074.json")
_CASES = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_PLACEHOLDER = "***REDACTED***"


@pytest.mark.parametrize("case", _CASES["mask"], ids=lambda c: c["name"])
def test_agent_masks_every_backend_shape(case) -> None:
    masked = mask_secret_values(case["text"], _PLACEHOLDER)
    assert _PLACEHOLDER in masked
    assert not [raw for raw in case["gone"] if raw in masked], masked


@pytest.mark.parametrize("text", _CASES["keep"])
def test_agent_leaves_benign_text_alone(text) -> None:
    assert mask_secret_values(text, _PLACEHOLDER) == text
