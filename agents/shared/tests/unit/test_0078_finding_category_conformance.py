"""Every agent's emitted `category` must belong to a declared vocabulary.

Feature 0078 track B. `ALL_CATEGORIES` is the SELECTOR vocabulary (what a caller
switches on in config_schema). The `category` FIELD on a finding is a different
thing, and four of six audited agents proved the two are unrelated -- asvs
declares `["asvs_requirements"]` and emits `ASVS-V12.1.1`.

So conformance is per-agent, and the vocabulary is either a SET (small, closed:
ssdf/soc2/chaos) or a SHAPE (open: cwe's 846-id catalog, asvs's requirement
ids). A single fleet-wide set would be wrong.

This test reads the literals each agent's skills actually emit and checks them
against that agent's declaration. It is a STATIC check on source, deliberately:
five of the six agents have no per-agent corpus fixtures to run, and a static
assertion catches the drift at the point it is introduced.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

AGENTS = pathlib.Path(__file__).resolve().parents[3]

def _category_literals(source: str) -> set[str]:
    """Literal `category` values in dict displays, via AST.

    NOT a regex over source: a regex also matches the string inside a COMMENT
    or DOCSTRING, and several skills document the attestation extractor's own
    `"category": "CWE-N"` convention in prose. Those are not emissions, and a
    guard that flags them would train people to ignore it.
    """
    out: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "category"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                out.add(value.value)
    return out

# SET vocabularies: the emitted value must reduce to a declared member.
SET_VOCAB = {
    "ssdf/ssdf_agent": frozenset({"PO", "PS", "PW", "RV"}),
    "soc2/soc2_agent": frozenset({"CC6", "CC7", "CC8"}),
    "chaos_engineering/chaos_agent": frozenset(
        {"retry", "circuit_breaker", "timeout", "fallback", "blast_radius"}
    ),
}

# SHAPE vocabularies: open sets, so the value must match the shape exactly.
SHAPE_VOCAB = {
    "cwe/cwe_agent": re.compile(r"^CWE-\d{1,5}$"),
    # xss deliberately borrows the CWE vocabulary: a finding is labelled by the
    # weakness it IS, not by the agent that found it.
    "xss/xss_agent": re.compile(r"^CWE-\d{1,5}$"),
}


def _emitted(rel: str) -> set[str]:
    root = AGENTS / rel / "skills"
    if not root.is_dir():
        pytest.skip(f"{rel}: no skills directory")
    out: set[str] = set()
    for path in root.rglob("*.py"):
        out |= _category_literals(path.read_text())
    return out


@pytest.mark.parametrize("rel", sorted(SET_VOCAB))
def test_set_vocabulary_reduces(rel: str) -> None:
    """Each emitted literal must reduce to a declared member."""
    from shared.tools.category_enum import normalize_to_enum

    allowed = SET_VOCAB[rel]
    emitted = _emitted(rel)
    if not emitted:
        pytest.skip(f"{rel}: no category literals found")
    bad = {c for c in emitted if normalize_to_enum(c, allowed) not in allowed}
    assert not bad, (
        f"{rel} emits {sorted(bad)}, which do not reduce to any of "
        f"{sorted(allowed)}. Either declare the value or emit a declared one — "
        f"a category no consumer can filter on is free text."
    )


@pytest.mark.parametrize("rel", sorted(SHAPE_VOCAB))
def test_shape_vocabulary_matches(rel: str) -> None:
    """Each emitted literal must match the agent's declared shape."""
    shape = SHAPE_VOCAB[rel]
    emitted = _emitted(rel)
    if not emitted:
        pytest.skip(f"{rel}: no category literals found")
    bad = {c for c in emitted if not shape.match(c)}
    assert not bad, f"{rel} emits {sorted(bad)}, which do not match {shape.pattern}"


def test_every_declared_agent_is_covered() -> None:
    """A new agent must not silently escape this guard."""
    known = set(SET_VOCAB) | set(SHAPE_VOCAB)
    # Agents with no static category literals (LLM-only or crosswalk-driven)
    # are recorded here so the omission is a DECISION, not an oversight.
    exempt = {
        "asvs/asvs_agent",      # ids come from the ASVS crosswalk data, not literals
        "owasp/owasp_agent",    # categorizer: re-labels other agents' findings
        "do178c/do178c_agent",  # objective ids come from data tables
        "discover/discover_agent",
        "prove/prove_agent",
    }
    present = {
        f"{p.parent.name}/{p.name}"
        for p in AGENTS.glob("*/[a-z]*_agent")
        if p.is_dir()
    }
    unaccounted = present - known - exempt
    assert not unaccounted, (
        f"agents not covered by the category conformance guard: "
        f"{sorted(unaccounted)}. Add a SET_VOCAB / SHAPE_VOCAB entry, or an "
        f"exempt entry saying why the agent has no static category literals."
    )
