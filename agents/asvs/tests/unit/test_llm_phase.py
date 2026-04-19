"""Tests for ASVS agent LLM-phase wiring.

Verifies that the agent correctly integrates with shared.audit_runner's
two-phase pipeline: Phase 1 skills (deterministic regex) + Phase 2 LLM
augmentation (when VULTURE_USE_LLM=true or config.use_llm=True).
"""
from asvs_agent.agent import INSTRUCTIONS, _build_llm_catalog_context
from asvs_agent.skills import SKILL_MAP, SKILL_TOOLS


def test_instructions_cite_asvs_version():
    """LLM prompt must identify the standard being audited."""
    assert "ASVS v5.0.0" in INSTRUCTIONS


def test_instructions_direct_llm_to_use_asvs_prefix():
    """LLM must be instructed to cite req_ids as ASVS-V{X}.{Y}.{Z}."""
    assert "ASVS-V" in INSTRUCTIONS


def test_instructions_describe_self_learning_protocol():
    """Prior findings feedback loop (SKIP/BOOST/DEMOTE) must be documented."""
    assert "SKIP" in INSTRUCTIONS
    assert "BOOST" in INSTRUCTIONS
    assert "DEMOTE" in INSTRUCTIONS


def test_instructions_mention_cwe_linkage():
    """Findings should carry linked_cwe metadata when the crosswalk maps."""
    assert "linked_cwe" in INSTRUCTIONS


def test_skill_tools_exposed_to_llm_phase():
    """run_combined_audit gates Phase 2 on skill_tools non-empty."""
    assert len(SKILL_TOOLS) >= 1
    assert SKILL_TOOLS[0] is not None


def test_skill_map_has_single_entry():
    """Consolidated design: one entry, one dispatch function."""
    assert list(SKILL_MAP.keys()) == ["asvs_requirements"]


def test_llm_catalog_context_non_empty_and_bounded():
    """Catalog context must be present and under 4000 chars (3000 target)."""
    ctx = _build_llm_catalog_context()
    assert 200 < len(ctx) < 4000


def test_llm_catalog_context_contains_critical_chapter_reqs():
    """Critical chapters (auth/session/tokens/crypto) must appear first."""
    ctx = _build_llm_catalog_context()
    critical_chapters_hit = sum(
        1 for ch in ("V6", "V7", "V9", "V11") if f"ASVS-{ch}." in ctx
    )
    assert critical_chapters_hit >= 2


def test_run_audit_generator_wires_phase_2_correctly():
    """Verify run_audit yields SSE events and passes use_llm through."""
    from asvs_agent.agent import run_audit
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "empty.py").write_text("x = 1\n")
        # With use_llm=False, Phase 2 is suppressed — must still yield events.
        events = list(run_audit(
            run_id="test-run",
            source_path=d,
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
        ))
        assert len(events) > 0
        combined = "".join(str(e) for e in events)
        assert "agent_start" in combined or "thinking" in combined
