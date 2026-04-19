"""Tests for ASVS agent memory-system integration.

Verifies end-to-end DRY behavior:
1. Prior findings flow into the LLM context as "Known issues: ..."
2. agent_type="asvs" is the consistent filter key
3. Preloaded path avoids redundant HTTP round-trips
4. Findings emitted by the skill have the fields needed for memory
   persistence by the Go backend (StoreFindingsAsMemories)
5. Identical repeated audits on unchanged code produce deterministic
   output (no re-analysis side effects)
"""
from unittest.mock import patch

import pytest

from asvs_agent.agent import run_audit


@pytest.fixture
def tmp_source(tmp_path):
    """Source tree with one known-violation file."""
    (tmp_path / "app.py").write_text("password = 'hunter2_admin'\n")
    return tmp_path


def _events(run_audit_gen):
    return [str(e) for e in run_audit_gen]


def test_prior_findings_preloaded_path_skips_http(tmp_source):
    """When prior_findings is provided, build_prior_context must NOT
    call memory_get_context (no HTTP round-trip)."""
    preloaded = [
        {
            "id": "mem-1",
            "title": "ASVS V13.3.1 violation",
            "category": "ASVS-V13.3.1",
            "agent_type": "asvs",
            "file_path": "app.py",
            "severity": "critical",
            "description": "hardcoded credential detected",
        }
    ]
    with patch("shared.tools.memory_client.memory_get_context") as fetch:
        events = _events(run_audit(
            run_id="t",
            source_path=str(tmp_source),
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
            prior_findings=preloaded,
        ))
    fetch.assert_not_called()
    assert len(events) > 0


def test_agent_type_filter_uses_asvs_consistently(tmp_source):
    """When no preloaded findings, memory_get_context is called with
    agent_type='asvs' — ensures cross-agent findings are not mixed."""
    with patch("shared.tools.memory_client.memory_get_context", return_value=[]) as fetch:
        _events(run_audit(
            run_id="t",
            source_path=str(tmp_source),
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
            prior_findings=None,
        ))
    assert fetch.called
    # Every call must pass agent_type="asvs".
    for call_args in fetch.call_args_list:
        # memory_get_context(codebase_path, agent_type, limit)
        args, kwargs = call_args
        agent_type = args[1] if len(args) > 1 else kwargs.get("agent_type")
        assert agent_type == "asvs", f"expected agent_type='asvs', got {agent_type!r}"


def test_findings_have_fields_required_for_memory_persistence(tmp_source):
    """Backend's StoreFindingsAsMemories reads title/category/severity/
    file_path/description/recommendation — all must be present on every
    ASVS finding dict so memories have the expected shape."""
    from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements
    result = check_asvs_requirements(str(tmp_source))
    required = {"title", "category", "severity", "file_path",
                "description", "recommendation", "check_id"}
    for f in result["findings"]:
        missing = required - set(f.keys())
        assert not missing, f"finding missing fields: {missing}"
        assert f["category"].startswith("ASVS-V")
        assert f["title"]
        assert f["description"]


def test_repeated_audit_is_deterministic(tmp_source):
    """Same source + no prior findings must produce same categories
    across repeated runs — no hidden state / global mutation."""
    from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements
    r1 = check_asvs_requirements(str(tmp_source))
    r2 = check_asvs_requirements(str(tmp_source))
    cats1 = sorted(f["category"] for f in r1["findings"])
    cats2 = sorted(f["category"] for f in r2["findings"])
    assert cats1 == cats2


def test_prior_context_injected_into_llm_instructions(tmp_source):
    """The 'Known issues' prior-context line must be emitted when
    prior_findings exist — that's what the LLM sees to skip them."""
    preloaded = [{
        "id": "mem-1",
        "title": "Some prior finding",
        "category": "ASVS-V11.3.2",
        "agent_type": "asvs",
        "file_path": "x.py",
        "severity": "high",
        "description": "broken crypto found in prior audit",
    }]
    events = _events(run_audit(
        run_id="t",
        source_path=str(tmp_source),
        config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
        prior_findings=preloaded,
    ))
    joined = "\n".join(events)
    # The "Known issues" marker is what build_prior_context emits to
    # signal the LLM that prior findings are present.
    assert "Known issues" in joined or "Skip known issues" in joined


def test_memory_api_failure_degrades_gracefully(tmp_source):
    """Down memory API must not break audits — degraded mode: skills
    still run, Phase 2 LLM loses prior-context hint only."""
    with patch(
        "shared.tools.memory_client.memory_get_context",
        side_effect=Exception("memory API down"),
    ):
        events = _events(run_audit(
            run_id="t",
            source_path=str(tmp_source),
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
            prior_findings=None,
        ))
    assert len(events) > 0
    # Known-issues / Skip-known markers should NOT appear (no prior context).
    joined = "\n".join(events)
    assert "Known issues" not in joined


def test_category_format_matches_backend_fingerprint_expectation(tmp_source):
    """Backend generateFingerprint uses (title, filepath, category,
    agent_type) — category must be stable across audits to dedupe.
    The 'ASVS-V{X}.{Y}.{Z}' format is the stable fingerprint component."""
    from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements
    import re
    result = check_asvs_requirements(str(tmp_source))
    for f in result["findings"]:
        # Match ASVS-V<chapter>.<section>.<req> format.
        assert re.match(r"^ASVS-V\d+\.\d+\.\d+$", f["category"]), \
            f"non-canonical category {f['category']}"


def test_check_id_is_stable_across_runs(tmp_source):
    """check_id is the preferred dedup key (stable, hierarchical).
    Repeated scans must produce identical check_ids for the same
    finding on the same line."""
    from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements
    r1 = check_asvs_requirements(str(tmp_source))
    r2 = check_asvs_requirements(str(tmp_source))
    ids1 = sorted((f["check_id"], f["file_path"], f["line_start"]) for f in r1["findings"])
    ids2 = sorted((f["check_id"], f["file_path"], f["line_start"]) for f in r2["findings"])
    assert ids1 == ids2
