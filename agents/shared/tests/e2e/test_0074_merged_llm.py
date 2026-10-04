"""Feature 0074 review item 3 (contract C3), end to end on the agent side.

A same-agent skill/LLM pair — the model echoes the skill's ``check_id`` in the
same file — collapses inside the agent before Go sees it. The surviving skill
row must leave the agent carrying ``merged_llm`` on the ``result`` snapshot,
through the validate stage, in the wire shape Go decodes:
``[{"provenance": str, "description": str}]``. Go's cross-agent merge folds it
into ``validation.provenance_origins`` / ``merged_descriptions``.

The model is never called; the real batch loop, final dedup and validate stage
run. All fixtures are synthetic.
"""

from __future__ import annotations

import json

from tests.unit.test_0074_agent_dedup_counters import (
    SKILL_CHECK_ID,
    _check_id_rows,
    _llm_env,
    _run,
)


def test_check_id_echo_pair_reaches_the_result_with_merged_llm(monkeypatch, tmp_path) -> None:
    _llm_env(monkeypatch, tmp_path, _check_id_rows)
    monkeypatch.delenv("VULTURE_DISABLE_VALIDATE")
    payload = json.loads(json.dumps(_run(tmp_path, "0074-c3-e2e", use_llm=True)))
    survivors = [f for f in payload["findings"]
                 if f.get("check_id") == SKILL_CHECK_ID and f.get("provenance") == "skill"]
    assert len(survivors) == 1
    assert survivors[0]["merged_llm"] == [{"provenance": "llm", "description": "model reasoning"}]
    assert "validation" in survivors[0], "the row went through the validate stage"
