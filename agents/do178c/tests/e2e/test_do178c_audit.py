"""E2E tests for DO-178C audit agent."""

import json

from do178c_agent.agent import run_audit


def _collect_events(gen):
    return list(gen)


class TestDO178CAuditE2E:
    def test_full_audit_default_dal_c(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def process():\n    return 1\n    dead_code()\n\n"
            "items = []\nfor x in range(10):\n    items.append(x)\n"
        )
        events = _collect_events(run_audit("run-1", str(tmp_path), {"dal_level": "C"}))
        assert any("agent_start" in e for e in events)
        assert any("agent_end" in e for e in events)
        assert any("dead_code" in e for e in events)

    def test_dal_e_skips_all_skills(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def process():\n    return 1\n    dead_code()\n"
        )
        events = _collect_events(run_audit("run-2", str(tmp_path), {"dal_level": "E"}))
        # DAL E skips all skills — should still have start/finish but no findings
        assert any("agent_start" in e for e in events)
        assert any("agent_end" in e for e in events)
        # No skill-produced finding events
        finding_events = [e for e in events if "event: finding" in e]
        assert len(finding_events) == 0

    def test_dal_a_detects_malloc_and_recursion(self, tmp_path):
        (tmp_path / "app.c").write_text(
            "void* buf = malloc(1024);\n"
            "int fact(int n) { return n * fact(n-1); }\n"
        )
        events = _collect_events(run_audit("run-3", str(tmp_path), {"dal_level": "A"}))
        event_text = "\n".join(events)
        assert "malloc" in event_text or "dynamic_alloc" in event_text
        assert "recursion" in event_text

    def test_category_filter_limits_skills(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def f():\n    return 1\n    dead()\n"
            "import time\ntime.sleep(1)\n"
        )
        events = _collect_events(
            run_audit("run-4", str(tmp_path), {"dal_level": "C", "categories": ["dead_code"]})
        )
        event_text = "\n".join(events)
        assert "dead_code" in event_text
        # timing is not in the requested categories, should not appear
        assert "do178c.timing" not in event_text
