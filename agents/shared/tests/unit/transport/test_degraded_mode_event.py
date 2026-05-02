"""Feature 0043 v1.1: degraded_mode SSE event emitter helper.

The event is consumed by the frontend banner (feature 0039's
LLMDegradedBanner component is already SSE-event-aware via
useLLMHealth, but the per-audit banner mode is the new one). Backend
agui/translator.go passes the event through generically — no
backend code change required for new event types.
"""

from __future__ import annotations

from shared.transport.event_emitter import AgUiEventEmitter


class TestDegradedModeEvent:
    def test_emits_event_with_canonical_shape(self):
        em = AgUiEventEmitter("test-run-1")
        raw = em.degraded_mode(
            "LLM unavailable: openai (gpt-4o) at https://api.openai.com — connection refused. Audit will run skills-only."
        )
        assert "degraded_mode" in raw
        assert "Audit will run skills-only" in raw
        assert "test-run-1" in raw

    def test_default_audit_mode_is_degraded(self):
        em = AgUiEventEmitter("run-2")
        raw = em.degraded_mode("LLM down")
        assert "degraded" in raw
        # The literal "audit_mode" key must appear in the JSON.
        assert "audit_mode" in raw

    def test_audit_mode_skills_only_explicit(self):
        em = AgUiEventEmitter("run-3")
        raw = em.degraded_mode(
            "Operator opted out of LLM (VULTURE_USE_LLM != true)",
            audit_mode="skills_only",
        )
        assert "skills_only" in raw

    def test_audit_mode_required_failed(self):
        em = AgUiEventEmitter("run-4")
        raw = em.degraded_mode(
            "VULTURE_REQUIRE_LLM=true but LLM unreachable",
            audit_mode="required_failed",
        )
        assert "required_failed" in raw

    def test_message_passes_through(self):
        em = AgUiEventEmitter("run-5")
        msg = "Custom message marker XYZZY"
        raw = em.degraded_mode(msg)
        assert msg in raw
