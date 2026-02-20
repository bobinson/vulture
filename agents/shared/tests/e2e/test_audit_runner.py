"""E2E tests for shared.audit_runner business logic.

These tests define the business contract for how the audit runner handles
prior findings context. The CRITICAL invariant: findings must NEVER be
silently dropped from results. Prior context is informational — it must
not cause the runner to remove findings or inflate the compliance score.
"""

import json

import pytest

from shared.audit_runner import run_skill_audit


def _sql_injection_skill(source_path: str) -> dict:
    """Stub skill that always returns a SQL injection finding."""
    return {
        "findings": [
            {
                "severity": "critical",
                "category": "A03-injection",
                "title": "Potential SQL injection",
                "description": "String interpolation in SQL query at line 5",
                "file_path": f"{source_path}/db.py",
                "line_start": 5,
                "line_end": 5,
                "recommendation": "Use parameterized queries",
            }
        ]
    }


def _weak_crypto_skill(source_path: str) -> dict:
    """Stub skill that always returns a weak crypto finding."""
    return {
        "findings": [
            {
                "severity": "high",
                "category": "A02-crypto-failure",
                "title": "Weak cryptographic algorithm",
                "description": "Weak crypto at line 3",
                "file_path": f"{source_path}/auth.py",
                "line_start": 3,
                "line_end": 3,
                "recommendation": "Use AES-256-GCM",
            }
        ]
    }


def _parse_result_event(events: list[str]) -> dict:
    """Extract the result event data from a list of SSE event strings."""
    for event in events:
        if "event: result" in event:
            data_line = [l for l in event.split("\n") if l.startswith("data:")][0]
            return json.loads(data_line[5:])
    raise AssertionError("No result event found in SSE output")


class TestSkillAuditWithPriorContext:
    """E2E tests verifying that prior context does NOT remove findings from results."""

    def test_findings_retained_when_all_match_prior_context(self, tmp_path):
        """When ALL findings match prior context, they must still appear in the result.

        This is the core business logic bug: re-scanning a codebase must NOT
        show 100% compliance just because findings were seen before.
        """
        prior_context = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues. Report NEW findings only."
        )
        skill_map = {"injection": _sql_injection_skill}

        events = list(run_skill_audit(
            run_id="test-prior-1",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map=skill_map,
            prior_context=prior_context,
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) >= 1, "Findings must NOT be dropped by dedup"
        assert result["findings"][0]["title"] == "Potential SQL injection"

    def test_score_reflects_findings_even_when_all_match_prior(self, tmp_path):
        """Score must reflect actual findings, not just 'new' ones.

        A re-scan of unchanged code must NOT return 100% compliance.
        """
        prior_context = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues. Report NEW findings only."
        )
        skill_map = {"injection": _sql_injection_skill}

        events = list(run_skill_audit(
            run_id="test-prior-2",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map=skill_map,
            prior_context=prior_context,
        ))

        result = _parse_result_event(events)
        assert result["score"] < 100.0, (
            f"Score must not be 100% when critical findings exist, got {result['score']}"
        )

    def test_multiple_findings_all_matching_prior_are_retained(self, tmp_path):
        """Multiple findings matching prior context must all be retained."""
        prior_context = (
            "Known issues (2):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            " H:[A02-crypto-failure] Weak cryptographic algorithm @auth.py\n"
            "Skip known issues. Report NEW findings only."
        )
        skill_map = {
            "injection": _sql_injection_skill,
            "crypto_failure": _weak_crypto_skill,
        }

        events = list(run_skill_audit(
            run_id="test-prior-3",
            source_path=str(tmp_path),
            categories=["injection", "crypto_failure"],
            skill_map=skill_map,
            prior_context=prior_context,
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) == 2, (
            f"Expected 2 findings retained, got {len(result['findings'])}"
        )

    def test_no_prior_context_still_works(self, tmp_path):
        """Without prior context, findings and score work as normal."""
        skill_map = {"injection": _sql_injection_skill}

        events = list(run_skill_audit(
            run_id="test-no-prior",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map=skill_map,
            prior_context="",
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) == 1
        assert result["score"] < 100.0


# ---------------------------------------------------------------------------
# Stub helpers for exception handling tests
# ---------------------------------------------------------------------------


def _working_skill(source_path: str) -> dict:
    """Stub skill that always returns a single finding."""
    return {
        "findings": [
            {
                "severity": "critical",
                "category": "A03-injection",
                "title": "SQL Injection",
                "description": "Found at line 5",
                "file_path": f"{source_path}/db.py",
                "line_start": 5,
                "line_end": 5,
                "recommendation": "Fix it",
            }
        ]
    }


def _failing_skill(source_path: str) -> dict:
    """Stub skill that always raises an exception."""
    raise RuntimeError("Skill crashed unexpectedly")


# ---------------------------------------------------------------------------
# Exception handling tests for run_skill_audit
# ---------------------------------------------------------------------------


class TestSkillExceptionHandling:
    """E2E tests: a failing skill must NOT crash the audit."""

    def test_failing_skill_returns_partial_results(self, tmp_path):
        """When one skill raises, the other skill's findings are still in the result."""
        skill_map = {
            "injection": _working_skill,
            "crypto": _failing_skill,
        }

        events = list(run_skill_audit(
            run_id="test-exc-partial",
            source_path=str(tmp_path),
            categories=["injection", "crypto"],
            skill_map=skill_map,
            prior_context="",
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) == 1, (
            f"Expected 1 finding from working skill, got {len(result['findings'])}"
        )
        assert result["findings"][0]["title"] == "SQL Injection"

    def test_failing_skill_emits_error_event(self, tmp_path):
        """A skill exception should emit a text_message with the error."""
        skill_map = {
            "injection": _working_skill,
            "crypto": _failing_skill,
        }

        events = list(run_skill_audit(
            run_id="test-exc-error-event",
            source_path=str(tmp_path),
            categories=["injection", "crypto"],
            skill_map=skill_map,
            prior_context="",
        ))

        # Flatten all event text to search for error indication
        all_event_text = "\n".join(events).lower()
        assert "failed" in all_event_text or "error" in all_event_text, (
            "Expected an error/failed message in SSE events when a skill crashes"
        )

    def test_all_skills_failing_returns_empty_findings(self, tmp_path):
        """When all skills fail, result should have 0 findings and score 100."""
        skill_map = {
            "crypto": _failing_skill,
            "misconfig": _failing_skill,
        }

        events = list(run_skill_audit(
            run_id="test-exc-all-fail",
            source_path=str(tmp_path),
            categories=["crypto", "misconfig"],
            skill_map=skill_map,
            prior_context="",
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) == 0, (
            f"Expected 0 findings when all skills fail, got {len(result['findings'])}"
        )
        assert result["score"] == 100.0, (
            f"Expected score 100.0 with no findings, got {result['score']}"
        )


# ---------------------------------------------------------------------------
# Exception handling tests for run_combined_audit
# ---------------------------------------------------------------------------


from shared.audit_runner import run_combined_audit


class TestCombinedAuditExceptionHandling:
    """E2E tests: run_combined_audit handles skill exceptions."""

    def test_combined_failing_skill_returns_partial(self, tmp_path, monkeypatch):
        """When one skill raises in combined mode, working skill findings are retained."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        skill_map = {
            "injection": _working_skill,
            "crypto": _failing_skill,
        }

        events = list(run_combined_audit(
            run_id="test-combined-exc-partial",
            source_path=str(tmp_path),
            categories=["injection", "crypto"],
            skill_map=skill_map,
            prior_context="",
        ))

        result = _parse_result_event(events)
        assert len(result["findings"]) == 1, (
            f"Expected 1 finding from working skill, got {len(result['findings'])}"
        )
        assert result["findings"][0]["title"] == "SQL Injection"

    def test_combined_failing_skill_emits_error(self, tmp_path, monkeypatch):
        """A skill exception in combined mode should emit an error message in events."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        skill_map = {
            "injection": _working_skill,
            "crypto": _failing_skill,
        }

        events = list(run_combined_audit(
            run_id="test-combined-exc-error",
            source_path=str(tmp_path),
            categories=["injection", "crypto"],
            skill_map=skill_map,
            prior_context="",
        ))

        all_event_text = "\n".join(events).lower()
        assert "failed" in all_event_text or "error" in all_event_text, (
            "Expected an error/failed message in SSE events when a skill crashes"
        )
