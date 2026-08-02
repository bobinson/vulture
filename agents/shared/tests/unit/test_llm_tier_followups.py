"""Three defects found by running the LLM tier against a real local gateway.

1. **The LLM phase analysed test files that every skill excludes.** 23 skill
   modules call ``is_test_file``; ``audit_runner`` called it zero times. The
   model duly read exploit tests that *demonstrate* SSTI and NoSQL injection
   and reported them as vulnerabilities — right weakness, wrong file. 9 of 22
   LLM findings on one target were test-file artefacts.

2. **The P5 transport hardening never reached the L5 judge.** Byte clamp,
   size-halving retry and 413 classification live in ``audit_runner`` and are
   absent from ``llm_judge`` — yet every observed 413 came from
   ``[validate.l5]``. The judge is the half that was actually failing.

3. **A truncated verdict was diagnosed but not survived.** On
   ``finish_reason == "length"`` the judge logged advice for a human and then
   returned the truncated text, which fails JSON parsing twice and yields "no
   verdict". A reasoning model burns the budget on hidden thinking, so this is
   the normal case for that class of model, not an edge case.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# 1. LLM phase must exclude test files
# ---------------------------------------------------------------------------


class TestLlmPhaseExcludesTestFiles:
    def test_source_context_skips_test_files(self, tmp_path: Path):
        from shared.audit_runner import _build_source_context

        (tmp_path / "app.ts").write_text(
            "export function handler (req) { return db.query(req.body.q) }\n"
        )
        (tmp_path / "app.test.ts").write_text(
            "it('is injectable', () => { db.query(`SELECT ${x}`) })\n"
        )
        (tmp_path / "test").mkdir()
        (tmp_path / "test" / "api.spec.ts").write_text("describe('x', () => {})\n")

        ctx = _build_source_context(str(tmp_path), max_chars=100_000)
        assert "app.ts" in ctx, "real source must still be sent"
        assert "app.test.ts" not in ctx, (
            "a test file reaching the prompt makes the model report the "
            "vulnerability the test demonstrates, anchored in the test"
        )
        assert "api.spec.ts" not in ctx

    def test_generated_files_are_also_excluded(self, tmp_path: Path):
        from shared.audit_runner import _build_source_context

        (tmp_path / "real.ts").write_text("const a = 1\n")
        (tmp_path / "bundle.min.js").write_text("var a=1;" * 500 + "\n")
        ctx = _build_source_context(str(tmp_path), max_chars=100_000)
        assert "real.ts" in ctx
        assert "bundle.min.js" not in ctx


# ---------------------------------------------------------------------------
# 2. L5 judge carries the P5 transport hardening
# ---------------------------------------------------------------------------


class TestJudgeTransportHardening:
    def test_oversized_user_message_is_clamped_before_send(self):
        from shared.validate.llm_judge import _clamp_request_body

        big = "x" * 400_000
        out = _clamp_request_body(big, max_bytes=64_000)
        assert len(out.encode("utf-8")) <= 64_000, (
            "the judge must enforce a byte ceiling; a token budget cannot bound "
            "a request BODY, which is what the gateway rejects"
        )

    def test_clamp_leaves_a_small_body_untouched(self):
        from shared.validate.llm_judge import _clamp_request_body

        small = "verdict please"
        assert _clamp_request_body(small, max_bytes=64_000) == small

    def test_size_errors_are_classified_not_swallowed(self):
        from shared.llm.errors import LLMErrorKind
        from shared.validate.llm_judge import _is_size_error

        for msg in (
            "Error code: 413 - {'code': 'request_too_large'}",
            "litellm.APIError: OpenAIException - request body too large",
        ):
            assert _is_size_error(RuntimeError(msg)), f"unclassified size error: {msg}"
        assert not _is_size_error(RuntimeError("malformed request body"))
        assert LLMErrorKind is not None


# ---------------------------------------------------------------------------
# 3. A truncated verdict must be retried, not merely diagnosed
# ---------------------------------------------------------------------------


class TestTruncatedVerdictIsRetried:
    def test_length_finish_triggers_a_larger_retry(self, monkeypatch):
        """The reasoning-model case: first call truncates, second must widen."""
        from shared.validate import llm_judge

        budgets: list[int] = []

        class _Msg:
            content = ""

        class _Choice:
            finish_reason = "length"
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        class _Good(_Resp):
            class _M:
                content = '{"verdicts": []}'
            choices = [type("C", (), {"finish_reason": "stop", "message": _M()})()]

        def fake_create(**kw):
            # Both modes truncate at the base budget (calls 1-2); only the
            # widened retry succeeds. That is the real reasoning-model shape.
            budgets.append(kw.get("max_tokens", 0))
            return _Resp() if len(budgets) <= 2 else _Good()

        client = type(
            "C", (), {"chat": type("X", (), {"completions": type(
                "Y", (), {"create": staticmethod(fake_create)})()})()},
        )()
        monkeypatch.setattr(llm_judge, "_get_client", lambda: client)
        out = llm_judge._call_llm("sys", "user", timeout_s=5, model="m")
        assert len(budgets) >= 3, "both modes must be tried, then a widened retry"
        assert max(budgets) > budgets[0], (
            f"the retry must widen the token budget, got {budgets}"
        )
        assert out, "the widened retry's content must be returned"


def test_reasoning_default_budget_is_not_the_measured_failure_point():
    """4000 was measured truncating on a reasoning model; the default must move."""
    from shared.validate.llm_judge import _DEFAULT_MAX_OUTPUT_TOKENS

    assert _DEFAULT_MAX_OUTPUT_TOKENS > 4000, (
        "the shipped default still truncates the model class this was found on"
    )
