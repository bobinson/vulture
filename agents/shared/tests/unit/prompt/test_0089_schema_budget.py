"""Feature 0089 Phase 0.c — the output schema and the token budget.

Both modules exist to remove a number or a field list from prose. A prompt
that *describes* its own contract in a sentence has two copies of it (the
sentence and the parser); these tests pin the single copy.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from shared import audit_runner
from shared.prompt.budget import (
    DEFAULT_MAX_TOOL_CALLS,
    TOOL_SCHEMA_TOKENS,
    TokenBudget,
    budget_for,
)
from shared.prompt.profile import profile_for
from shared.prompt.schema import FINDING_SCHEMA, VERDICT_SCHEMA, OutputSchema


class TestOutputSchema:
    def test_schema_field_list_matches_code(self):
        """FINDING_SCHEMA is the GENERATE contract, not a second opinion of it.

        Asserted against the constant audit_runner actually whitelists, so a
        field added or dropped there fails HERE rather than shipping a prompt
        that asks for a field the parser discards.
        """
        from shared.audit_runner import _MODEL_VISIBLE_FIELDS

        expected = frozenset(_MODEL_VISIBLE_FIELDS) | {"evidence_quote"}
        assert FINDING_SCHEMA.field_names() == expected
        # Order is the contract too: the prose sentence is read left to right.
        assert FINDING_SCHEMA.as_field_list().split(", ")[:len(_MODEL_VISIBLE_FIELDS)] == \
            list(_MODEL_VISIBLE_FIELDS)

    def test_schema_renders_three_ways(self):
        """One definition, three renderings — prose, JSON Schema, name set."""
        prose = FINDING_SCHEMA.as_field_list()
        js = FINDING_SCHEMA.as_json_schema()
        names = FINDING_SCHEMA.field_names()

        assert isinstance(prose, str)
        assert prose.startswith("severity, category, title, description")
        assert "{" not in prose            # prose, not JSON

        assert isinstance(js, dict)
        assert js["name"] == FINDING_SCHEMA.id
        item = js["schema"]["properties"][FINDING_SCHEMA.array_key]["items"]
        assert set(item["properties"]) == set(names)
        assert item["properties"]["line_start"]["type"] == "integer"
        assert item["properties"]["title"]["type"] == "string"
        assert item["additionalProperties"] is False

        assert isinstance(names, frozenset)
        # The three renderings agree on the field set.
        assert set(prose.split(", ")) == set(names) == set(item["properties"])

    def test_verdict_schema_is_the_judge_shape(self):
        """`_coerce_verdict` rebuilds a whitelisted dict; this is that whitelist."""
        assert VERDICT_SCHEMA.field_names() == frozenset({
            "id", "exploitable", "window_sufficient", "evidence_line", "reasoning",
        })
        props = VERDICT_SCHEMA.as_json_schema()["schema"]["properties"][
            VERDICT_SCHEMA.array_key]["items"]["properties"]
        assert props["exploitable"]["type"] == "number"
        assert props["window_sufficient"]["type"] == "boolean"
        assert props["evidence_line"]["type"] == "integer"

    def test_lint_reads_field_names(self):
        """check_01_orphan_field's `spec.schema_fields` is fed from here."""
        from shared.prompt.lint import check_01_orphan_field
        from shared.prompt.spec import PromptSpec

        spec = PromptSpec(id="s", tier="generate", fragments=(),
                          schema_fields=tuple(sorted(FINDING_SCHEMA.field_names())))
        assert check_01_orphan_field(spec, None) == []

    def test_empty_schema_is_refused(self):
        with pytest.raises(ValueError):
            OutputSchema(id="empty", array_key="rows", fields=())


class TestTokenBudget:
    def _profile(self, model: str, window: int = 128_000):
        """Same window for both, so only the overhead differs."""
        return dataclasses.replace(profile_for(model), ctx_window=window)

    def test_budget_subtracts_reasoning_overhead(self):
        """A reasoning model burns tokens before emitting anything; that is a
        subtraction, never a sentence asking it not to think."""
        qwen = self._profile("qwen/qwen3.6-35b-a3b")
        openai = self._profile("gpt-4o")
        assert qwen.reasoning_overhead_tokens == 700
        assert openai.reasoning_overhead_tokens == 0

        b_q = budget_for(qwen, prompt_chars=40_000, n_tools=3)
        b_o = budget_for(openai, prompt_chars=40_000, n_tools=3)
        assert b_q.headroom == b_o.headroom
        assert b_o.max_output - b_q.max_output == 700

    def test_budget_counts_tool_schema_tokens(self):
        prof = self._profile("gpt-4o")
        b24 = budget_for(prof, prompt_chars=40_000, n_tools=24)
        assert b24.tool_schema_tokens == 24 * TOOL_SCHEMA_TOKENS
        assert TOOL_SCHEMA_TOKENS == 150

        b0 = budget_for(prof, prompt_chars=40_000, n_tools=0)
        assert b0.tool_schema_tokens == 0
        assert b0.headroom - b24.headroom == 24 * TOOL_SCHEMA_TOKENS

    def test_tool_call_budget_comes_from_judge_tools(self):
        from shared.validate.judge_tools import (
            DEFAULT_MAX_TOOL_CALLS as CODE_DEFAULT,
        )

        assert DEFAULT_MAX_TOOL_CALLS == CODE_DEFAULT
        prof = self._profile("gpt-4o")
        assert budget_for(prof, prompt_chars=1_000, n_tools=3).tool_call_budget == \
            CODE_DEFAULT
        # No tools attached ⇒ no tool calls to budget for.
        assert budget_for(prof, prompt_chars=1_000, n_tools=0).tool_call_budget == 0

    def test_budget_never_goes_negative(self):
        """An oversized prompt yields a floor, not a negative max_tokens the
        provider would reject."""
        prof = self._profile("qwen/qwen3.6-35b-a3b", window=4_096)
        b = budget_for(prof, prompt_chars=4_000_000, n_tools=24)
        assert b.headroom == 0
        assert b.max_output == TokenBudget.MIN_OUTPUT_TOKENS


class TestProseContractIsReproducible:
    """Phase 1 must reproduce today's prompt BYTE for byte (0089 §4, TRANSCRIBE).

    The shipped prose contract exists in two places and neither is the
    9-name list ``as_field_list()`` returns:

    * ``_field_contract()`` names the eight required fields and appends the
      quote as a SEPARATE, ``_quote_required()``-GATED obligation sentence.
    * the unstructured branch (``audit_runner.py:3295``) names the same eight
      as a plain comma list.

    ``evidence_quote`` is therefore not a member of either sentence's list.
    Folding it in changes policy as well as bytes: it asks for the quote even
    when ``VULTURE_LLM_QUOTE_REQUIRED`` is off, and it reduces the obligation
    ("copy the 1-3 source lines ... VERBATIM ... reported as unverified") to a
    bare field name. These tests pin the rendering Phase 1 can actually use.
    """

    # Transcribed byte-exactly from audit_runner.py:3294-3296. The test below
    # asserts this string is still present in the source, so it cannot drift
    # silently into a stale copy of the sentence it is standing in for.
    COPY_B = (
        "IMPORTANT: Return findings as a JSON array. Each object must have: "
        "severity, category, title, description, file_path, line_start, line_end, recommendation. "
        "Wrap the array in ```json ... ``` fences."
    )

    @staticmethod
    def _sequence(text: str, vocabulary) -> list[str]:
        """Schema field names appearing in `text`, in order of appearance."""
        pattern = re.compile(
            r"\b(" + "|".join(re.escape(n) for n in vocabulary) + r")\b")
        return pattern.findall(text)

    def test_copy_b_is_still_in_the_source(self):
        """The transcription above must still be what audit_runner ships."""
        src = Path(audit_runner.__file__).read_text(encoding="utf-8")
        collapsed = re.sub(r'"\s*\n\s*"', "", src)   # join adjacent literals
        assert self.COPY_B in collapsed

    def test_prose_rendering_is_byte_exact_in_the_shipped_sentence(self):
        """The prose rendering must be a VERBATIM substring of the real sentence.

        A rendering that is merely 'about right' cannot transcribe; one
        character of drift is a different prompt.
        """
        assert FINDING_SCHEMA.as_required_field_list() in self.COPY_B

    def test_prose_rendering_matches_field_contract_order(self):
        """`_field_contract()`'s own sentence names the same eight, in order."""
        sentence = " ".join(audit_runner._field_contract()[:2])
        vocab = FINDING_SCHEMA.field_names()
        assert self._sequence(sentence, vocab) == \
            FINDING_SCHEMA.as_required_field_list().split(", ")

    def test_quote_is_not_a_member_of_the_prose_list(self):
        """`evidence_quote` is a gated obligation sentence, not a list member.

        It stays in the SCHEMA (the field is asked for, and json_schema admits
        it) while staying out of the prose list, which is what lets one
        definition serve both without asking for the quote unconditionally.
        """
        assert "evidence_quote" not in FINDING_SCHEMA.as_required_field_list()
        assert "evidence_quote" in FINDING_SCHEMA.field_names()
        sentence = " ".join(audit_runner._field_contract()[:2])
        assert "evidence_quote" not in sentence


def test_budget_tool_call_default_matches_code():
    """The drift guard for the one constant budget.py transcribes.

    Importing it for real costs 626 ms and 1520 modules (vs 35 ms / 120 for the
    rest of the library) because `shared/validate/__init__.py` eagerly pulls in
    llm_judge — and it inverts the dependency the prompt library exists to
    establish. So the value is transcribed and this test is what keeps it true.
    """
    from shared.prompt.budget import DEFAULT_MAX_TOOL_CALLS as transcribed
    from shared.validate.judge_tools import DEFAULT_MAX_TOOL_CALLS as real

    assert transcribed == real, (
        "shared/prompt/budget.py's transcribed DEFAULT_MAX_TOOL_CALLS drifted "
        f"from judge_tools ({transcribed} != {real})"
    )
