"""An agent that DECLARES a category vocabulary must name it to the model.

Track B conformed categories post hoc and the normaliser deliberately never
guesses -- correct for `PW-3.3` -> `PW`, useless for prose. With the LLM tier
finally running to completion, soc2 emitted NINE categories:

    CC6, CC7, CC8, 'Access Logging', 'Monitoring', 'Change Management',
    'Data Retention', 'API Design / Access Control', 'Encryption / Access Control'

The six prose labels have no declared prefix, so they reduce to nothing and pass
straight through. chaos looked clean only because its LLM values happened to be
separator variants of declared names, which DO reduce.

Prevention at the source; the normaliser stays as the net. Neither alone is
enough: a prompt cannot bind a model, and the normaliser cannot rescue a label
with nothing to reduce.
"""

import asyncio
from dataclasses import dataclass, field

from shared.audit_runner import _category_vocabulary_suffix


class TestSuffixContent:
    def test_names_every_declared_value(self):
        s = _category_vocabulary_suffix(frozenset({"CC6", "CC7", "CC8"}))
        assert "CC6" in s and "CC7" in s and "CC8" in s

    def test_values_are_sorted_for_determinism(self):
        # A set has no order; an unstable prompt defeats prompt caching and
        # makes two identical audits produce different requests.
        a = _category_vocabulary_suffix(frozenset({"PW", "PO", "RV", "PS"}))
        b = _category_vocabulary_suffix(frozenset({"RV", "PS", "PO", "PW"}))
        assert a == b

    def test_instructs_exact_use(self):
        s = _category_vocabulary_suffix(frozenset({"CC6"})).lower()
        assert "category" in s and ("exactly" in s or "only" in s)

    def test_empty_vocabulary_adds_nothing(self):
        assert _category_vocabulary_suffix(frozenset()) == ""

    def test_none_adds_nothing(self):
        assert _category_vocabulary_suffix(None) == ""


class TestProseLabelsAreWhatThisTargets:
    def test_the_measured_soc2_prose_labels_are_not_declared(self):
        """Documents WHY the prompt is needed: these reduce to nothing."""
        from shared.tools.category_enum import normalize_to_enum

        allowed = frozenset({"CC6", "CC7", "CC8"})
        for prose in ("Access Logging", "Monitoring", "Change Management",
                      "Data Retention", "API Design / Access Control"):
            assert normalize_to_enum(prose, allowed) == prose, (
                f"{prose!r} unexpectedly reduces; the prompt fix would be moot"
            )


# ── AC13.2 second clause: the wiring, read from the RENDERED prompt ──────────
#
# `_category_vocabulary_suffix` above is asserted as a pure function, which says
# nothing about whether anything ever CALLS it. Deleting the call site in
# `_collect_llm_findings_async` leaves the whole shared suite green, so the only
# guard that can fail on that mutation is one that reads what the model is
# actually shown. Same harness shape as 0076's AC9 (test_0076_obligation.py:88):
# the SDK is stubbed, so this is prompt assembly only -- no network, no model.

@dataclass
class _Shown:
    """What one real LLM call put in front of the model."""

    prompt: str = ""            # user message (builder output)
    instructions: str = ""      # system message (Agent instructions kwarg)
    agent_kwargs: dict = field(default_factory=dict)


_AGENT_INSTRUCTIONS = "You are a SOC2 auditor."


def _capture_with_enum(monkeypatch, tmp_path, *, structured: bool,
                       enum: frozenset[str]) -> _Shown:
    """Render one batch with a declared vocabulary bound to this context.

    The branch is pinned EXPLICITLY on both sides (0076 D7): a stray
    ``OPENAI_BASE_URL`` in the developer's environment turns structured output
    off, which would test the unstructured branch twice and report the
    structured contract as covered when it never rendered.
    """
    import agents as agents_sdk

    from shared import audit_runner

    shown = _Shown()

    class _FakeAgent:
        def __init__(self, **kwargs):
            shown.agent_kwargs = kwargs
            shown.instructions = kwargs.get("instructions", "")

    class _FakeResult:
        final_output = "[]"

    class _FakeRunner:
        @staticmethod
        async def run(_agent, input: str = "", **_kwargs):  # SDK's own kwarg name
            shown.prompt = input
            return _FakeResult()

    monkeypatch.setattr(agents_sdk, "Agent", _FakeAgent)
    monkeypatch.setattr(agents_sdk, "Runner", _FakeRunner)
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr("shared.llm.provider._CUSTOM_BASE_URL", "", raising=False)
    if not structured:
        monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")

    source_root = tmp_path / "src"
    source_root.mkdir(exist_ok=True)
    (source_root / "a.ts").write_text("const a = 1;\n")

    token = audit_runner._CATEGORY_ENUM.set(enum)
    try:
        asyncio.run(
            audit_runner._collect_llm_findings_async(
                run_id="run-0078",
                source_path=str(source_root),
                categories=["access_logging"],
                skill_tools=[],
                instructions=_AGENT_INSTRUCTIONS,
                domain_label="controls",
                source_context="--- a.ts ---\n1: const a = 1;\n",
            )
        )
    finally:
        audit_runner._CATEGORY_ENUM.reset(token)
    return shown


class TestTheVocabularyReachesTheModel:
    """AC13.2, second clause: a test asserts the declared values appear in the
    prompt. Both branches, because the two paths assemble instructions
    separately and a fix applied to one works on one path only."""

    ENUM = frozenset({"CC6", "CC7", "CC8"})

    @staticmethod
    def _assert_named(shown: _Shown) -> None:
        text = shown.instructions
        assert "CATEGORY VOCABULARY" in text, (
            "the declared vocabulary is never shown to the model: "
            f"instructions={text!r}"
        )
        for value in sorted(TestTheVocabularyReachesTheModel.ENUM):
            assert value in text, f"{value} missing from the rendered instructions"

    def test_structured_branch_names_the_vocabulary(self, monkeypatch, tmp_path):
        shown = _capture_with_enum(
            monkeypatch, tmp_path, structured=True, enum=self.ENUM)
        assert shown.agent_kwargs.get("output_type") is not None, (
            "branch not pinned: this rendered the unstructured path"
        )
        self._assert_named(shown)

    def test_unstructured_branch_names_the_vocabulary(self, monkeypatch, tmp_path):
        shown = _capture_with_enum(
            monkeypatch, tmp_path, structured=False, enum=self.ENUM)
        assert shown.agent_kwargs.get("output_type") is None, (
            "branch not pinned: this rendered the structured path"
        )
        self._assert_named(shown)

    def test_the_agent_instructions_are_retained_alongside(self, monkeypatch, tmp_path):
        """Appended, never substituted: the vocabulary must not displace the
        agent's own instructions (or 0076's quote obligation on the
        unstructured path)."""
        for structured in (True, False):
            shown = _capture_with_enum(
                monkeypatch, tmp_path, structured=structured, enum=self.ENUM)
            assert _AGENT_INSTRUCTIONS in shown.instructions, (
                f"agent instructions lost (structured={structured})"
            )

    def test_no_vocabulary_declared_adds_nothing(self, monkeypatch, tmp_path):
        """An agent with no declared enum sees no vocabulary block -- the
        prevention is opt-in on the declaration, exactly like the normaliser."""
        shown = _capture_with_enum(
            monkeypatch, tmp_path, structured=True, enum=frozenset())
        assert "CATEGORY VOCABULARY" not in shown.instructions
        assert _AGENT_INSTRUCTIONS in shown.instructions
