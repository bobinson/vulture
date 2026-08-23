"""0076 §5.2 — the model must be ASKED to quote the code it accuses, on every path.

The keystone defect (0076 A1/A3) is not that the model lies about line numbers; it
is that nothing in the pipeline ever asks it for evidence, and any evidence it
volunteers is thrown away by the parser's eight-key whitelist (A2). A claim that
carries no quote is not checkable by any amount of downstream machinery, so the
verifier of §5.3 is vacuous until the obligation of §5.2 ships.

Measured, and why the wording is pinned rather than left to taste:

  * 0075 measured 78% mislocation on raw-presented files against 13% on numbered
    ones. The detector's OWN ``read_file`` tool (``tools/file_reader.py:28``)
    still returns unnumbered text, so a model that widens its view with its tool
    is pushed straight back into the mislocated class (A5). AC4 closes that with
    0075's EXISTING switch — one switch, one policy — not a second one.
  * Two contracts carry the field list: the builder at ``audit_runner:2347-2348``
    (reached on every call, both branches) and the unstructured instruction at
    ``:2536-2541``. They are the same policy written twice, so a fix applied to
    one silently works on one path only. AC9 asserts both, on the RENDERED text,
    with the endpoint pinned on each branch (D7: the structured path is off
    whenever a custom endpoint is configured).
  * The consequence clause is *"will be reported as unverified"*, never *"do not
    report findings you cannot quote"*. AC20 locks that: a prompt that instructs
    suppression is a deletion mechanism living OUTSIDE every switch this feature
    ships, and it is un-rollbackable once a run has completed — the findings it
    suppressed were never emitted, so no later flag can bring them back.

``test_prompt_never_instructs_suppression_of_unquotable_findings`` is a
REGRESSION LOCK, not a RED test, and it is labelled so deliberately: the baseline
prompt contains no suppression instruction, so it passes before and after this
feature. It earns its place because it is the only guard against a future prompt
edit turning the obligation into a suppression mechanism, and it is the one recall
guard in 0076 that cannot be implemented as a code path.

Every contract here is read from the text the model actually receives — the
rendered prompt and the captured ``Agent(instructions=..., output_type=...)``
kwargs — never from a source-level grep, so a change of internal structure that
preserves the contract keeps these green.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The obligation, verbatim from 0076 §5.2. Compared whitespace-insensitively so
# the implementation may wrap it across prompt parts, but the WORDS are pinned:
# each clause below is load-bearing and is separately asserted further down.
_OBLIGATION = (
    'evidence_quote: copy the 1-3 source lines your finding is about, VERBATIM '
    'from the numbered listing above (you may include the "NN: " prefix). '
    'A finding without a quote will be reported as unverified.'
)


def _squash(text: str) -> str:
    """Collapse every whitespace run to one space.

    The builder joins its parts with ``\\n`` and the unstructured branch appends
    to an instruction block, so the same sentence legitimately carries different
    line breaks on the two paths. Only the wording is contractual.
    """
    return " ".join(text.split())


# ── capturing what the model is actually shown ───────────────────────────────


@dataclass
class _Contracts:
    """The two prompt contracts, as rendered on one real call."""

    prompt: str = ""            # the builder's output (:2347-2348), user message
    instructions: str = ""      # augmented_instructions (:2536-2541), system message
    agent_kwargs: dict = field(default_factory=dict)

    @property
    def output_type(self) -> Any:
        return self.agent_kwargs.get("output_type")

    @property
    def both(self) -> tuple[tuple[str, str], ...]:
        return (("builder prompt", self.prompt), ("agent instructions", self.instructions))


def _capture(monkeypatch, tmp_path, *, structured: bool) -> _Contracts:
    """Run one LLM batch with the SDK stubbed out and capture both contracts.

    No network, no model, no sleep: ``agents.Agent`` and ``agents.Runner`` are
    replaced, so the only thing exercised is the prompt/schema assembly inside
    ``_collect_llm_findings_async``.

    D7 — the branch is pinned EXPLICITLY on both sides rather than inherited from
    the developer's environment: ``supports_structured_output`` returns False
    whenever a custom OpenAI-compatible endpoint is configured, so a stray
    ``OPENAI_BASE_URL`` would silently test the unstructured branch twice and
    report the structured contract as covered when it never rendered.
    """
    import agents as agents_sdk

    from shared import audit_runner

    captured = _Contracts()

    class _FakeAgent:
        def __init__(self, **kwargs):
            captured.agent_kwargs = kwargs
            captured.instructions = kwargs.get("instructions", "")

    class _FakeResult:
        final_output = "[]"

    class _FakeRunner:
        @staticmethod
        async def run(_agent, input: str = "", **_kwargs):  # SDK's own kwarg name
            captured.prompt = input
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

    asyncio.run(
        audit_runner._collect_llm_findings_async(
            run_id="run-0076",
            source_path=str(source_root),
            categories=["injection"],
            skill_tools=[],
            instructions="You are an auditor.",
            domain_label="checks",
            source_context="--- a.ts ---\n1: const a = 1;\n",
        )
    )
    return captured


def _finding_properties(output_type: Any) -> set[str]:
    """Property names of the FINDING model inside a structured output schema.

    Read from the JSON schema the SDK sends as ``response_format`` rather than
    from ``AuditFinding`` itself: the contract is what the model is SHOWN, so an
    implementation that keeps a wider internal model and narrows only the
    response schema still satisfies it.
    """
    schema = output_type.model_json_schema()
    for definition in schema.get("$defs", {}).values():
        props = definition.get("properties", {})
        if "title" in props and "severity" in props:
            return set(props)
    raise AssertionError(f"no finding model found in structured schema: {schema}")


# ── AC9: both contracts request the quote ────────────────────────────────────


def test_the_builder_contract_requests_the_evidence_quote():
    """A1 — the builder lists the eight fields the model must return and is
    reached on EVERY LLM call, both branches. It asked for no evidence at all."""
    from shared.audit_runner import _build_llm_prompt

    prompt = _build_llm_prompt(
        "/src", ["injection"], "checks", "--- a.ts ---\n1: const a = 1;\n", "",
    )
    assert _squash(_OBLIGATION) in _squash(prompt), (
        "the builder's field contract must request evidence_quote verbatim "
        f"(0076 §5.2); rendered prompt was:\n{prompt}"
    )


def test_both_prompt_contracts_request_the_quote(monkeypatch, tmp_path):
    """T2.2 / AC9 — the A3 duplication guard.

    Two contracts, one policy, two places. This is the test a fix applied to only
    one of them must fail: the builder's user message AND the unstructured
    branch's ``augmented_instructions`` are asserted on the SAME run.
    """
    contracts = _capture(monkeypatch, tmp_path, structured=False)
    wanted = _squash(_OBLIGATION)
    for label, text in contracts.both:
        assert wanted in _squash(text), (
            f"the {label} must request evidence_quote verbatim — a fix to one "
            f"prompt path only leaves the other blind (0076 A3). Rendered:\n{text}"
        )


def test_the_two_contracts_carry_the_identical_sentence(monkeypatch, tmp_path):
    """DRY (rule 3): not merely 'both ask for a quote' but both ask in the SAME
    words, so there is one authority for the obligation and not two that can
    drift apart. Two differently-worded requests are two policies."""
    contracts = _capture(monkeypatch, tmp_path, structured=False)
    wanted = _squash(_OBLIGATION)
    assert _squash(contracts.prompt).count(wanted) >= 1
    assert _squash(contracts.instructions).count(wanted) >= 1, (
        "the unstructured instruction must repeat the builder's sentence "
        "verbatim, not a paraphrase of it"
    )


def test_the_obligation_sentence_names_the_numbered_format():
    """§5.2 property 2 — the sentence names the ``"NN: "`` prefix the model is
    already looking at. 0075 made every content line carry it, so the model WILL
    echo it; the prompt permits that instead of fighting it, and the verifier's
    normaliser strips it (§5.3)."""
    from shared.audit_runner import _build_llm_prompt

    prompt = _build_llm_prompt("/src", ["injection"], "checks", "--- a.ts ---\n1: x\n", "")
    assert 'NN: ' in prompt, (
        "the obligation must name the numbered-listing format the model is shown, "
        "so an echoed prefix is expected rather than treated as a mismatch"
    )


def test_the_obligation_bounds_the_quote_at_the_configured_max_lines(monkeypatch):
    """§5.2 property 3 — the stated range must match ``VULTURE_LLM_QUOTE_MAX_LINES``.

    The point is that the signal floor is satisfiable BY COMPLIANCE rather than by
    luck: a model told '1-3 lines' while the verifier clamps at 2 would be refused
    for doing exactly what it was asked. Read at call time (D14) — the override is
    flipped inside the test with no module reload.
    """
    from shared.audit_runner import _build_llm_prompt

    def _stated_max(text: str) -> str:
        match = re.search(r"\b1-(\d+)\s+source lines\b", _squash(text))
        assert match, f"the obligation must state a '1-N source lines' bound; got:\n{text}"
        return match.group(1)

    default_prompt = _build_llm_prompt("/src", ["c"], "checks", "--- a.ts ---\n1: x\n", "")
    assert _stated_max(default_prompt) == "3", "the documented default is 3 lines"

    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "2")
    narrowed = _build_llm_prompt("/src", ["c"], "checks", "--- a.ts ---\n1: x\n", "")
    assert _stated_max(narrowed) == "2", (
        "the prompt must track VULTURE_LLM_QUOTE_MAX_LINES; a fixed '1-3' asks "
        "the model for more lines than the verifier will accept once the knob moves"
    )


def test_the_obligation_promises_annotation_never_deletion():
    """Principle 3 — ANNOTATE, never DROP, stated to the model in the prompt.

    The consequence clause is what makes the difference between an obligation and
    a suppression instruction, so it is asserted positively here and negatively by
    the AC20 lock below.
    """
    from shared.audit_runner import _build_llm_prompt

    prompt = _squash(_build_llm_prompt("/src", ["c"], "checks", "--- a.ts ---\n1: x\n", ""))
    assert "will be reported as unverified" in prompt, (
        "the model must be told an unquoted finding is REPORTED-as-unverified, "
        "not withheld (0076 §5.2 property 1)"
    )


def _structured_finding_properties(monkeypatch, tmp_path) -> set[str]:
    """The finding fields the model is shown on the STRUCTURED branch (D7 pinned)."""
    contracts = _capture(monkeypatch, tmp_path, structured=True)
    assert contracts.output_type is not None, (
        "the structured branch must be the one under test here — D7: a custom "
        "endpoint silently disables it"
    )
    return _finding_properties(contracts.output_type)


def test_audit_finding_schema_carries_the_quote(monkeypatch, tmp_path):
    """T2.4 / AC9 — the structured contract, asserted on the response schema the
    SDK actually sends, not on the class. A prompt sentence the schema contradicts
    is not an obligation: on this branch the schema IS the contract."""
    props = _structured_finding_properties(monkeypatch, tmp_path)
    assert "evidence_quote" in props, (
        f"the structured schema must carry evidence_quote; got {sorted(props)}"
    )


def test_audit_finding_schema_no_longer_carries_code_snippet_or_check_id(monkeypatch, tmp_path):
    """T2.4 / B3 — both fields leave what the model is SHOWN.

    ``code_snippet`` must stop being model-authorable: such a string is today
    indistinguishable from a source read, it displaces the real window fed to the
    L5 judge (D8), and it scores +3 in the Go winner selection
    (``stream_handler.go:1040``) — so a fabricated snippet outranks a real one.
    ``check_id`` is never persisted by either repository (measured: 0 of 1,554
    rows, C7), so a model-invented value is noise that nonetheless keys the Python
    dedup identity.
    """
    props = _structured_finding_properties(monkeypatch, tmp_path)
    assert "code_snippet" not in props, (
        "code_snippet must not be a model-authored field (0076 B3) — it is a "
        "source-read artefact produced by _attach_code_snippet"
    )
    assert "check_id" not in props, (
        "check_id must not be a model-authored field (0076 B3/C7) — it is never "
        "persisted, so a model-invented value is pure noise in the dedup identity"
    )


def test_quote_field_survives_the_unstructured_whitelist():
    """T2.1 / A2 — ``_normalize_finding`` returns a fresh dict of exactly the
    whitelisted keys, so a volunteered quote is DISCARDED on the path the
    measured configuration actually takes. Asking for the field is pointless
    unless the parser keeps it."""
    from shared.audit_runner import _normalize_finding

    raw = {
        "severity": "high",
        "category": "CWE-89",
        "title": "SQL injection",
        "file_path": "api/users.ts",
        "line_start": 30,
        "line_end": 30,
        "evidence_quote": '30: const q = `SELECT * FROM users WHERE id = ${id}`;',
    }
    normalized = _normalize_finding(raw)
    assert normalized.get("evidence_quote") == raw["evidence_quote"], (
        "the parser whitelist must carry evidence_quote through; dropping it "
        "silently reverts the whole feature on the unstructured path (0076 A2)"
    )


# ── AC20: the primary recall guard ───────────────────────────────────────────
#
# A suppression instruction in the prompt is the one deletion mechanism in this
# feature that no switch can reverse and no probe can measure: the suppressed
# rows were never emitted, so they are absent from the SSE stream, from the DB
# and from every offline replay. It is therefore locked on the literal text.

_SENTENCES = re.compile(r"(?<=[.!?])\s+|\n+")

_SUPPRESSION_PATTERNS = (
    # "do not report ...", "never include ...", "avoid flagging ..."
    re.compile(
        r"\b(?:do not|don't|never|avoid|refrain from)\s+(?:\w+\s+){0,3}?"
        r"(?:report|reporting|include|including|list|listing|emit|emitting|"
        r"output|outputting|return|returning|mention|mentioning|flag|flagging|raise)\b",
        re.IGNORECASE,
    ),
    # "skip any finding ...", "omit issues ...", "discard the result ..."
    # The three lookbehinds keep the OPPOSITE instruction ("do not omit findings")
    # out of the hit set — that sentence forbids suppression rather than ordering it.
    re.compile(
        r"(?<!not )(?<!n't )(?<!never )"
        r"\b(?:skip|omit|exclude|withhold|suppress|discard|drop|ignore|hide)(?:s|ing)?\s+"
        r"(?:\w+\s+){0,4}?(?:finding|findings|issue|issues|result|results)\b",
        re.IGNORECASE,
    ),
    # exclusivity, in either word order: "only report ...", "report only ..."
    re.compile(r"\bonly\s+(?:report|include|list|emit|output|return|flag)\b", re.IGNORECASE),
    re.compile(r"\b(?:report|include|list|emit|output|return)\s+only\b", re.IGNORECASE),
)


def _suppression_hits(text: str) -> list[str]:
    """Sentences of ``text`` that instruct the model to withhold a finding.

    O(n) in the text: a fixed number of linear regex passes over each sentence,
    no cross-product over findings or lines.
    """
    hits: list[str] = []
    for sentence in _SENTENCES.split(text):
        if any(pattern.search(sentence) for pattern in _SUPPRESSION_PATTERNS):
            hits.append(_squash(sentence))
    return hits


def test_prompt_never_instructs_suppression_of_unquotable_findings(monkeypatch, tmp_path):
    """AC20 / T2.3 — THE feature's primary recall guard.

    REGRESSION LOCK, not a RED test, and §0 of the plan labels it so: the baseline
    prompt contains no suppression instruction, so this passes both before and
    after the obligation lands. It earns its place anyway, because it is the only
    thing standing between the obligation and its most tempting mis-edit —
    "and do not report findings you cannot quote", which would convert a recall
    feature into a silent deletion mechanism sitting outside every switch in §5.9.

    Asserted on the literal rendered text of BOTH contracts, because the two are
    edited independently (A3).
    """
    contracts = _capture(monkeypatch, tmp_path, structured=False)
    for label, text in contracts.both:
        hits = _suppression_hits(text)
        assert not hits, (
            f"the {label} instructs the model to withhold findings: {hits}. "
            "0076 annotates, never drops — an unquoted finding is reported as "
            "unverified, not suppressed (AC20)"
        )


def test_the_suppression_detector_catches_the_wording_it_guards_against():
    """A lock is worthless unless it is shown to lock something.

    This is the forbidden set: the phrasings an implementer tightening the
    obligation would actually reach for. If the guard above ever goes quiet
    because its patterns rotted, this test goes quiet with it — which is why the
    two are kept adjacent and both run on the default lane.
    """
    forbidden = [
        "Do not report findings you cannot quote.",
        "If you cannot quote the code, do not include the finding.",
        "Skip any finding without an evidence_quote.",
        "Omit findings whose quote you cannot copy verbatim.",
        "Exclude issues that lack a quote.",
        "Only report findings you can quote.",
        "Report only findings with an evidence_quote.",
        "Withhold the finding when no quote is available.",
        "Never flag an issue you cannot cite.",
        "Discard any results without supporting lines.",
    ]
    for text in forbidden:
        assert _suppression_hits(text), f"the AC20 guard must catch: {text!r}"


def test_the_suppression_detector_does_not_fire_on_legitimate_prompt_text():
    """The other half of the lock's own calibration, and the harder half.

    A guard that over-fires would block the obligation itself, or 0075's elision
    header — which literally contains the word "omitted" — and would be deleted by
    the first person it inconveniences. The permitted set therefore includes the
    real obligation, the elision header, the sentence T2.6 adds about fetchable
    ranges, and the ANTI-suppression instruction ("do not omit findings"), whose
    verb is negated and must not read as an order to suppress.
    """
    permitted = [
        _OBLIGATION,
        "--- api/users.ts (lines 1-9, 31-89 omitted) ---",
        "The omitted ranges above are fetchable with read_file.",
        "Do not omit findings that you cannot quote.",
        "For each issue found, provide severity, category, title, description, "
        "file_path, line_start, line_end, and recommendation.",
        "IMPORTANT: Return findings as a JSON array.",
    ]
    for text in permitted:
        assert not _suppression_hits(text), (
            f"the AC20 guard must not fire on legitimate prompt text: {text!r}"
        )


# ── AC4: the detector's own read_file returns numbered lines ─────────────────


_SAMPLE = "const a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\nconst e = 5;\n"


def _sample_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.ts"
    path.write_text(_SAMPLE)
    return path


def test_detector_read_file_returns_numbered_lines(tmp_path):
    """T2.5 / AC4 / A5 — the detector's tool must present source the same way the
    batched feed does.

    0075 numbered the feed and measured mislocation fall from 78% to 13%. The
    tool the model uses to widen its view past the feed still returned bare
    ``"".join(lines)``, so every line the model read through the tool put it back
    in the class 0075 fixed — and those are precisely the lines it went looking
    for. The judge's equivalent tool (``judge_tools.py:213``) has numbered its
    output all along.

    Numbering is asserted exactly, line for line: an implementation that hands
    ``readlines()`` (which keeps the trailing newline) to the formatter renders a
    blank line between every source line, doubling the tool's output inside a
    budgeted context.
    """
    from shared.tools.file_reader import read_file

    out = read_file(str(_sample_file(tmp_path)))
    expected = [f"{n}: {line}" for n, line in enumerate(_SAMPLE.splitlines(), start=1)]
    assert out.splitlines() == expected, (
        f"read_file must number every line as 'N: code' (0076 AC4); got:\n{out!r}"
    )


def test_detector_read_file_numbers_a_line_range_absolutely(tmp_path):
    """The numbers must be ABSOLUTE file positions, never range-relative.

    0075's rationale applies unchanged: a number that restarts at 1 for a slice
    beginning at file line 3 is worse than no number, because the model's
    ``line_start`` then looks precise and is systematically wrong by the offset —
    and a wrong-but-plausible line is exactly what the anchor verifier of §5.3
    cannot distinguish from a fabrication.
    """
    from shared.tools.file_reader import read_file

    out = read_file(str(_sample_file(tmp_path)), 3, 5)
    assert out.splitlines() == ["3: const c = 3;", "4: const d = 4;", "5: const e = 5;"], (
        f"a ranged read must carry absolute line numbers; got:\n{out!r}"
    )


def test_line_numbers_switch_restores_raw_read_file_output(monkeypatch, tmp_path):
    """AC4's rollback half — ``VULTURE_LLM_LINE_NUMBERS=false`` restores the
    pre-0076 bytes exactly, for the whole-file and the ranged read alike. Read at
    call time (D14): the variable is flipped inside the test with no reload."""
    from shared.tools.file_reader import read_file

    monkeypatch.setenv("VULTURE_LLM_LINE_NUMBERS", "false")
    path = str(_sample_file(tmp_path))
    assert read_file(path) == _SAMPLE, "the switch must restore byte-identical raw output"
    assert read_file(path, 3, 5) == "const c = 3;\nconst d = 4;\nconst e = 5;\n"


def test_read_file_numbering_is_governed_by_one_switch_not_a_second():
    """AC4 — *one switch, not a second*.

    0075 already owns the policy "the model is always shown numbered source", and
    §5.2 reuses ``VULTURE_LLM_LINE_NUMBERS`` rather than minting a tool-specific
    twin. A second name would let an operator roll back the feed and not the tool
    (or the reverse) and end up with one model reading two presentations — the
    exact asymmetry 0075 §12 identified as the defect, reintroduced one layer down.

    Scoped to the two modules this task touches, and tolerant of the switch being
    read through a shared helper elsewhere: what is forbidden is a NEW variable
    name appearing here.
    """
    from shared.tools import file_reader

    sources = [Path(file_reader.__file__)]
    leaf = Path(file_reader.__file__).with_name("line_format.py")
    if leaf.exists():          # T0.1's leaf module; its own guards live in test_0076_line_format
        sources.append(leaf)

    names: set[str] = set()
    for source in sources:
        names.update(re.findall(r"VULTURE_[A-Z0-9_]+", source.read_text()))
    assert names <= {"VULTURE_LLM_LINE_NUMBERS"}, (
        f"line numbering must be governed by 0075's switch alone; found {sorted(names)}"
    )


def test_the_confined_read_file_tool_delegates_rather_than_reimplementing():
    """REGRESSION LOCK (true today, must stay true).

    The detector is handed ``make_read_file_tool(source_root)``, not the bare
    ``read_file`` — the confined wrapper is the only reader the model can actually
    reach in the real pipeline. If it grew its own read, AC4 would be satisfied on
    a function no model ever calls.
    """
    import inspect

    from shared.tools import file_reader

    source = inspect.getsource(file_reader.make_read_file_tool)
    assert "read_file(path, start_line, end_line)" in source, (
        "the confined tool must delegate to read_file so numbering applies to the "
        "reader the model is actually given"
    )


# ── VULTURE_LLM_QUOTE_REQUIRED=false: the P2 rollback ────────────────────────


def test_quote_required_false_removes_the_sentence_from_both_contracts(monkeypatch, tmp_path):
    """§5.9 — the obligation's own switch, default ``true`` (``!= "false"``).

    It exists because the added field is §5.7's one un-mitigable risk: a ninth
    field consumes output tokens and attention and the model may return fewer
    rows. Flipping it must remove the ask from BOTH contracts — leaving it in one
    would keep paying the risk on that path while reporting the feature rolled back.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "false")
    contracts = _capture(monkeypatch, tmp_path, structured=False)
    for label, text in contracts.both:
        assert "evidence_quote" not in text, (
            f"VULTURE_LLM_QUOTE_REQUIRED=false must strip the obligation from the "
            f"{label}; it still reads:\n{text}"
        )


def test_quote_required_false_removes_the_field_from_the_structured_schema(monkeypatch, tmp_path):
    """The same switch, on the structured contract: the schema is what the model
    is shown there, so a field left in it is still an ask. Read at call time — no
    module reload, per AC23/D14."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "false")
    contracts = _capture(monkeypatch, tmp_path, structured=True)
    assert contracts.output_type is not None, "structured branch must be under test (D7)"
    props = _finding_properties(contracts.output_type)
    assert "evidence_quote" not in props, (
        f"the switch must remove the field from the response schema; got {sorted(props)}"
    )


def test_quote_required_defaults_on(monkeypatch, tmp_path):
    """Default-true idiom check (D14: ``!= "false"``, never ``env_truthy``, which
    is default-false). With the variable unset the obligation must be present —
    the shipped configuration is the one that carries the field."""
    contracts = _capture(monkeypatch, tmp_path, structured=True)
    assert _squash(_OBLIGATION) in _squash(contracts.prompt)
    assert "evidence_quote" in _finding_properties(contracts.output_type)
