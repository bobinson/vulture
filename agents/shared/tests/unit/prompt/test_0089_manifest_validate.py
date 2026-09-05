"""Feature 0089 Phase 0.b/0.c — the VALIDATE tier as fragments + one manifest.

The transcription is only worth anything if it is byte-exact: a fragment whose
text drifted from the prompt file it was copied out of would let the linter
pass on text no model ever sees. So the guard here is a substring check
against the real source files, not a hand-written expectation.

Two fragments predate this transcription: `validate/closure` and
`validate/tool_discipline` were frozen in the skeleton commit from the
PRE-4.1 wording, and the same commit then rewrote `validate_judge.txt`'s
closure section and `tool_discipline_prompt()`. They are deliberately left as
they are — their stances (BLESSES_ABSTENTION vs PERMITS_TOOL_USE) are the
measured defect this feature exists to surface — so they are excluded from the
byte-exactness map and the coverage check tolerates exactly their divergence.
"""

from __future__ import annotations

from pathlib import Path

import shared.validate as _validate_pkg
from shared.prompt import Mode, PromptSpec, lint, profile_for, render
from shared.prompt.manifests import MANIFESTS
from shared.prompt.manifests.validate_judge import VALIDATE_JUDGE
from shared.prompt.registry import get
from shared.prompt.render import _fill

_PROMPTS = Path(_validate_pkg.__file__).parent / "prompts"
SYSTEM_SRC = (_PROMPTS / "validate_judge.txt").read_text(encoding="utf-8")
USER_SRC = (_PROMPTS / "validate_judge_user.txt").read_text(encoding="utf-8")

# fragment id -> the source text it was transcribed out of.
TRANSCRIBED: dict[str, str] = {
    "validate/role": SYSTEM_SRC,
    "validate/untrusted_warning": SYSTEM_SRC,
    "validate/language_idioms": SYSTEM_SRC,
    "validate/calibration": SYSTEM_SRC,
    "validate/evidence_citation": SYSTEM_SRC,
    "validate/output_contract": SYSTEM_SRC,
    "validate/user_template": USER_SRC,
}

# The only lines of validate_judge.txt that the render may fail to reproduce:
# the three closure lines the 4.1 change rewrote after the fragment was frozen.
KNOWN_CLOSURE_DIVERGENCE = frozenset({
    "enough is not a failure — but when you have tools it is not yet the answer",
    "either. Look first; report false only if the answer is still out of reach.",
})


def _profile():
    return profile_for("gpt-4o")


def _contributed(fid: str, spec) -> str:
    """The bytes `render` emits for this fragment, by the renderer's own rules.

    `render._seam_join` interpolates `spec.variables` and then drops each
    part's trailing newlines unless it declares `keep_trailing`, so a fragment
    whose FILE ends with a newline — every validate fragment does; the tier
    transcribes `validate_judge.txt`, one terminator per line — is never a
    literal substring of the render. Comparing the raw text against the render
    therefore reports `validate/tool_discipline` absent from a prompt it is
    fully present in.

    This is the renderer's contract, not a tolerance: the containment check
    below still demands an exact run of bytes, only of the form the renderer
    actually emits. The bytes the check stops seeing — a fragment file's
    trailing newline count — reach no prompt at all and are pinned directly,
    by `test_0089_parity_validate_assembly.py`'s
    `test_validate_fragment_files_carry_exactly_one_terminator`.

    `render._fill` is imported rather than restated so the two cannot disagree
    about the substitution; it is a no-op for the no-`variables` renders here,
    and correct for a call site that supplies them.
    """
    frag = get(fid)
    text = _fill(frag.text, spec.variables)
    return text if frag.keep_trailing else text.rstrip("\n")


def _absent_fragments(rendered: str, spec=VALIDATE_JUDGE) -> list[str]:
    """Fragment ids whose bytes the render does not carry.

    A fragment contributing NOTHING counts as absent. Without that clause the
    check has a hole at both ends: `_seam_join` skips a part that is only
    newlines, and `"" in rendered` is true of every render — so emptying a
    fragment file removes a whole section from the judge prompt and satisfies
    a plain containment test.
    """
    return [fid for fid in spec.fragments
            if not _contributed(fid, spec).strip()
            or _contributed(fid, spec) not in rendered]


def _uncovered_source_lines(rendered: str) -> set[str]:
    return {ln for ln in SYSTEM_SRC.splitlines() if ln.strip() and ln not in rendered}


def _drifted_fragments() -> list[str]:
    return [fid for fid, src in TRANSCRIBED.items() if get(fid).text not in src]


def _of_check(findings, name):
    return [f for f in findings if f.check == name]


def _is_closure_vs_tools(f) -> bool:
    return "tool_discipline" in f.fragment and "closure" in f.fragment


def _is_numbered_snippet_dangle(f) -> bool:
    return f.fragment == "validate/evidence_citation" and "numbered_snippet" in f.message


def test_manifest_validate_judge_renders():
    """The manifest renders, and its system text carries the real sections."""
    rp = render(VALIDATE_JUDGE, _profile(), mode=Mode.TRANSCRIBE)
    assert rp.system == rp.instructions != ""

    absent = _absent_fragments(rp.instructions)
    assert not absent, f"fragments absent from rendered system text: {absent}"

    # Every non-blank line of the source prompt survives the split, except the
    # closure wording the skeleton's frozen fragment predates.
    uncovered = _uncovered_source_lines(rp.instructions)
    assert uncovered <= KNOWN_CLOSURE_DIVERGENCE, f"lost source lines: {uncovered}"

    assert USER_SRC.strip() in rp.user


def test_manifest_validate_judge_places_both_roles():
    """System fragments to the system turn, the template to the user turn."""
    rp = render(VALIDATE_JUDGE, _profile(), mode=Mode.TRANSCRIBE)
    assert [m["role"] for m in rp.messages] == ["system", "user"]
    assert get("validate/user_template").text not in rp.instructions


def test_validate_fragments_are_byte_exact():
    """Each transcribed fragment's text appears VERBATIM in its source file."""
    drifted = _drifted_fragments()
    assert not drifted, f"fragment text not found verbatim in source: {drifted}"


def test_lint_surfaces_validate_blockers():
    """promptlint reports the evidence_line blocker without calling a model.

    The stance conflict is NOT asserted here any more, and its absence is the
    point: feature 0089 item 4.1 landed ahead of the migration and qualified
    the Closure sentence, so `validate/closure` now honestly declares
    BLESSES_ABSTENTION_AFTER_LOOKING and the live prompt genuinely no longer
    holds the contradiction. Asserting a conflict here would require declaring
    the fragment dishonestly, which is the one failure mode §0.c forbids.
    The check itself is pinned by
    `test_lint_catches_the_pre_41_stance_conflict` below, against a fixture
    carrying the pre-4.1 text.
    """
    rp = render(VALIDATE_JUDGE, _profile(), mode=Mode.TRANSCRIBE)
    findings = lint(VALIDATE_JUDGE, rp)

    dangling = _of_check(findings, "dangling_reference")
    assert any(map(_is_numbered_snippet_dangle, dangling)), f"no dangle: {findings}"
    assert not any(map(_is_closure_vs_tools, _of_check(findings, "stance_conflict"))), (
        "4.1 qualified the Closure sentence; a conflict here means a fragment "
        "was declared dishonestly"
    )


def test_lint_catches_the_pre_41_stance_conflict():
    """The regression guard for the defect that motivated the whole feature.

    Measured on qwen3.6-35b-a3b: with the pre-4.1 wording the judge made ZERO
    tool calls across every probe. The linter must catch that composition from
    the declarations alone, in milliseconds, with no model call — so the check
    is pinned against a fixture rather than against whatever the live prompt
    happens to say today.
    """
    from shared.prompt.fragment import Fragment, Role, Stance
    from shared.prompt.lint import check_03_stance_conflict

    pre_41_closure = Fragment(
        id="fixture/closure_pre_41", text="Being unable to see enough is not "
        "a failure - it is the answer.\n", role=Role.SYSTEM,
        stance=(Stance.BLESSES_ABSTENTION,))
    tools = Fragment(
        id="fixture/tool_discipline", text="Tools: you may call read_file.\n",
        role=Role.SYSTEM, stance=(Stance.PERMITS_TOOL_USE,))

    from shared.prompt import registry
    registry.FRAGMENTS[pre_41_closure.id] = pre_41_closure
    registry.FRAGMENTS[tools.id] = tools
    try:
        spec = PromptSpec(id="fixture", tier="validate",
                          fragments=(tools.id, pre_41_closure.id),
                          tools=("read_file",))
        rp = render(spec, _profile(), mode=Mode.TRANSCRIBE)
        found = check_03_stance_conflict(spec, rp)
        assert found, "the linter must catch PERMITS_TOOL_USE vs BLESSES_ABSTENTION"
        assert "PERMITS_TOOL_USE" in found[0].message
    finally:
        registry.FRAGMENTS.pop(pre_41_closure.id, None)
        registry.FRAGMENTS.pop(tools.id, None)


def test_schema_fields_are_the_verdict_schema():
    """One field list. `check_01_orphan_field` reads this tuple, and a local
    copy of the five names is a second place L5's contract can drift from
    `llm_judge._coerce_verdict`."""
    from shared.prompt.schema import VERDICT_SCHEMA

    assert VALIDATE_JUDGE.schema_fields == tuple(f.name for f in VERDICT_SCHEMA.fields)
    assert VALIDATE_JUDGE.schema_fields == (
        "id", "exploitable", "window_sufficient", "evidence_line", "reasoning")
    declared = get("validate/output_contract").declares_fields
    assert set(declared) == set(VALIDATE_JUDGE.schema_fields)


def test_manifests_registry_exports_validate_judge():
    assert MANIFESTS["validate_judge"] is VALIDATE_JUDGE


def test_manifest_declares_the_judge_tools_and_template():
    assert VALIDATE_JUDGE.tier == "validate"
    assert VALIDATE_JUDGE.tools == ("read_file", "search_pattern", "parse_ast")
    assert VALIDATE_JUDGE.user_fragments == ("validate/user_template",)
    assert VALIDATE_JUDGE.slots == ()


def test_system_fragments_are_in_source_order():
    """Order is the contract: the render must reproduce the file's sequence."""
    positions = [SYSTEM_SRC.index(get(fid).text)
                 for fid in VALIDATE_JUDGE.fragments if fid in TRANSCRIBED]
    assert positions == sorted(positions)
    assert VALIDATE_JUDGE.fragments[-1] == "validate/tool_discipline"
