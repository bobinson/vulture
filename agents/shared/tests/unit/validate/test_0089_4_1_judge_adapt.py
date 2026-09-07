"""Feature 0089 item 4.1 — the L5 judge renders ADAPT, and the TURNS it sends.

Item 4.1's prompt-TEXT half landed first (the three abstention sites were
qualified, taking the judge's tool-call rate from 0% to 100%); this file covers
the half the plan's 4.1 row actually names — `llm_judge._judge_prompt` moving
from `Mode.TRANSCRIBE` to `Mode.ADAPT`. `test_0089_mode_matches_phase` pins the
constant. What is pinned HERE is what the constant does to the wire, because
the flip's whole risk lives in the two turns the judge assembles by hand.

WHY THIS FILE HAD TO EXIST BEFORE THE FLIP. PROVE's identical flip (item 4.5)
shipped a regression: ADAPT rule 1 relocates the entire system turn into the
user turn for a family whose chat template has no system role, the call site
then prepended its own user turn, and gemma — the very family rule 1 exists for
— got `['user', 'user']` on the wire, which an alternation-strict template
rejects. `llm_helper._compose_turns` is that fix.

The judge's assembly has the SAME ROOT and a different symptom, so the same
fix does not transcribe. VALIDATE renders one spec twice and keeps
`.instructions` from one render and `.user` from the other, so the relocated
text arrives in the user half by itself and nothing is duplicated. What the
hardcoded literal produced instead was

    [{"role": "system", "content": ""}, {"role": "user", "content": ...}]

— an empty system message, which `render._messages` refuses to emit for exactly
the reason the judge must not send one ("a gateway is entitled to reject a
zero-length message, and a model that accepts one still spends a turn boundary
on nothing").

AND A SECOND ONE, WHICH PROVE DOES NOT HAVE, because PROVE renders its system
spec and its user content separately while the judge's two paths render two
DIFFERENT specs. `_judge_batch` used to render the user turn once, from
`VALIDATE_JUDGE`, and send those same bytes down both paths. Under TRANSCRIBE
that is correct — the user turn is the verbatim template either way. Under
ADAPT, for a no-system-role family, the user turn carries the folded system
turn, and `VALIDATE_JUDGE`'s includes `validate/tool_discipline`. The plain
path exists precisely because there are no tools (no source root to confine
reads to, or the provider rejected `tools=`), so that fold would hand the tool
contract to the one request that cannot honour it.

Everything below drives `llm_judge._judge_batch` — the function that picks the
path and assembles the turns — with a fake client that snapshots each
`create(**kw)`. Nothing here asserts against a prompt string typed into the
test: the expected side is a live render, a live fragment, or the live profile.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from shared.llm.provider import get_model
from shared.prompt import Mode, profile_for, registry, render
from shared.prompt.lint import family_models
from shared.prompt.manifests import MANIFESTS
from shared.prompt.profile import MODEL_PROFILES
from shared.prompt.render import _fill
from shared.validate import l5_cache, llm_judge
from shared.validate.types import ValidateConfig

FAMILIES = tuple(sorted(MODEL_PROFILES))

# One finding per request, so `{n}` is 1 in both the user template and the tool
# contract and `_filled()` below needs no second value.
BATCH_N = 1


# ── the fake provider ─────────────────────────────────────────────────────
#
# Same shape as `test_0089_4_3_judge_markers.py`'s, with one difference that
# matters here: each request's `messages` is SNAPSHOT rather than referenced.
# The tool loop appends later turns to the same list object, so a stored
# reference would show the first request holding turns it never carried.


class _FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class _FakeResp:
    def __init__(self, message):
        self.choices = [type("c", (), {"message": message,
                                       "finish_reason": "stop"})()]


class _FakeCompletions:
    def __init__(self, calls_log):
        self.calls = calls_log

    def create(self, **kw):
        self.calls.append({**kw, "messages": [dict(m) for m in kw["messages"]]})
        return _FakeResp(_FakeMessage(content=json.dumps({"verdicts": [
            {"id": "F-1", "exploitable": 0.9, "window_sufficient": True,
             "evidence_line": 42, "evidence_file": "svc/db/queries.py",
             "reasoning": "ok"},
        ]})))


class _FakeClient:
    def __init__(self, calls_log):
        self.chat = type("chat", (), {})()
        self.chat.completions = _FakeCompletions(calls_log)


class _Executor:
    """A tool executor that is never called — its mere presence selects the
    tool-equipped path, which is the only thing these tests need from it."""

    def execute(self, name: str, arguments: str) -> str:  # pragma: no cover
        raise AssertionError("the scripted model asks for no tools")


def _finding() -> dict:
    return {
        "id": "F-1", "check_id": "py.sql-injection", "severity": "high",
        "file_path": "svc/db/queries.py", "line_start": 42, "line_end": 44,
        "description": "User input is concatenated into a SQL string.",
        "code_snippet": "q = 'SELECT * FROM u WHERE id = ' + uid",
    }


def _turns(monkeypatch, model: str, *, tools: bool) -> list[dict]:
    """The FIRST request `_judge_batch` puts on the wire, for `model`.

    Production end to end: `_resolve_l5_runtime`'s own system prompt, the real
    batching, the real path selection. Only the client and the verdict cache
    are replaced — the cache because it is sqlite-backed and a hit would skip
    the request this file is about.
    """
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)
    monkeypatch.delenv("VULTURE_VALIDATE_LLM_MODEL", raising=False)
    monkeypatch.setattr(l5_cache, "lookup", lambda key: None)
    monkeypatch.setattr(l5_cache, "store", lambda *a, **kw: None)
    calls: list[dict] = []
    monkeypatch.setattr(llm_judge, "_get_client", lambda: _FakeClient(calls))

    rt = llm_judge._resolve_l5_runtime(ValidateConfig())
    assert rt is not None and rt.model == model, rt
    llm_judge._judge_batch(
        batch_idx=0, batch=[(0, _finding(), "python")], audit_id="aud-4-1",
        system_prompt=rt.system_prompt, model=rt.model,
        per_batch_timeout_s=5.0,
        tool_executor=_Executor() if tools else None,
        max_tool_calls=rt.max_tool_calls,
    )
    assert calls, "the judge issued no request at all"
    return calls[0]["messages"]


def _profile(model: str):
    """The profile the judge must be adapting to — resolved the way the call
    site resolves it, so a change there is visible here."""
    return profile_for(get_model(model))


def _spec(tools: bool):
    return MANIFESTS["validate_judge" if tools else "validate_judge_plain"]


def _filled(fid: str) -> str:
    """A fragment's contributed bytes, interpolated by the renderer's own rule.

    `_fill` is imported rather than re-implemented for the reason
    `test_0089_parity_validate_assembly` gives: a second copy of the
    substitution rule drifts. `validate/tool_discipline` is the one fragment
    here that carries a placeholder, and `{n}` is the batch size.
    """
    return _fill(registry.get(fid).text, {"n": BATCH_N}).strip("\n")


def _delivered(msgs: list[dict]) -> str:
    return "\n".join(m["content"] for m in msgs)


# ══════════════════════════════════════════════════════════════════════════
# A — the shape of the turns
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("tools", (True, False), ids=("tool-path", "plain-path"))
@pytest.mark.parametrize("family", FAMILIES)
def test_the_judge_never_puts_an_empty_turn_on_the_wire(monkeypatch, family, tools):
    """The regression the flip introduces, on every family and both paths.

    For nine of the ten families this passes before the flip and after it; for
    `gemma` it is the whole point, and the parametrisation is what makes that
    one case a member of a swept property rather than a special case somebody
    remembered to write down.
    """
    msgs = _turns(monkeypatch, family_models()[family], tools=tools)
    empty = [i for i, m in enumerate(msgs) if not (m.get("content") or "").strip()]
    assert empty == [], (
        f"{family}: message(s) {empty} carry no content — "
        f"{[m['role'] for m in msgs]}"
    )


@pytest.mark.parametrize("tools", (True, False), ids=("tool-path", "plain-path"))
@pytest.mark.parametrize("family", FAMILIES)
def test_the_turn_roles_follow_the_profile(monkeypatch, family, tools):
    """The roles are DERIVED from the capability, never listed per family.

    Two failures at once. A profile with a system role must still get one — so
    the fix cannot be "stop sending a system turn" — and a profile without one
    must get a single user turn, with no `['user', 'user']` (PROVE's symptom)
    and no empty leading turn (the judge's).
    """
    profile = _profile(family_models()[family])
    msgs = _turns(monkeypatch, family_models()[family], tools=tools)
    roles = [m["role"] for m in msgs]
    assert roles == (["system", "user"] if profile.system_role else ["user"]), (
        f"{family} (system_role={profile.system_role}): {roles}")
    assert all(a != b for a, b in zip(roles, roles[1:])), (
        f"{family}: two consecutive turns share a role — {roles}")


# ══════════════════════════════════════════════════════════════════════════
# B — the two specs stay two specs once the fold merges the turns
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("family", FAMILIES)
def test_the_no_tools_path_never_ships_the_tool_contract(monkeypatch, family):
    """`validate/tool_discipline` may reach only the request that has tools.

    The plain path is reached when there is no source root to confine reads to,
    or when the provider has just REJECTED `tools=`. Telling that request it
    may call `read_file` is not a wasted paragraph, it is an instruction the
    model cannot carry out — and under ADAPT the fold is what puts it there,
    because the folded user turn is the whole system turn of whichever spec
    produced it.
    """
    contract = _filled("validate/tool_discipline")
    model = family_models()[family]
    plain = _delivered(_turns(monkeypatch, model, tools=False))
    tooled = _delivered(_turns(monkeypatch, model, tools=True))
    assert contract not in plain, (
        f"{family}: the no-tools request carries the tool contract")
    assert contract in tooled, (
        f"{family}: the tool-equipped request lost the tool contract — the "
        "fixture no longer distinguishes the two specs")


# ══════════════════════════════════════════════════════════════════════════
# C — the fold moves the prompt, it does not lose it
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("tools", (True, False), ids=("tool-path", "plain-path"))
@pytest.mark.parametrize("family", FAMILIES)
def test_every_fragment_the_rules_admit_reaches_the_wire(monkeypatch, family, tools):
    """What ADAPT admits for this profile must arrive, in whichever turn.

    The admitted set is read off the library's own render rather than listed,
    so rule 9 dropping `core/language` for a family that does not pin its
    output language is not a gap here — and a rule that started dropping
    something else would not be excused either, because
    `test_the_rules_drop_exactly_the_language_pin` below states what may be
    missing and nothing more.
    """
    model = family_models()[family]
    spec = _spec(tools)
    rp = render(replace(spec, variables={"n": BATCH_N}), _profile(model),
                mode=Mode.ADAPT)
    library = rp.instructions + "\n" + rp.user
    admitted = [fid for fid in spec.fragments if _filled(fid) in library]
    assert len(admitted) >= 7, (f"{family}: only {admitted} admitted; the "
                                "comparison has nothing left to make")

    wire = _delivered(_turns(monkeypatch, model, tools=tools))
    missing = [fid for fid in admitted if _filled(fid) not in wire]
    assert missing == [], f"{family}: lost in assembly — {missing}"


@pytest.mark.parametrize("tools", (True, False), ids=("tool-path", "plain-path"))
@pytest.mark.parametrize("family", FAMILIES)
def test_the_rules_drop_exactly_the_language_pin(monkeypatch, family, tools):
    """The other direction: what is ABSENT from the wire is one known clause.

    Without this, the sweep above is satisfied by a renderer that drops
    everything — an empty admitted set would make its `missing` list empty too
    (the `>= 7` floor there is the cheap half of the same guard). The clause is
    `core/language`, and it is absent exactly for the six families whose
    profile does not pin the output language.
    """
    model = family_models()[family]
    spec = _spec(tools)
    profile = _profile(model)
    wire = _delivered(_turns(monkeypatch, model, tools=tools))
    absent = [fid for fid in spec.fragments if _filled(fid) not in wire]
    assert absent == ([] if profile.output_language_pin else ["core/language"]), (
        f"{family} (output_language_pin={profile.output_language_pin}): {absent}")


# ══════════════════════════════════════════════════════════════════════════
# D — the profile is the one belonging to the model L5 actually CALLS
# ══════════════════════════════════════════════════════════════════════════


def test_the_judge_adapts_to_its_own_model_not_the_run_model(monkeypatch):
    """`VULTURE_VALIDATE_LLM_MODEL` selects the judge's model AND its profile.

    Under TRANSCRIBE the profile reached nothing but a discarded budget hint,
    so `profile_for()` resolving from the ambient model was harmless and the
    module said so. Under ADAPT the profile decides placement and the language
    pin, and the judge may legitimately be calling a different model from the
    rest of the run (`--validate-model`). Adapting the prompt for one model and
    sending it to another is the defect this asserts against.

    It is also why the call site resolves the model to a STRING before
    `profile_for` sees it — that function is `lru_cache`d on its argument, so
    `profile_for()` pins whatever the first caller's environment resolved to
    under the key `None` for the life of the process. Item 4.4 hit the same
    hazard at `generate.domain_instructions` and fixed it the same way.
    """
    pin = _filled("core/language")
    run_model, judge_model = family_models()["openai"], family_models()["glm"]
    assert _profile(run_model).output_language_pin is False, "fixture assumption"
    assert _profile(judge_model).output_language_pin is True, "fixture assumption"

    monkeypatch.setenv("VULTURE_LLM_MODEL", run_model)
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MODEL", judge_model)
    rt = llm_judge._resolve_l5_runtime(ValidateConfig())
    assert rt is not None and rt.model == judge_model, rt
    assert pin in rt.system_prompt, (
        "the judge is calling a language-pinning model with a prompt adapted "
        "for one that does not pin")
    assert pin in llm_judge._judge_system_prompt(BATCH_N, rt.model)

    monkeypatch.delenv("VULTURE_VALIDATE_LLM_MODEL")
    rt2 = llm_judge._resolve_l5_runtime(ValidateConfig())
    assert rt2 is not None and rt2.model == run_model, rt2
    assert pin not in rt2.system_prompt, (
        "the clause survived for a family whose profile does not pin — rule 9 "
        "is not reaching this site")
    assert pin not in llm_judge._judge_system_prompt(BATCH_N, rt2.model)


# ══════════════════════════════════════════════════════════════════════════
# E — the guard is load-bearing, and the mode is what makes it so
# ══════════════════════════════════════════════════════════════════════════


def test_the_gemma_fold_empties_the_system_turn_at_the_source(monkeypatch):
    """The ingredient the assembly guard exists for, read off production.

    Stated separately from the wire assertions because it is the thing that
    would be true whatever the call site did with it: for a no-system-role
    family BOTH judge system prompts render empty, so the naive two-element
    literal could only ever have produced `{"role": "system", "content": ""}`.
    The text is not lost — it is in the user turn, asserted here so "empty" and
    "gone" cannot be confused.
    """
    model = family_models()["gemma"]
    assert _profile(model).system_role is False, "fixture assumption"
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)

    assert llm_judge._judge_system_prompt(BATCH_N, model) == ""
    assert llm_judge._judge_system_prompt_plain(model) == ""
    user = llm_judge._render_user_message(
        "aud-4-1", [(0, _finding(), "python")], "0089aa41", model=model)
    for fid in ("validate/role", "core/untrusted", "validate/output_contract"):
        assert _filled(fid) in user, fid


def test_a_system_role_family_still_gets_a_system_turn(monkeypatch):
    """The control for the test above: the fold is conditional, not universal.

    If it were not, "never send an empty system turn" would be satisfied by
    never sending a system turn at all, and every assertion in this file would
    pass against a judge that had stopped using the role entirely.
    """
    model = family_models()["openai"]
    assert _profile(model).system_role is True, "fixture assumption"
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)

    system = llm_judge._judge_system_prompt(BATCH_N, model)
    assert _filled("validate/role") in system
    assert _filled("validate/tool_discipline") in system
    plain = llm_judge._judge_system_prompt_plain(model)
    assert _filled("validate/role") in plain
    assert _filled("validate/tool_discipline") not in plain


def test_the_flip_is_what_moves_these_bytes(monkeypatch):
    """ADAPT is doing the work, not a fragment edit — measured, both specs.

    The scaffold note for this item recorded the judge as rendering
    byte-identical under both modes on the default profile, with only
    `response_format` differing. That was true when it was written and items
    4.7 (the mirror) and 4.8 (the language pin) have since made it false, so
    the claim is re-measured here rather than inherited: on the DEFAULT
    profile the two modes now differ in both turns, which is why this item
    re-captures goldens and moves `_VERDICT_SCHEMA_VERSION`.
    """
    model = family_models()["openai"]
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)
    profile = _profile(model)
    for spec_id in ("validate_judge", "validate_judge_plain"):
        spec = replace(MANIFESTS[spec_id], variables={"n": BATCH_N})
        t = render(spec, profile, mode=Mode.TRANSCRIBE)
        a = render(spec, profile, mode=Mode.ADAPT)
        assert t.fingerprint != a.fingerprint, spec_id
        # The mirror moves text INTO the user turn; the language pin moves
        # text OUT of the system turn. Both, or the item is half-applied.
        assert len(a.user) > len(t.user), spec_id
        assert len(a.instructions) < len(t.instructions), spec_id
