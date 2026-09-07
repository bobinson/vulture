"""Feature 0089 Phase 1 — the ASSEMBLED generate prompt, byte for byte.

Phase 0.c proved each fragment's text appears VERBATIM *somewhere* in the live
builder's output (`test_0089_manifest_generate.py::
test_generate_fragments_are_byte_exact`, which asserts `text in original`).
Containment is not parity. Three defects survive an `in` test untouched:

* a line the live builder emits that NO fragment transcribes — the assembled
  render is simply short, and every individual fragment still matches;
* two fragments in the wrong ORDER — both are still `in` the original;
* a different SEPARATOR between two adjacent fragments — `"\\n"` in the
  builder against `"\\n\\n"` in `render`, invisible to a containment check and
  invisible to any assertion that normalises whitespace.

This file closes that gap. For each of the seven agents that HAS an LLM
generate path it assembles the prompt twice — once through
`shared.audit_runner`, once through `shared.prompt.render` — and compares the
bytes of BOTH roles. Nothing here normalises, trims, lowercases, sorts, counts
or `in`-tests: the two assertions are `==` on the whole role string, which is
the only comparison that can catch all three defects above.

WHY THE UNSTRUCTURED BRANCH. The builder appends `generate/json_fenced`'s
sentence only when `supports_structured_output()` is False, and the seven
committed specs list that fragment unconditionally — so they mirror the
unstructured branch, and that is the branch compared here. Under ADAPT the
mirroring is the renderer's rule 4+5 rather than TRANSCRIBE's "render
everything", which is why `MODEL` must resolve to a `Structured.NONE`
profile as well as to a False `supports_structured_output`. The branch is
*selected by the live function*, not asserted by this file: `_live_prompt`
resolves the model through `get_model_with_fallback` and checks
`supports_structured_output` before it builds anything, so if that predicate
ever changes for this model the precondition fails loudly instead of silently
comparing against the wrong half of an `if`.

FIVE SECTIONS HAVE NO LIVE COUNTERPART, AND PHASE 4 IS WHY. Three parts of the
system turn are still read from the pre-library builder — the agent's own
`INSTRUCTIONS` literal, `_category_vocabulary_suffix`, and the inline JSON
sentence read with `ast` — so that much of the live side is genuinely
independent of the library. The rest is not, and each one names the item that
spent it:

* `core/untrusted` (item 4.3) — the tier had NO untrusted-content text at all
  before it, which is the defect that item fixes (raw repository source inlined
  with zero marking, `audit_runner.py:3038`, 0089 LLD §9.2);
* `generate/source_presentation`, `generate/evidence_discipline`,
  `generate/tool_trigger`, `generate/vocab_severity` (item 4.4) — four
  sentences the tier never had. The `--- path ---` / `NN: ` contract was never
  stated, three file tools were attached with no sentence permitting their use,
  and `severity`'s closed set was silently coerced rather than named.

There is nothing pre-library to read any of the five from, so
`_library_only_section()` below takes their text from the fragment and this
file no longer has an opinion about those bytes.

What it still has an opinion about, for each, is its POSITION and its SEAM,
both of which are literals here — insert one elsewhere in the turn, or join it
with one newline instead of two, and this fails. What is genuinely unobserved
is a reword of the text itself, and that is pinned by
`test_0089_version_bump.py`, which exists for precisely this: a Phase 4 item
spends a parity oracle, and the hand-written digest in that file becomes the
fragment's pin.

ITEM 4.4 ALSO FLIPPED THE MODE. Both of this tier's call sites render
`Mode.ADAPT` now, so the expected side below does too — the live side calls
`_build_llm_prompt`, which IS one of them. On `MODEL` the two modes are
byte-identical (gemini has a system role and `Structured.NONE`, so neither the
fold nor rule 4+5 bites), which is what makes the flip show up here as "nothing
moved" rather than as a diff.

HERMETIC. No network, no model call, no agent-package import (each agent's
`INSTRUCTIONS` is read with `ast`, as Phase 0.c reads it). The two knobs that
move the prompt's bytes — `VULTURE_LLM_QUOTE_REQUIRED` and
`VULTURE_LLM_QUOTE_MAX_LINES`, both read at call time — are pinned to their
shipped defaults so an operator's ambient env cannot fake either a pass or a
failure.
"""

from __future__ import annotations

import ast
import dataclasses
import difflib
from pathlib import Path

import pytest

from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests.generate import GENERATE_SPECS

# tests/unit/prompt/<this file> -> prompt -> unit -> tests -> shared -> agents
AGENTS_DIR = Path(__file__).resolve().parents[4]

# Discovered empirically, not assumed: `grep -rn run_combined_audit agents/*/`
# reports exactly these seven agent packages as call sites (`owasp` is a
# categorizer over CWE findings with no LLM path, and `discover` documents in
# its own source that it does not route through the runner). Asserted against
# `GENERATE_SPECS` in `test_parity_covers_every_generate_agent` below, so a new
# agent cannot be added to one side alone.
AGENT_PACKAGES: dict[str, str] = {
    "asvs": "asvs/asvs_agent/agent.py",
    "chaos": "chaos_engineering/chaos_agent/agent.py",
    "cwe": "cwe/cwe_agent/agent.py",
    "do178c": "do178c/do178c_agent/agent.py",
    "soc2": "soc2/soc2_agent/agent.py",
    "ssdf": "ssdf/ssdf_agent/agent.py",
    "xss": "xss/xss_agent/agent.py",
}

# xss keeps its instructions in a sibling .md instead of a module constant.
XSS_INSTRUCTIONS = AGENTS_DIR / "xss" / "xss_agent" / "INSTRUCTIONS.md"

AGENTS = tuple(sorted(AGENT_PACKAGES))

# ── the ONE set of inputs both sides are fed ──────────────────────────────
#
# Per-agent inputs (`INSTRUCTIONS`, `domain_label`) are read from each agent's
# own source below. The rest are fixed literals, identical on both sides, so
# any difference in the output is a difference between the two ASSEMBLERS.
#
# `VOCABULARY` is deliberately non-empty for all seven. Only chaos, soc2 and
# ssdf pass `category_enum=` at their call site today, and
# `_category_vocabulary_suffix` returns "" for a falsy vocabulary — feeding the
# empty case would compare a rendered CATEGORY VOCABULARY block against nothing
# and manufacture a mismatch out of an input choice rather than out of drift.
# The non-empty case is the one that actually exercises the fragment's bytes.
SOURCE_PATH = "/src/target"
CATEGORIES = ["alpha", "beta"]
VOCABULARY = frozenset({"ALPHA", "BETA"})
SOURCE_BODY = "30: def handler(req):\n31:     return eval(req.body)"
PRIOR_CONTEXT = ""

# gemini is the shipped model family for which `supports_structured_output`
# is False, i.e. the unstructured branch TRANSCRIBE mirrors. Chosen for that
# predicate, and the predicate is re-checked at run time in `_live_prompt`.
MODEL = "gemini-2.5-flash"


@pytest.fixture(autouse=True)
def _pin_prompt_knobs(monkeypatch):
    """Pin the two env knobs that move the prompt's bytes to their defaults."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "true")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "3")
    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)


# ── reading the live bytes without importing the agent packages ───────────

def _module_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _str_constant(node: ast.AST) -> str | None:
    """The value of a plain string literal, else None (an f-string included).

    Narrow on purpose: every `INSTRUCTIONS` constant in the fleet is a plain
    literal today, so an f-string here means the constant grew a substitution
    the prompt library has not transcribed — a failure, not a value to guess.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _instructions(agent: str) -> str:
    """The agent's own system prompt, exactly as the agent package holds it."""
    if agent == "xss":
        return XSS_INSTRUCTIONS.read_text(encoding="utf-8")
    tree = _module_ast(AGENTS_DIR / AGENT_PACKAGES[agent])
    found = [
        value
        for node in ast.walk(tree)
        if any(
            isinstance(t, ast.Name) and t.id == "INSTRUCTIONS"
            for t in getattr(node, "targets", ())
        )
        and (value := _str_constant(node.value)) is not None
    ]
    assert len(found) == 1, f"{agent}: expected one INSTRUCTIONS literal, got {len(found)}"
    return found[0]


def _run_combined_audit_calls(tree: ast.Module) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_combined_audit"
    ]


def _domain_label(agent: str) -> str:
    """The `domain_label=` this agent passes at its own call site."""
    tree = _module_ast(AGENTS_DIR / AGENT_PACKAGES[agent])
    labels = [
        value
        for call in _run_combined_audit_calls(tree)
        for kw in call.keywords
        if kw.arg == "domain_label" and (value := _str_constant(kw.value)) is not None
    ]
    assert len(labels) == 1, f"{agent}: expected one domain_label, got {labels}"
    return labels[0]


# The seam between two appended system blocks, as a literal: the live builder
# joins every one of them with a blank line (`_category_vocabulary_suffix` and
# the JSON sentence both open `"\n\n"`), and `_generate_system_prompt` spells
# the identity seam `f"{head}\n\n{suffix}"`.
_UNTRUSTED_SEAM = "\n\n"

# What each library-only section interpolates, supplied here as literals so the
# expected side never shares a reading with the code under test. The two tool
# budgets are `shared.llm.loop_detector`'s, cross-checked against the detector
# it configures by `test_0089_parity_generate_repair.py::
# test_the_pinned_tool_budgets_are_the_ones_the_loop_guard_enforces`.
_SECTION_VARIABLES = {"tool_call_budget": "100", "tool_repeat_budget": "20"}


def _library_only_section(fragment_id: str) -> str:
    """One section of the turn that has no pre-library source. See the docstring.

    Read from the fragment because there is nothing else to read it from. The
    seam and the insertion point are this file's own literals, so ordering and
    join width remain independently checked.
    """
    from shared.prompt.registry import get

    text = get(fragment_id).text
    for name, value in _SECTION_VARIABLES.items():
        text = text.replace("{" + name + "}", value)
    return _UNTRUSTED_SEAM + text.rstrip("\n")


def _json_fenced_literal() -> str:
    """The unstructured branch's JSON sentence, read out of the live builder.

    It is an inline literal, not behind a function, so there is nothing to
    call. The shape asserted here IS the live statement —
    `augmented_instructions += (<literal>)` — so a reworded literal changes
    these bytes and a restructured statement fails the assertions instead of
    quietly matching.

    BEFORE feature 0089 item 4.4 the statement added a second term,
    `+ _quote_contract_suffix()`, and this asserted that shape::

        assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
        assert value.right.func.id == "_quote_contract_suffix"

    4.4 removed the placement and the function. The assertion that no second
    term exists takes its place, so a re-appended copy of any sentence fails
    here instead of being silently taken as the left operand.
    """
    from shared import audit_runner as ar

    tree = _module_ast(Path(ar.__file__))
    found = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "augmented_instructions"
    ]
    assert len(found) == 1, f"expected one `augmented_instructions +=`, got {len(found)}"
    value = found[0]
    assert not isinstance(value, ast.BinOp), (
        "the unstructured branch appends a second term again; item 4.4 left it "
        "one literal, and a second term is a second author"
    )
    literal = _str_constant(value)
    assert literal, "the JSON-array sentence is no longer a plain literal"
    return literal


# ── the two assemblers ────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class Assembled:
    """The two role strings one generate call is built from."""

    instructions: str
    user: str


def _live_prompt(agent: str) -> Assembled:
    """The prompt `shared.audit_runner` builds for `agent`, from live code."""
    from shared import audit_runner as ar
    from shared.llm.provider import get_model_with_fallback, supports_structured_output

    resolved = get_model_with_fallback(MODEL)
    # Preconditions, so the comparison below cannot silently target the wrong
    # branch of the builder's two `if`s.
    assert not supports_structured_output(resolved), (
        f"{resolved!r} now supports structured output; the unstructured branch "
        "Mode.TRANSCRIBE mirrors is unreachable with this model"
    )
    assert "anthropic" not in resolved, (
        f"{resolved!r} is an anthropic model; the builder would move the source "
        "body into the system turn (generate/source_in_system)"
    )

    # `_category_vocabulary_suffix(current_category_enum())` is the live line;
    # `current_category_enum()` would return exactly this frozenset, so the
    # vocabulary is passed straight in rather than bound through the ContextVar.
    instructions = (_instructions(agent) or "") + _library_only_section("core/untrusted")
    for fid in ("generate/source_presentation", "generate/evidence_discipline",
                "generate/tool_trigger"):
        instructions += _library_only_section(fid)
    instructions += ar._category_vocabulary_suffix(VOCABULARY)
    instructions += _library_only_section("generate/vocab_severity")
    instructions += _json_fenced_literal()
    # `vocabulary` and `fenced` are the SAME two facts the instructions above
    # are built from, and until item 4.7 this call passed neither — it took the
    # defaults (`vocabulary=None`, `fenced=False`), i.e. the branch with no
    # category enum and no JSON contract, while the string two lines up appended
    # both. The mismatch could not be observed: `generate/vocab_category` and
    # `generate/json_fenced` are SYSTEM fragments, and the live system turn here
    # is hand-assembled rather than read from `_generate_system_prompt`, so
    # neither ever reached the role this call returns. Item 4.7 mirrors the JSON
    # contract into the user turn, which is the first time the branch the file's
    # own docstring says it compares ("WHY THE UNSTRUCTURED BRANCH") had to
    # actually be the branch requested. Passing them widens the comparison; it
    # does not relax it.
    user = ar._build_llm_prompt(
        SOURCE_PATH, CATEGORIES, _domain_label(agent), SOURCE_BODY, PRIOR_CONTEXT,
        vocabulary=VOCABULARY, fenced=True,
    )
    return Assembled(instructions=instructions, user=user)


def _rendered_prompt(agent: str) -> Assembled:
    """The prompt the library renders for `agent`, from the shipped spec.

    `variables` is the only thing supplied here: the specs ship with none, and
    `generate/vocab_category` / `generate/source_inline` carry `{...}`
    placeholders the renderer's own `_fill` resolves. A real call site supplies
    them the same way. No fragment text and no spec field is otherwise touched.
    """
    spec = dataclasses.replace(
        GENERATE_SPECS[agent],
        variables={
            "source_context": SOURCE_BODY,
            "category_vocabulary": ", ".join(sorted(VOCABULARY)),
            # `_build_llm_prompt` interpolates FOUR values; only two were
            # supplied here, so the task preamble could not match by
            # construction. Completing the fixture widens what this test
            # compares (four interpolations, not two) rather than relaxing it.
            "source_path": SOURCE_PATH,
            "domain_label": _domain_label(agent),
            "categories": ", ".join(CATEGORIES),
            # The same completion, for the same reason. `generate/quote_
            # obligation` interpolates the bound rather than stating "1-3",
            # because `audit_runner._quote_obligation()` reads the verifier's
            # own VULTURE_LLM_QUOTE_MAX_LINES at call time (0076 §5.2 property
            # 3) and a fragment that froze the default would stop tracking it.
            # Fed as the PINNED literal the `_pin_prompt_knobs` fixture sets,
            # not by calling `_quote_max_lines()` — one reading shared by both
            # sides would move them together.
            "quote_max_lines": "3",
            # Item 4.4's two tool budgets, as literals for the same reason.
            **_SECTION_VARIABLES,
        },
    )
    rp = render(spec, profile_for(MODEL), mode=Mode.ADAPT)
    return Assembled(instructions=rp.instructions, user=rp.user)


# ── reporting ─────────────────────────────────────────────────────────────

def _role_diff(role: str, live: str, rendered: str) -> list[str]:
    if live == rendered:
        return [f"  {role}: byte-identical ({len(live.encode())} bytes)"]
    head = (
        f"  {role}: MISMATCH  live={len(live.encode())}B "
        f"rendered={len(rendered.encode())}B"
    )
    body = difflib.unified_diff(
        live.splitlines(keepends=True),
        rendered.splitlines(keepends=True),
        fromfile=f"live/audit_runner:{role}",
        tofile=f"rendered/prompt-library:{role}",
        n=1,
    )
    return [head, *(line.rstrip("\n") for line in body)]


def _report(agent: str, live: Assembled, rendered: Assembled) -> str:
    """Both roles' diffs in one message, so whichever assert fires shows all."""
    return "\n".join([
        f"generate/{agent}: assembled prompt is not byte-identical",
        *_role_diff("instructions", live.instructions, rendered.instructions),
        *_role_diff("user", live.user, rendered.user),
    ])


# ── the seven parity tests ────────────────────────────────────────────────

@pytest.mark.parametrize("agent", AGENTS)
def test_generate_prompt_is_byte_identical(agent: str):
    """`render(GENERATE_SPECS[agent])` reproduces the live builder's bytes.

    One test per agent because the agents differ in exactly the inputs that
    reach the prompt — their `INSTRUCTIONS` and their `domain_label` — so a
    drift in one agent's transcription must name that agent.
    """
    live = _live_prompt(agent)
    rendered = _rendered_prompt(agent)
    report = _report(agent, live, rendered)

    assert rendered.instructions == live.instructions, report
    assert rendered.user == live.user, report


def test_parity_covers_every_generate_agent():
    """The seven parameterized cases are the seven specs, with none exempt."""
    assert set(AGENTS) == set(GENERATE_SPECS)
    assert set(AGENTS) == set(AGENT_PACKAGES)
    assert len(AGENTS) == 7
    for agent in AGENTS:
        assert (AGENTS_DIR / AGENT_PACKAGES[agent]).is_file(), agent
    assert XSS_INSTRUCTIONS.is_file()
