"""Feature 0089 Phase 1 — REPAIR of the generate parity claim. Three defects.

`test_0089_parity_generate.py` asserts `render(GENERATE_SPECS[agent])` equals
`audit_runner`'s bytes for all seven generate agents, and the red team
confirmed both of its `==` are genuine: mutating a fragment moves only the
rendered side, mutating the builder only the live side, and it hardcodes no
expected prompt text. Three things it nonetheless could not see. This file
closes each. Every assertion here is `==` on a whole role string, a whole
fragment pair, or a whole byte run; nothing is normalised, trimmed,
lowercased, sorted or `in`-tested, and no test asserts a length in place of
the bytes.

1. NEWLINE BLINDNESS — the one place "compare BYTES" did not.
   `render`'s join drops each part's TRAILING newline run and the joined
   body's LEADING run. Five bytes added to `generate/field_contract`'s
   boundaries (+2 leading, +3 trailing) left all seven `rendered.user` strings
   byte-identical, so a compared fragment's boundary newlines were outside the
   reach of ANY assertion made against `render`'s output. The normalisation is
   in PRODUCTION, so the parity test neither caused it nor could cure it — but
   it need not be the only witness.

   Those bytes are not decoration. `generate/task`'s trailing newline IS the
   seam between the audit-target lines and the field contract, and
   `domains/asvs` / `domains/xss` carry the trailing newline their agents'
   `INSTRUCTIONS` constants end with. `test_live_roles_are_the_raw_fragment_
   bytes` rebuilds both live roles from the fragments' RAW bodies with each
   live seam spelled out and asserts them against the live builder, which
   strips nothing — so every one of those runs now fails a test if it changes,
   whatever the renderer does with it. `test_pinned_boundary_runs_*` pins the
   runs themselves, and that is the assertion the +2/+3 mutation fails.

2. A DELTA COUNT IN PROSE GOES STALE; AN ENUMERATED SEAM DOES NOT.
   The transcription is not at parity, and "exactly three deltas, four for
   asvs and xss" has already been restated twice by concurrent work — the
   renderer has since grown per-fragment `seam` / `keep_trailing`, which moves
   the boundary from unrepresentable to undeclared. So nothing here counts
   deltas or freezes an inventory. `test_each_seam_renders_the_live_bytes`
   parametrizes over EVERY adjacent fragment pair in all seven specs and
   compares that pair's rendered bytes to its live bytes, so an unsatisfied
   seam is one named red case, a satisfied one goes green on its own, and a
   NEW gap appears as a new red case. The count is a test outcome, never a
   literal in this file, and there is no table to keep in step.

3. THE VOCABULARY SORT WAS ONLY PROBABILISTICALLY UNDER TEST.
   `_category_vocabulary_suffix` sorts, and its docstring makes the sort
   load-bearing ("two identical audits build an identical prompt — an unstable
   system message would defeat prompt caching"). Deleting `sorted()` left the
   parity equality TRUE, because a two-element `frozenset({"ALPHA","BETA"})`
   happens to iterate in sorted order under some hash seeds (measured: sorted
   at PYTHONHASHSEED 0/5/7919, unsorted at 1/2/3/4/42) — a removed sort was a
   coin-flip intermittent failure. Here the live side is fed the vocabulary as
   an ORDERED, deliberately unsorted tuple as well as as a frozenset, and the
   two members are replaced by four mixing digit- and letter-leading
   identifiers (`A01`, `ALPHA`, `B02`, `zeta`).
   `_category_vocabulary_suffix` takes any iterable (`sorted(allowed)`), and
   order-insensitivity is the property under test, so an ordered input is the
   only input that can observe it.

VARIABLES ARE MERGED, NOT REPLACED. `dataclasses.replace(spec, variables=
{...})` discards whatever the spec declared — the trap the red team flagged as
hypothetical, which concurrent work has since made real and reverted twice.
Every dict here is `{**spec.variables, **_per_run(agent)}` with the key sets
asserted disjoint. `domain_label` is fed to the render from a PINNED table and
read from the agent's own call site by `ast` for the live side — never one
reading shared by both, which would move the two sides of every comparison
together; the manifest's copy is cross-checked too, when it ships one.

HERMETIC, as the parity test is: no network, no model call, no agent-package
import. The AST readers are DUPLICATED from the parity test rather than
imported, deliberately — an independent assembler must not inherit the
assumptions of the one it checks.
"""

from __future__ import annotations

import ast
import dataclasses
import difflib
from pathlib import Path

import pytest

from shared.prompt import Mode, profile_for, registry, render
from shared.prompt.fragment import Role, Stance
from shared.prompt.manifests.generate import GENERATE_SPECS
from shared.prompt.spec import PromptSpec

# tests/unit/prompt/<this file> -> prompt -> unit -> tests -> shared -> agents
AGENTS_DIR = Path(__file__).resolve().parents[4]

AGENT_PACKAGES: dict[str, str] = {
    "asvs": "asvs/asvs_agent/agent.py",
    "chaos": "chaos_engineering/chaos_agent/agent.py",
    "cwe": "cwe/cwe_agent/agent.py",
    "do178c": "do178c/do178c_agent/agent.py",
    "soc2": "soc2/soc2_agent/agent.py",
    "ssdf": "ssdf/ssdf_agent/agent.py",
    "xss": "xss/xss_agent/agent.py",
}
XSS_INSTRUCTIONS = AGENTS_DIR / "xss" / "xss_agent" / "INSTRUCTIONS.md"
AGENTS = tuple(sorted(AGENT_PACKAGES))

# gemini is the shipped family for which `supports_structured_output` is False,
# i.e. the unstructured branch TRANSCRIBE mirrors. Re-checked at run time in
# `_assert_branch_preconditions`, so a comparison cannot silently target the
# wrong half of the builder's `if`.
MODEL = "gemini-2.5-flash"

SOURCE_PATH = "/src/target"
CATEGORIES = ["alpha", "beta"]

# Deliberately carries NO boundary newline: a substituted value that began or
# ended with "\n" would manufacture a boundary run the pins below do not know
# about, and repair (1) would then be pinning the input instead of the
# fragment. `test_substituted_values_carry_no_boundary_newlines` asserts it.
SOURCE_BODY = "30: def handler(req):\n31:     return eval(req.body)"
PRIOR_CONTEXT = ""

# Repair (3). Four members mixing a digit-leading identifier, letter-leading
# ones and one lowercase, so sorted order is not the order of any literal here.
VOCAB_MEMBERS: tuple[str, ...] = ("A01", "ALPHA", "B02", "zeta")
VOCAB_SORTED_TEXT = ", ".join(sorted(VOCAB_MEMBERS))
# The two shapes the live builder is fed. `frozenset` is the shipped type
# (`current_category_enum()` returns one); the tuple is a fixed permutation
# that is NOT sorted, which is what makes the live `sorted()` observable
# independently of PYTHONHASHSEED.
VOCAB_UNSORTED_TUPLE: tuple[str, ...] = ("zeta", "ALPHA", "A01", "B02")
VOCAB_INPUTS = (
    pytest.param(frozenset(VOCAB_MEMBERS), id="frozenset"),
    pytest.param(VOCAB_UNSORTED_TUPLE, id="unsorted-tuple"),
)


@pytest.fixture(autouse=True)
def _pin_prompt_knobs(monkeypatch):
    """Pin the two env knobs that move the prompt's bytes to their defaults."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "true")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "3")
    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)


# ── the pinned tables: bytes and seams `render` cannot be asked about ─────
#
# `lead` / `trail` are the fragment body's LEADING and TRAILING newline runs.
# A fragment that does not declare `keep_trailing` loses its trailing run in
# the render, so those bytes cannot be asserted through `render`'s output
# (repair 1); pinning them here is the only place a change to them fails.
# `role` is pinned too because `Mode.TRANSCRIBE` ignores front matter
# entirely: flipping `generate/field_contract` to `role: SYSTEM` moves ZERO
# rendered bytes, so nothing else in this tier would notice.


@dataclasses.dataclass(frozen=True)
class Pin:
    lead: str
    trail: str
    role: Role


# `asvs` and `xss` are the two agents whose INSTRUCTIONS constant ends with a
# newline; their domain fragment transcribes it.
_DOMAIN_TRAIL = {a: ("\n" if a in ("asvs", "xss") else "") for a in AGENTS}

PINS: dict[str, Pin] = {
    **{
        f"domains/{a}": Pin(lead="", trail=_DOMAIN_TRAIL[a], role=Role.SYSTEM)
        for a in AGENTS
    },
    # Item 4.3. No trailing run, like every other fragment in this tier: the
    # GENERATE fragments transcribe Python string literals, not lines of a
    # prompt file, and a trailing newline here would be one the live builder
    # never emitted. (`core/untrusted` is also listed by both judge specs,
    # whose own fragments do end with one — the two conventions are reconciled
    # on `test_0089_parity_validate_assembly.py::
    # test_validate_fragment_files_carry_exactly_one_terminator`.)
    # Item 4.7. ROLE CHANGED on both of these, and the change is the item:
    # `SYSTEM` -> `SYSTEM+USER_MIRROR`, so each is now emitted in the system turn
    # AND at the front of the user turn (LLD rule 2 — "the marker rule" and "the
    # output contract"). The bodies are untouched, which is why only the `role`
    # column moves and the two newline runs do not. Note the pin's standing
    # reason has GAINED force rather than lost it: TRANSCRIBE still ignores front
    # matter, so this flip is invisible to every TRANSCRIBE golden in the tree,
    # and under ADAPT it now moves real bytes — a revert would be silent in the
    # first mode and lossy in the second.
    "core/untrusted": Pin(lead="", trail="", role=Role.SYSTEM_USER_MIRROR),
    "generate/vocab_category": Pin(lead="", trail="", role=Role.SYSTEM),
    "generate/json_fenced": Pin(lead="", trail="", role=Role.SYSTEM_USER_MIRROR),
    "generate/task": Pin(lead="", trail="", role=Role.USER),
    "generate/field_contract": Pin(lead="", trail="", role=Role.USER),
    # Item 4.4. ROLE CHANGED, and the change is the item. This was
    # `Role.SYSTEM_USER_MIRROR` and the fragment was listed in BOTH turns,
    # because `_field_contract()` returned the sentence and
    # `_quote_contract_suffix()` appended it again — but only on the
    # unstructured branch, so a structured-output model was told to quote its
    # evidence once and an LM Studio / Gemini model twice. It is `USER` now and
    # listed once. The mirror role could not have served: ADAPT prepends a
    # mirrored fragment to the user turn WITHOUT removing it from the system
    # turn, so listed-in-both plus mirrored renders three copies.
    "generate/quote_obligation": Pin(lead="", trail="", role=Role.USER),
    "generate/source_inline": Pin(lead="", trail="", role=Role.USER),
    # The four sections item 4.4 added. Same convention as the rest of the
    # tier: no boundary newline runs, so the `.md` files carry no terminator.
    "generate/source_presentation": Pin(lead="", trail="", role=Role.SYSTEM),
    "generate/evidence_discipline": Pin(lead="", trail="", role=Role.SYSTEM),
    "generate/tool_trigger": Pin(lead="", trail="", role=Role.SYSTEM),
    "generate/vocab_severity": Pin(lead="", trail="", role=Role.SYSTEM),
    # Item 4.8. Same convention again — no boundary runs — which is what lets
    # one file serve this tier and VALIDATE, whose own fragments end with
    # exactly one newline (`test_0089_parity_validate_assembly.py` scopes that
    # rule to `validate/` ids for this reason).
    "core/language": Pin(lead="", trail="", role=Role.SYSTEM),
}

# The bytes the LIVE builder puts BETWEEN two adjacent fragments' RAW bodies,
# read off `audit_runner` and spelled out rather than produced by a join, so a
# separator change fails a test instead of being absorbed by one:
#
#   augmented_instructions + _category_vocabulary_suffix(...)  -> "\n\n" opener
#   augmented_instructions += ("\n\nIMPORTANT: ...")           -> "\n\n" opener
#   _quote_contract_suffix -> f"\n{_quote_obligation()}"       -> "\n"
#   _build_llm_prompt      -> "\n".join(parts)                 -> "\n"
#
# `_build_llm_prompt` puts BOTH of `generate/task`'s lines in that same
# `"\n".join`, so the seam that follows it is a single newline like the ones
# between the field-contract lines — which is why it is pinned per PAIR here
# and not inferred from a fragment's position.
_SEAM_INSTRUCTIONS_TO_VOCAB = "\n\n"
# Item 4.3 inserted `core/untrusted` between the agent identity and the
# vocabulary block, so the seam that used to run identity -> vocab is now two
# seams of the same width. Both are pinned, and both are literals here rather
# than derived from `Fragment.seam`, for this table's standing reason: a seam
# read from the same declaration the renderer reads would move both sides of
# the comparison together.
LIVE_SEAMS: dict[tuple[str, str], str] = {
    **{
        (f"domains/{a}", "core/untrusted"): _SEAM_INSTRUCTIONS_TO_VOCAB
        for a in AGENTS
    },
    # Item 4.4 inserted three sections between the policy and the vocabulary
    # block and one more between the two vocabularies, all at the tier's one
    # system-turn width. `("generate/json_fenced", "generate/quote_obligation")`
    # is GONE from this table because that adjacency is gone: the quote
    # obligation is a user-turn fragment now and the fenced sentence ends the
    # system turn.
    ("core/untrusted", "generate/source_presentation"): "\n\n",
    ("generate/source_presentation", "generate/evidence_discipline"): "\n\n",
    ("generate/evidence_discipline", "generate/tool_trigger"): "\n\n",
    ("generate/tool_trigger", "generate/vocab_category"): "\n\n",
    ("generate/vocab_category", "generate/vocab_severity"): "\n\n",
    ("generate/vocab_severity", "generate/json_fenced"): "\n\n",
    ("generate/task", "generate/field_contract"): "\n",
    ("generate/field_contract", "generate/quote_obligation"): "\n",
    ("generate/quote_obligation", "generate/source_inline"): "\n\n",
    # Item 4.7's two NEW adjacencies, both in the USER turn: rule 2 prepends the
    # mirrored marker rule and the mirrored wire shape ahead of `generate/task`,
    # at the tier's ordinary blank-line width. `("core/untrusted",
    # "generate/json_fenced")` is a different PAIR from the system turn's
    # `("core/untrusted", "generate/source_presentation")` even though the left
    # side is the same fragment — which is the reason this table is keyed on
    # pairs and not on a per-fragment "seam before me".
    ("core/untrusted", "generate/json_fenced"): "\n\n",
    ("generate/json_fenced", "generate/task"): "\n\n",
}

# The placeholders the templated fragments interpolate, pinned so a rename
# cannot leave a literal `{name}` standing in the prompt as though it were a
# byte of content. `domains/xss` also matches the placeholder pattern, on a
# literal `{var}` inside its prose that nothing supplies and both sides
# therefore render identically — it is content, not a template, so it is not
# listed and not filled.
PLACEHOLDERS: dict[str, frozenset[str]] = {
    "generate/task": frozenset({"source_path", "domain_label", "categories"}),
    "generate/vocab_category": frozenset({"category_vocabulary"}),
    "generate/source_inline": frozenset({"source_context"}),
    # `audit_runner._quote_obligation()` states the bound from the verifier's
    # own VULTURE_LLM_QUOTE_MAX_LINES, read at call time (0076 §5.2 property
    # 3): a model told "1-3 lines" while the verifier clamps at 2 would be
    # refused for doing exactly what it was asked. So the fragment interpolates
    # the number instead of freezing the default, and it is pinned here for the
    # same reason the other three are — a rename would leave a literal
    # `{quote_max_lines}` standing in the prompt as though it were content.
    "generate/quote_obligation": frozenset({"quote_max_lines"}),
    # Item 4.4. Both budgets are read from `shared.llm.loop_detector`, the
    # module whose `LoopDetector.record` returns KILL at exactly these two
    # counts, rather than retyped into the fragment — a prompt that promises a
    # bound nothing enforces teaches the model a rule it can break for free.
    "generate/tool_trigger": frozenset({"tool_call_budget", "tool_repeat_budget"}),
}

# The `domain_label=` each agent passes at its own `run_combined_audit` call
# site (a real parameter of that function, defaulted to "categories"), pinned
# as DATA — the third pinned table, and the one the lever made necessary.
#
# `generate/task` is new and interpolates `{domain_label}`, and the manifest
# ships no `variables`, so the label is no longer a spec constant the render
# inherits: it is a per-run value a call site supplies. If the value fed to the
# render were read by the same `ast` walk `_live` uses, a relabelled call site
# would move BOTH sides at once and nothing here could see it. Measured, with
# `_per_run` reading it live: changing cwe's to "CWE weaknesses" left all 85
# cases in this file green, and the whole `tests/unit/prompt` suite unmoved.
# So the render is fed the pinned literal and the live builder the `ast`
# reading — the same two-independent-sources discipline as `LIVE_SEAMS`.
# The two tool budgets `generate/tool_trigger` interpolates, pinned as DATA for
# the reason `LIVE_SEAMS` and `CALL_SITE_DOMAIN_LABELS` are: a value read from
# `shared.llm.loop_detector` here would move both sides of every comparison in
# this file together. `test_the_pinned_tool_budgets_are_the_ones_the_loop_guard_
# enforces` is where these two literals meet the code that enforces them, and it
# drives the real `LoopDetector` rather than comparing constant to constant.
PINNED_TOOL_CALL_BUDGET = "100"
PINNED_TOOL_REPEAT_BUDGET = "20"

CALL_SITE_DOMAIN_LABELS: dict[str, str] = {
    "asvs": "ASVS requirements",
    "chaos": "resilience categories",
    "cwe": "CWE categories",
    "do178c": "DO-178C objectives",
    "soc2": "SOC2 clauses",
    "ssdf": "SSDF practice groups",
    "xss": "XSS categories",
}


# ── reading the live bytes without importing the agent packages ───────────

def _module_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _str_constant(node: ast.AST) -> str | None:
    """The value of a plain string literal, else None (an f-string included)."""
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


def _domain_label(agent: str) -> str:
    """The `domain_label=` this agent passes at its own call site."""
    tree = _module_ast(AGENTS_DIR / AGENT_PACKAGES[agent])
    labels = [
        value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "run_combined_audit"
        for kw in call.keywords
        if kw.arg == "domain_label" and (value := _str_constant(kw.value)) is not None
    ]
    assert len(labels) == 1, f"{agent}: expected one domain_label, got {labels}"
    return labels[0]


def _json_fenced_literal() -> str:
    """The unstructured branch's JSON sentence, read out of the live builder.

    The shape asserted here IS the live statement — `augmented_instructions +=
    (<literal>)` — so a reworded literal changes these bytes and a restructured
    statement fails loudly instead of quietly matching.

    BEFORE feature 0089 item 4.4 the statement was `augmented_instructions +=
    (<literal>) + _quote_contract_suffix()`, and this function asserted that
    shape::

        assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
        assert value.right.func.id == "_quote_contract_suffix"

    4.4 removed the second term and the function it called. The assertion that
    NO call is added is kept in its place — otherwise a future edit could
    re-append a second copy of any sentence and this reader would simply take
    the left operand and report nothing.
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


# ── variables: merged, and `domain_label` pinned against the call site ───

def _per_run(agent: str) -> dict[str, str]:
    """What a CALL SITE supplies, `domain_label` from the PINNED table.

    Pinned rather than read from the call site by `ast`, because `_live` reads
    it that way: one shared reading would move both sides of every comparison
    together and make a relabelled call site undetectable here (measured — see
    `CALL_SITE_DOMAIN_LABELS`). `test_spec_transcribes_the_call_sites_domain_
    label` is where the two readings meet.
    """
    return {
        "source_path": SOURCE_PATH,
        "categories": ", ".join(CATEGORIES),
        "source_context": SOURCE_BODY,
        "category_vocabulary": VOCAB_SORTED_TEXT,
        "domain_label": CALL_SITE_DOMAIN_LABELS[agent],
        # The quote bound `generate/quote_obligation` interpolates. Pinned as a
        # literal, like `domain_label`, and matching what `_pin_prompt_knobs`
        # sets: reading it from `_quote_max_lines()` would be the one reading
        # shared by both sides of every comparison here.
        "quote_max_lines": "3",
        # The two tool budgets `generate/tool_trigger` interpolates. Pinned as
        # literals for this table's standing reason — reading them from
        # `loop_detector` here would be one reading shared by both sides — and
        # cross-checked against the enforcing code by
        # `test_the_pinned_tool_budgets_are_the_ones_the_loop_guard_enforces`.
        "tool_call_budget": PINNED_TOOL_CALL_BUDGET,
        "tool_repeat_budget": PINNED_TOOL_REPEAT_BUDGET,
    }


def _variables(agent: str) -> dict[str, str]:
    """`{**spec.variables, **_per_run(agent)}`, nothing silently overridden.

    A manifest may or may not declare `domain_label` — that has moved twice
    during Phase 1 — so the agent's own call site is the authority and the
    manifest's copy, when it ships one, must agree with it. What the render is
    FED is the pinned literal (`_per_run`), which is what makes the two
    comparable at all. Any OTHER key the spec declares must not collide with a
    per-run one, or `replace` would drop a value the spec meant to bind.
    """
    declared = dict(GENERATE_SPECS[agent].variables)
    live_label = _domain_label(agent)
    if "domain_label" in declared:
        assert declared["domain_label"] == live_label, (
            f"{agent}: manifest declares domain_label={declared['domain_label']!r}, "
            f"call site passes {live_label!r}"
        )
    per_run = _per_run(agent)
    overlap = (set(declared) & set(per_run)) - {"domain_label"}
    assert overlap == set(), (
        f"{agent}: spec declares {sorted(overlap)}, which this file's per-run "
        "values would silently override"
    )
    return {**declared, **per_run}


def _fill(text: str, variables: dict[str, str]) -> str:
    """`render._fill`'s substitution, reimplemented so nothing is shared."""
    out = text
    for key, value in variables.items():
        out = out.replace("{" + key + "}", value)
    return out


def _part(fragment_id: str, variables: dict[str, str]) -> str:
    """The fragment's RAW body — boundary newlines included — variables filled."""
    return _fill(registry.get(fragment_id).text, variables)


def _measured_runs(text: str) -> tuple[str, str]:
    """The text's actual leading and trailing newline runs, as bytes."""
    return text[: len(text) - len(text.lstrip("\n"))], text[len(text.rstrip("\n")) :]


# ── the assemblers ────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class Assembled:
    instructions: str
    user: str


def _assert_branch_preconditions() -> None:
    from shared.llm.provider import get_model_with_fallback, supports_structured_output

    resolved = get_model_with_fallback(MODEL)
    assert not supports_structured_output(resolved), (
        f"{resolved!r} now supports structured output; the unstructured branch "
        "Mode.TRANSCRIBE mirrors is unreachable with this model"
    )
    assert "anthropic" not in resolved, (
        f"{resolved!r} is an anthropic model; the builder would move the source "
        "body into the system turn (generate/source_in_system)"
    )


def _live(agent: str, vocabulary) -> Assembled:
    """#1 — what `shared.audit_runner` builds, from live code."""
    from shared import audit_runner as ar

    _assert_branch_preconditions()
    # FIVE sections of this turn have no pre-library source: `core/untrusted`
    # (item 4.3) and the four `generate/*` sections item 4.4 added. The tier
    # had no untrusted-content text, no presentation contract, no evidence
    # discipline, no tool permission and no severity vocabulary at all, so
    # there is no live literal, no helper and no retained file to read any of
    # them from. Their BYTES therefore come from the fragment and are not
    # independently observed here — `test_0089_version_bump.py` is the pin for
    # them. Their POSITION and their SEAM still are: every one is a `LIVE_SEAMS`
    # entry and this statement's ordering, so a moved or re-joined section
    # fails. What remains genuinely independent is the agent's own
    # `INSTRUCTIONS` literal, `_category_vocabulary_suffix` and the fenced-JSON
    # literal, all three read out of code this file does not render.
    instructions = (_instructions(agent) or "") + "\n\n"
    instructions += registry.get("core/untrusted").text.rstrip("\n")
    for fid in ("generate/source_presentation", "generate/evidence_discipline",
                "generate/tool_trigger"):
        instructions += "\n\n" + _part(fid, _per_run(agent)).rstrip("\n")
    instructions += ar._category_vocabulary_suffix(vocabulary)
    instructions += "\n\n" + registry.get("generate/vocab_severity").text.rstrip("\n")
    instructions += _json_fenced_literal()
    # The same two facts the string above was just built from. Until item 4.7
    # this call took the defaults — `vocabulary=None`, `fenced=False` — so it
    # requested the branch WITHOUT the category enum and WITHOUT the JSON
    # contract while the instructions beside it appended both. Unobservable
    # until now, because both are SYSTEM fragments and this file assembles the
    # live system turn by hand; rule 2 puts the wire shape into the USER turn,
    # which is the role this call returns. Supplying them makes the request
    # match the branch, and widens what the comparison covers.
    user = ar._build_llm_prompt(
        SOURCE_PATH, CATEGORIES, _domain_label(agent), SOURCE_BODY, PRIOR_CONTEXT,
        vocabulary=vocabulary, fenced=True,
    )
    return Assembled(instructions=instructions, user=user)


def _admitted(ids: tuple[str, ...]) -> tuple[str, ...]:
    """`ids` minus the fragments ADAPT's rule 9 drops for this file's `MODEL`.

    Item 4.8. Rule 9 admits a `BINDS_LANGUAGE` fragment only for a profile
    whose `output_language_pin` is set, and `MODEL` is deliberately not one:
    this file's subject is the live builder's UNSTRUCTURED branch, and the
    families that pin the output language are the ones
    `supports_structured_output` answers True for, so the two cannot be
    satisfied by one model. `core/language` is therefore listed by all seven
    specs and rendered by none of them here — and every expectation below is
    built from the spec's fragment LIST, so each has to be filtered the way the
    renderer filters or the recipe describes a prompt production never sends.

    Read from the fragment's declared `stance` and the profile's own flag, not
    by calling `render._rule_language`: the discipline this file keeps is that
    the expected side never shares a reading with the code under test, and
    `_mirrored` reads `role` the same way for the same reason.

    WHAT THIS LEAVES UNCOVERED, deliberately: the two seams `core/language`
    introduces on a profile that DOES pin it
    (`generate/vocab_severity` -> `core/language` -> `generate/json_fenced`)
    are not pinned in this file, because no model can put them on the branch
    this file reads. They are pinned as bytes by the `<manifest>.glm.txt`
    goldens and asserted as placement by `test_0089_4_8_language_pin.py`.
    """
    if profile_for(MODEL).output_language_pin:
        return tuple(ids)
    return tuple(i for i in ids
                 if Stance.BINDS_LANGUAGE not in registry.get(i).stance)


def _mirrored(spec) -> tuple[str, ...]:
    """This spec's system fragments that rule 2 also emits in the user turn.

    Read from each fragment's declared `role` on disk, never from `render` — the
    whole point of `_live_role` is to rebuild the turn from the DECLARATIONS, so
    a composition taken from the renderer would move both sides of the
    comparison together, which is the failure mode this file was written to fix.
    """
    return tuple(f for f in _admitted(spec.fragments)
                 if registry.get(f).role is Role.SYSTEM_USER_MIRROR)


def _user_ids(spec) -> tuple[str, ...]:
    """The USER turn's fragment order under item 4.7: mirrored first, then own.

    `render` prepends (`usr_frags = mirrored + usr_frags`), so the mirrored
    parts lead. Stated here as its own function so the ORDER is an assertion
    this file makes rather than an assumption buried in a call.
    """
    return _mirrored(spec) + tuple(spec.user_fragments)


def _live_role(fragment_ids: tuple[str, ...], variables: dict[str, str]) -> str:
    """#2 — the live bytes rebuilt from RAW fragment bodies and pinned seams.

    Nothing strips: the parts are the `.md` bodies exactly as they are on disk
    and the seams are the literals in `LIVE_SEAMS`. This is the assertion
    `render` cannot be asked for, because the renderer's join deletes the
    boundary bytes before any comparison against its output can see them.

    The part ORDER comes from the spec, so a reordered spec does not quietly
    reorder the expectation too: an adjacent pair with no pinned seam is an
    assembly this file has not been taught, and fails.
    """
    out: list[str] = []
    for left, right in zip(fragment_ids, fragment_ids[1:], strict=False):
        seam = LIVE_SEAMS.get((left, right))
        assert seam is not None, (
            f"no pinned live seam for {left!r} -> {right!r}; the spec's "
            "assembly changed and this file has not been taught the new seam"
        )
        out += [_part(left, variables), seam]
    out.append(_part(fragment_ids[-1], variables))
    return "".join(out)


def _rendered(agent: str) -> Assembled:
    """#3 — what the library actually renders for `agent`. The SUT.

    `Mode.ADAPT` as of item 4.4, following the call site: `_build_llm_prompt`
    on the live side renders ADAPT now, and comparing it against a TRANSCRIBE
    render would be comparing two modes. On this file's `MODEL` the two are
    byte-identical anyway — gemini has a system role and
    `Structured.NONE`, so neither the fold nor rule 4+5 bites — which is what
    makes the flip observable here as "nothing moved" rather than as a diff.
    """
    spec = dataclasses.replace(GENERATE_SPECS[agent], variables=_variables(agent))
    rp = render(spec, profile_for(MODEL), mode=Mode.ADAPT)
    return Assembled(instructions=rp.instructions, user=rp.user)


def _render_pair(role: str, left: str, right: str, variables: dict[str, str]) -> str:
    """The SUT, asked for just ONE seam: a two-fragment spec, same mode.

    Rendered on the role the pair actually occupies, so the user turn's seams
    are not checked through the system path. Two user fragments also keep the
    `verbatim` single-fragment bypass out of the way.
    """
    ids = (left, right)
    spec = PromptSpec(
        id=f"probe/{left}|{right}", tier="generate",
        fragments=ids if role == "instructions" else (),
        user_fragments=() if role == "instructions" else ids,
        variables=variables,
    )
    rp = render(spec, profile_for(MODEL), mode=Mode.ADAPT)
    return rp.instructions if role == "instructions" else rp.user


def _adjacent_pairs():
    """Every adjacent fragment pair in all seven specs, as one case each."""
    out = []
    for agent in AGENTS:
        spec = GENERATE_SPECS[agent]
        # `_user_ids`, not `spec.user_fragments`: item 4.7's mirror creates two
        # adjacencies that exist only in the rendered user turn, and a pair
        # enumerated from the spec's own list alone would never see them.
        for role, ids in (("instructions", _admitted(spec.fragments)),
                          ("user", _user_ids(spec))):
            for left, right in zip(ids, ids[1:], strict=False):
                out.append(pytest.param(
                    agent, role, left, right, id=f"{agent}-{role}-{left}-to-{right}",
                ))
    return tuple(out)


ADJACENT_PAIRS = _adjacent_pairs()


# ── reporting ─────────────────────────────────────────────────────────────

def _msg(what: str, ln: str, left: str, rn: str, right: str) -> str:
    if left == right:
        return f"{what}: byte-identical ({len(left.encode())} bytes)"
    body = difflib.unified_diff(
        left.splitlines(keepends=True), right.splitlines(keepends=True),
        fromfile=f"{ln}", tofile=f"{rn}", n=1,
    )
    return "\n".join([
        f"{what}: MISMATCH {ln}={len(left.encode())}B {rn}={len(right.encode())}B",
        *(line.rstrip("\n") for line in body),
        f"  {ln} tail: {left[-90:]!r}",
        f"  {rn} tail: {right[-90:]!r}",
    ])


# ── repair 1: the bytes the join discards are now under a byte assertion ──

@pytest.mark.parametrize("fragment_id", sorted(PINS))
def test_pinned_boundary_runs_and_role_are_what_the_file_holds(fragment_id: str):
    """The boundary newline runs the renderer's join deletes, pinned as bytes.

    A part's trailing run is dropped unless the fragment declares
    `keep_trailing`, and the joined body's leading run is always dropped, so
    these runs need not change any rendered byte: +2 leading and +3 trailing
    newlines in `generate/field_contract` left all seven `rendered.user`
    strings identical. This is the assertion that mutation fails. The
    comparison is between the run MEASURED in the file and the run pinned
    here — never between a string and itself.
    """
    fragment = registry.get(fragment_id)
    pin = PINS[fragment_id]
    assert _measured_runs(fragment.text) == (pin.lead, pin.trail), (
        f"{fragment_id}: boundary newline runs changed. The renderer's join can "
        "drop these bytes, so an assertion made against render's output need "
        f"not see it; measured={_measured_runs(fragment.text)!r} "
        f"pinned={(pin.lead, pin.trail)!r}"
    )
    # TRANSCRIBE ignores front matter, so a role flip moves zero rendered bytes.
    assert fragment.role is pin.role, f"{fragment_id}: role is now {fragment.role}"
    # `verbatim` bypasses the join for a LONE user fragment; none of these is one.
    assert fragment.verbatim is False, f"{fragment_id}: verbatim is now set"


def test_substituted_values_carry_no_boundary_newlines():
    """So a variable's value cannot manufacture a run the pins do not cover."""
    for agent in AGENTS:
        for name, value in _variables(agent).items():
            assert _measured_runs(value) == ("", ""), f"{agent}/{name}"


@pytest.mark.parametrize("fragment_id", sorted(PLACEHOLDERS))
def test_templated_fragments_interpolate_exactly_the_pinned_names(fragment_id: str):
    """A renamed placeholder would render as a literal `{name}` in the prompt."""
    assert registry.get(fragment_id).variables() == PLACEHOLDERS[fragment_id]


@pytest.mark.parametrize("vocabulary", VOCAB_INPUTS)
@pytest.mark.parametrize("agent", AGENTS)
def test_live_roles_are_the_raw_fragment_bytes(agent: str, vocabulary):
    """The live builder's bytes == the fragments' RAW bodies + the live seams.

    Repair (1): this is where a fragment's boundary newlines are decidable,
    because the live builder concatenates and never strips — `generate/task`'s
    trailing newline and `domains/asvs` / `domains/xss`'s included. It holds
    whatever the renderer currently does with them, so it is the durable half
    of the parity claim. Repair (3): with the ordered `unsorted-tuple` input,
    deleting `sorted()` from `_category_vocabulary_suffix` fails this at every
    hash seed.

    Two independent sources: the left side is live code plus each agent's own
    `INSTRUCTIONS` literal read by `ast`; the right side is `.md` files on disk
    plus the pinned seams. A fragment edit moves only the right, an
    `audit_runner` edit only the left.
    """
    live = _live(agent, vocabulary)
    spec, variables = GENERATE_SPECS[agent], _variables(agent)
    system_ids = _admitted(spec.fragments)
    assert _live_role(system_ids, variables) == live.instructions, _msg(
        f"generate/{agent} instructions", "live/audit_runner", live.instructions,
        "recipe/raw-fragment-bytes", _live_role(system_ids, variables),
    )
    assert _live_role(_user_ids(spec), variables) == live.user, _msg(
        f"generate/{agent} user", "live/audit_runner", live.user,
        "recipe/raw-fragment-bytes", _live_role(_user_ids(spec), variables),
    )


# ── repair 2: every seam is its own case, so no count can go stale ────────

@pytest.mark.parametrize("agent,role,left,right", ADJACENT_PAIRS)
def test_each_seam_renders_the_live_bytes(agent: str, role: str, left: str, right: str):
    """One adjacent pair, rendered, against the same pair's live bytes.

    Repair (2). The residual gap between `render` and the live builder is a
    set of SEAMS, and this is that set enumerated rather than counted: an
    unsatisfied seam is one named red case, a seam the fragment layer learns
    to declare goes green by itself, and a new gap arrives as a new red case.
    Nothing in this file has to be edited when the total changes, which is the
    repair — the previous claim was a number in a report.

    Byte-exact and independent on both sides: the expected string is the two
    `.md` bodies with the pinned live seam between them; the actual string is
    `render`'s own output for a two-fragment spec in the same mode.
    """
    variables = _variables(agent)
    seam = LIVE_SEAMS.get((left, right))
    assert seam is not None, f"no pinned live seam for {left!r} -> {right!r}"
    expected = _part(left, variables) + seam + _part(right, variables)
    actual = _render_pair(role, left, right, variables)
    assert actual == expected, _msg(
        f"generate/{agent} {role} seam {left} -> {right}",
        "live/audit_runner", expected, "rendered/prompt-library", actual,
    )


@pytest.mark.parametrize("agent", AGENTS)
def test_generate_prompt_is_byte_identical(agent: str):
    """The whole-role parity assertion, with the spec's variables MERGED.

    The same comparison `test_0089_parity_generate.py` makes, except that the
    variable dict is `{**spec.variables, **_per_run(agent)}` rather than a
    replacement, and `domain_label` is supplied from the agent's call site. A
    render whose `{source_path}` is still a literal placeholder is not the
    render a call site gets, and its diff describes the wrong gap.
    """
    live = _live(agent, frozenset(VOCAB_MEMBERS))
    rendered = _rendered(agent)
    report = "\n".join([
        _msg(f"generate/{agent} instructions", "live/audit_runner", live.instructions,
             "rendered/prompt-library", rendered.instructions),
        _msg(f"generate/{agent} user", "live/audit_runner", live.user,
             "rendered/prompt-library", rendered.user),
    ])
    assert rendered.instructions == live.instructions, report
    assert rendered.user == live.user, report


def test_seam_join_levers_are_byte_exact():
    """The two levers repair (1) named, pinned against literal bytes.

    `keep_trailing` decides whether a part's trailing run survives and `seam`
    decides the width of the boundary. Without them a fragment could widen a
    seam (leading blank lines survive) but never tighten one, and a trailing
    newline was unrepresentable — which is what made `asvs`/`xss` and
    `generate/task` unreachable from the fragment layer. Asserted here so the
    levers themselves cannot regress silently while every seam case above
    stays green on the old bytes.
    """
    from shared.prompt.render import _seam_join

    assert _seam_join([("a\n", "blank", False), ("b", "blank", False)]) == "a\n\nb"
    assert _seam_join([("a\n", "blank", True), ("b", "blank", False)]) == "a\n\n\nb"
    assert _seam_join([("a", "blank", False), ("b", "tight", False)]) == "a\nb"
    assert _seam_join([("a\n", "blank", True), ("b", "tight", False)]) == "a\n\nb"
    # The joined body's LEADING run goes regardless of either lever.
    assert _seam_join([("\n\na", "blank", False), ("b", "tight", False)]) == "a\nb"


# ── repair 3: the sort is observable at every hash seed ──────────────────

@pytest.mark.parametrize("permutation", [
    pytest.param(("A01", "ALPHA", "B02", "zeta"), id="already-sorted"),
    pytest.param(("zeta", "ALPHA", "A01", "B02"), id="unsorted"),
    pytest.param(("zeta", "B02", "ALPHA", "A01"), id="reversed"),
])
def test_category_vocabulary_suffix_is_order_invariant(permutation: tuple[str, ...]):
    """Every permutation builds the SAME system-message bytes.

    `_category_vocabulary_suffix`'s docstring makes the sort load-bearing for
    prompt-cache stability, and deleting it kept the parity equality true under
    this interpreter's hash seed. Ordered tuples make the property decidable:
    without `sorted()`, `unsorted` and `reversed` cannot both match.
    """
    from shared import audit_runner as ar

    assert sorted(permutation) == sorted(VOCAB_MEMBERS), "permutation must be one"
    expected = _SEAM_INSTRUCTIONS_TO_VOCAB + _part(
        "generate/vocab_category", {"category_vocabulary": VOCAB_SORTED_TEXT},
    )
    assert ar._category_vocabulary_suffix(permutation) == expected, (
        "the declared vocabulary no longer reaches the prompt sorted; two "
        "identical audits would build different system messages"
    )


# ── the call site's own inputs, so a label cannot render as a byte ────────

@pytest.mark.parametrize("agent", AGENTS)
def test_spec_transcribes_the_call_sites_domain_label(agent: str):
    """The `domain_label` the render is FED == the one the agent passes.

    `generate/task` interpolates it, so an absent or drifted value renders the
    literal `{domain_label}` into the prompt — a transcription gap that looks
    like a byte. Two independent sources, as everywhere else here: the pinned
    table on the left, the agent's own `run_combined_audit(domain_label=...)`
    keyword read by `ast` on the right.

    The SUBJECT moved with the lever, and this is what keeps the claim
    decidable rather than tautological. The manifest used to declare the label
    and this compared the manifest against the call site; the manifest now
    ships no `variables` at all, so the render is fed the pinned literal
    instead — while `_per_run` read the call site directly, relabelling cwe's
    to "CWE weaknesses" left every case in this file green. The manifest's copy
    is still checked, for the day it ships one again, so neither source can
    drift unobserved.
    """
    live_label = _domain_label(agent)
    declared = GENERATE_SPECS[agent].variables.get("domain_label")
    if declared is not None:
        assert declared == live_label, (
            f"{agent}: manifest declares {declared!r}, call site passes "
            f"{live_label!r}"
        )
    assert CALL_SITE_DOMAIN_LABELS[agent] == live_label, (
        f"{agent}: pinned {CALL_SITE_DOMAIN_LABELS[agent]!r}, call site passes "
        f"{live_label!r} — the pinned literal is the byte the rendered prompt "
        "would carry, so these two disagreeing is a transcription gap"
    )


def test_the_pinned_tool_budgets_are_the_ones_the_loop_guard_enforces():
    """Where the pinned literals meet the code that actually stops the run.

    Item 4.4's `generate/tool_trigger` tells the model a number, and the whole
    point of interpolating it is that the number is the enforced one. This file
    feeds the render a PINNED literal (`_per_run`) so that a change to
    `loop_detector` cannot move both sides of a comparison at once — which
    leaves exactly one thing to check here, and it is checked by DRIVING the
    detector rather than by reading its constants: a renamed or re-defaulted
    threshold, or a `record()` that stopped returning KILL at the stated count,
    fails here.
    """
    from shared.llm.loop_detector import LoopAction, LoopDetector

    total = LoopDetector()
    actions = [total.record(f"tool_{i}", None, f"result_{i}")
               for i in range(int(PINNED_TOOL_CALL_BUDGET))]
    assert actions[-1] is LoopAction.KILL, (
        f"the prompt promises the run stops at {PINNED_TOOL_CALL_BUDGET} tool "
        "calls; the guard did not stop it there"
    )
    assert LoopAction.KILL not in actions[:-1], "it stops EARLIER than promised"

    repeat = LoopDetector()
    repeats = [repeat.record("read_file", None, "same")
               for _ in range(int(PINNED_TOOL_REPEAT_BUDGET))]
    assert repeats[-1] is LoopAction.KILL, (
        f"the prompt promises the run stops after {PINNED_TOOL_REPEAT_BUDGET} "
        "identical calls; the guard did not stop it there"
    )
    assert LoopAction.KILL not in repeats[:-1]


# ── coverage: nothing may be added to one side alone ─────────────────────

def test_repair_covers_every_generate_agent_fragment_and_seam():
    """The pins cover every fragment and every seam the seven specs render."""
    assert set(AGENTS) == set(GENERATE_SPECS)
    assert set(AGENTS) == set(AGENT_PACKAGES)
    assert len(AGENTS) == 7
    rendered_ids = {
        fid
        for spec in GENERATE_SPECS.values()
        for fid in (*spec.fragments, *spec.user_fragments)
    }
    # Equality, not containment: an unpinned new fragment would have boundary
    # bytes nothing checks, and a stale pin would hide a dropped fragment.
    assert rendered_ids == set(PINS)
    # Same for the seams: every adjacent pair the specs assemble is pinned, and
    # no pinned seam has become unreachable.
    assembled_pairs = {
        (left, right)
        for spec in GENERATE_SPECS.values()
        # `_user_ids`, not `spec.user_fragments` — same reason as
        # `_adjacent_pairs`: item 4.7's mirror assembles two pairs that appear in
        # no spec list, and enumerating from the lists alone would call the table
        # complete while two of its entries were unreachable.
        for ids in (_admitted(spec.fragments), _user_ids(spec))
        for left, right in zip(ids, ids[1:], strict=False)
    }
    assert assembled_pairs == set(LIVE_SEAMS)
    assert {p.values[2:] for p in ADJACENT_PAIRS} == assembled_pairs
    # A new agent cannot arrive with its label pinned on one side only.
    assert set(CALL_SITE_DOMAIN_LABELS) == set(AGENTS)
    for agent in AGENTS:
        assert (AGENTS_DIR / AGENT_PACKAGES[agent]).is_file(), agent
    assert XSS_INSTRUCTIONS.is_file()
    for agent, spec in GENERATE_SPECS.items():
        # No slot, and no LONE user fragment that would take the verbatim
        # bypass instead of the join every assertion above assumes.
        assert spec.slots == (), agent
        assert len(spec.user_fragments) > 1, agent
        # An empty part would be dropped by the join's filter, silently.
        for fid in (*spec.fragments, *spec.user_fragments):
            assert registry.get(fid).text != "", f"{agent}/{fid}"
