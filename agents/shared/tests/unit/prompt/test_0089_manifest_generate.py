"""Feature 0089 Phase 0.c — the GENERATE tier, transcribed.

Phase 1's whole value rests on one property: the fragments under
``prompt/fragments/generate`` and ``prompt/fragments/domains`` are the SAME
bytes today's builder emits. So the byte-exactness test does not compare
against a hand-typed copy of the prompt — it recomputes the prompt from
``shared.audit_runner`` (and from each agent's own ``INSTRUCTIONS``, read via
``ast`` because the agent packages are not importable from here) and asserts
each fragment appears verbatim inside it.

The lint test is the other half: transcription is not endorsement. The GENERATE
prompt as it exists today trips three of promptlint's checks, and those
findings are the deliverable, not a defect in the transcription.
"""

from __future__ import annotations

import ast
from pathlib import Path

from shared.prompt import Mode, lint, profile_for, render
from shared.prompt.manifests.generate import GENERATE_SPECS
from shared.prompt.registry import get

# tests/unit/prompt/<this file> -> tests/unit/prompt -> unit -> tests -> shared
# -> agents
AGENTS_DIR = Path(__file__).resolve().parents[4]

# Every agent whose domain instructions are a module-level `INSTRUCTIONS`
# constant. `owasp` is deliberately absent: it is a categorizer with no LLM
# path and therefore no instructions to transcribe.
AGENT_INSTRUCTION_SOURCES: dict[str, Path] = {
    "chaos": AGENTS_DIR / "chaos_engineering" / "chaos_agent" / "agent.py",
    "soc2": AGENTS_DIR / "soc2" / "soc2_agent" / "agent.py",
    "ssdf": AGENTS_DIR / "ssdf" / "ssdf_agent" / "agent.py",
    "do178c": AGENTS_DIR / "do178c" / "do178c_agent" / "agent.py",
    "asvs": AGENTS_DIR / "asvs" / "asvs_agent" / "agent.py",
    "cwe": AGENTS_DIR / "cwe" / "cwe_agent" / "agent.py",
}
XSS_INSTRUCTIONS = AGENTS_DIR / "xss" / "xss_agent" / "INSTRUCTIONS.md"

SEVEN_AGENTS = frozenset({"chaos", "soc2", "ssdf", "do178c", "asvs", "cwe", "xss"})

# Every fragment that states the eight-field list in a `generate/cwe` render.
#
# BEFORE feature 0089 item 4.4 this was a set of THREE — `generate/json_fenced`
# enumerated the same eight fields as `generate/field_contract`, in the SYSTEM
# turn, appended by a different branch of the builder, and
# `audit_runner._quote_contract_suffix` documented that pair as "one policy
# written twice, in two places that are edited independently". 4.4 resolved the
# tier's half: `generate/json_fenced` states the WIRE SHAPE and declares no
# fields. What is left is the half that belongs to the agent identity —
# `domains/cwe` ships its own "## Reporting Format" block — and it is annotated
# on the manifest rather than fixed here, because that text is pinned
# byte-for-byte against the constant cwe's own unit tests assert on.
FIELD_LIST = frozenset({
    "generate/field_contract", "domains/cwe",
})

# The eight fields the tier's ONE declaring fragment names in its own sentence.
CONTRACT_FIELDS = (
    "severity", "category", "title", "description",
    "file_path", "line_start", "line_end", "recommendation",
)


# ── reading the ORIGINAL bytes without importing the agent packages ────────

def _piece(node: ast.expr) -> str:
    """One f-string segment, rendered back to its `{name}` template form."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    inner = getattr(node, "value", None)
    return "{" + inner.id + "}" if isinstance(inner, ast.Name) else "{?}"


def _template(node: ast.AST) -> str | None:
    """A str literal, or an f-string reduced to its template. Else None."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(_piece(v) for v in node.values)
    return None


def _string_templates(path: Path) -> str:
    """Every string literal in a module, joined. Implicit concatenation is
    already folded by the parser, so a multi-line literal arrives whole."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = [t for node in ast.walk(tree) if (t := _template(node)) is not None]
    return "\n".join(found)


def _assigns(node: ast.AST, name: str) -> bool:
    targets = getattr(node, "targets", ())
    return any(isinstance(t, ast.Name) and t.id == name for t in targets)


def _first_str(values: list, where: str) -> str:
    real = [v for v in values if v is not None]
    assert real, f"no str constant for {where}"
    return real[0]


def _module_constant(path: Path, name: str) -> str:
    """The value of a module-level `name = "..."` assignment."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values = [_template(n.value) for n in ast.walk(tree) if _assigns(n, name)]
    return _first_str(values, f"{name} in {path}")


def _filled(fragment_id: str, fill: dict[str, str]) -> str:
    text = get(fragment_id).text
    for key, value in fill.items():
        text = text.replace("{" + key + "}", value)
    return text


def _assert_byte_exact(fragment_id: str, original: str, fill: dict[str, str]) -> None:
    text = _filled(fragment_id, fill)
    assert text, f"{fragment_id}: empty fragment"
    assert text in original, f"{fragment_id}: not byte-exact"


def test_generate_fragments_are_byte_exact():
    """Each fragment's text appears VERBATIM in the output of the function, or
    inside the constant, it was transcribed from."""
    from shared import audit_runner as ar

    vocab = frozenset({"CWE-79", "CWE-89"})
    fill = {"source_context": "SRCBODY", "category_vocabulary": "CWE-79, CWE-89"}
    literals = _string_templates(Path(ar.__file__))
    args = ("/src", ["injection"], "categories")
    inline = ar._build_llm_prompt(*args, "SRCBODY", "")
    in_system = ar._build_llm_prompt(*args, "SRCBODY", "", source_in_system=True)
    tools_only = ar._build_llm_prompt(*args, "", "")

    # (fragment id, the ORIGINAL text it must be found in, variables to fill)
    cases: tuple[tuple[str, str, dict[str, str]], ...] = (
        ("generate/field_contract", "\n".join(ar._field_contract()), {}),
        # `_quote_obligation()` states the bound from the verifier's own
        # VULTURE_LLM_QUOTE_MAX_LINES, read at call time (0076 §5.2 property
        # 3), so the fragment interpolates it rather than freezing the default
        # — filled here from the same knob, which keeps this comparison against
        # the live sentence's bytes exactly as strict as it was.
        ("generate/quote_obligation", ar._quote_obligation(),
         {"quote_max_lines": str(ar._quote_max_lines())}),
        ("generate/vocab_category", ar._category_vocabulary_suffix(vocab), fill),
        # These two live inside `_collect_llm_findings_async`, not behind a
        # function, so they are read out of the module's own literals.
        ("generate/json_fenced", literals, {}),
        ("generate/source_in_system", literals, {}),
        ("generate/source_inline", inline, fill),
        ("generate/source_in_system_ref", in_system, {}),
        ("generate/tools_only", tools_only, {}),
    )
    for fragment_id, original, variables in cases:
        _assert_byte_exact(fragment_id, original, variables)

    for agent, path in AGENT_INSTRUCTION_SOURCES.items():
        assert get(f"domains/{agent}").text == _module_constant(path, "INSTRUCTIONS")
    assert get("domains/xss").text == XSS_INSTRUCTIONS.read_text(encoding="utf-8")


def _assert_spec_shape(agent, spec, manifests) -> None:
    assert spec.tier == "generate", agent
    # The three read-only file tools are attached on EVERY generate call.
    assert spec.tools == ("read_file", "list_files", "search_pattern"), agent
    assert manifests[spec.id] is spec, agent


def _assert_renders(agent, spec, profile, manifests) -> None:
    rendered = render(spec, profile, mode=Mode.TRANSCRIBE)
    assert get(f"domains/{agent}").text in rendered.instructions, agent
    assert get("generate/field_contract").text in rendered.user, agent
    _assert_spec_shape(agent, spec, manifests)


def test_manifest_generate_renders_all_seven_agents():
    """Seven scan agents have an LLM generate path. `owasp` has none."""
    from shared.prompt.manifests import MANIFESTS

    assert set(GENERATE_SPECS) == SEVEN_AGENTS
    assert "owasp" not in GENERATE_SPECS

    profile = profile_for("gpt-4o")
    for agent, spec in GENERATE_SPECS.items():
        _assert_renders(agent, spec, profile, MANIFESTS)


def _lint(agent: str) -> list:
    spec = GENERATE_SPECS[agent]
    profile = profile_for("gpt-4o")
    return lint(spec, render(spec, profile, mode=Mode.TRANSCRIBE))


def _only(findings: list, check: str) -> list:
    return [f for f in findings if f.check == check]


def _checks(findings: list) -> set[str]:
    return {f.check for f in findings}


def _fragments_for(findings: list, check: str) -> list[str]:
    return [f.fragment for f in _only(findings, check)]


def _assert_cwe_contract(cwe: list) -> None:
    """Two fragments state a field list in one render: the shared contract and
    the agent's own "## Reporting Format" block. Not merged — the duplication
    IS the audit blocker."""
    assert "duplicate_contract" in _checks(cwe)
    assert set(_fragments_for(cwe, "duplicate_contract")) == FIELD_LIST


def _assert_cwe_tools(cwe: list) -> None:
    """Three tools are attached and a fragment now permits using them.

    BEFORE feature 0089 item 4.4 this read `assert "tool_announcement" in
    _checks(cwe)`: GENERATE's only tool sentence (`generate/tools_only`) sat in
    the `else` branch that a non-empty source context makes unreachable, so the
    render held three tools and no permission. `generate/tool_trigger` is on
    every branch now, which is the fix that finding named — so the assertion is
    inverted rather than deleted, and it fails if the fragment is dropped.
    And every field cwe names is in the schema.
    """
    assert "tool_announcement" not in _checks(cwe)
    assert "orphan_field" not in _checks(cwe)


def _assert_asvs_orphan(asvs: list) -> None:
    """`linked_cwe` is asked for by the prompt and exists in no schema."""
    assert _fragments_for(asvs, "orphan_field") == ["domains/asvs"]
    assert any("linked_cwe" in f.message for f in _only(asvs, "orphan_field"))


def test_lint_surfaces_generate_blockers():
    """Three findings the GENERATE prompt earns as it stands today."""
    cwe = _lint("cwe")
    _assert_cwe_contract(cwe)
    _assert_cwe_tools(cwe)
    _assert_asvs_orphan(_lint("asvs"))


def test_json_fenced_declares_the_fields_its_text_names():
    """A fragment's `declares_fields` must match what its text SAYS.

    The honesty check, in both directions. A fragment that names a contract
    while declaring nothing is invisible to `check_02_duplicate_contract`,
    which would let a real duplication pass review unreported; a fragment that
    declares a contract its text does not state manufactures a duplication that
    is not in the prompt.

    BEFORE feature 0089 item 4.4 this asserted the FIRST direction on
    `generate/json_fenced`:

        for name in JSON_FENCED_FIELDS:
            assert name in frag.text, name
        assert frag.declares_fields == JSON_FENCED_FIELDS

    — because the fragment then spelled the list out ("Each object must have:
    severity, category, ... recommendation"). 4.4 removed the list from that
    sentence, so the same rule now demands the opposite declaration, and the
    test asserts the second direction on the same fragment plus the first on
    `generate/field_contract`, the author the list moved to. Both fragments are
    still checked; neither is exempted.
    """
    fenced = get("generate/json_fenced")
    assert fenced.declares_fields == ()
    for name in CONTRACT_FIELDS:
        assert name not in fenced.text, f"json_fenced still names {name!r}"

    contract = get("generate/field_contract")
    assert contract.declares_fields == CONTRACT_FIELDS
    for name in CONTRACT_FIELDS:
        assert name in contract.text, name


# The two agents whose own domain instructions add a second field list.
OWN_REPORTING_FORMAT = frozenset({"cwe", "asvs"})


def _assert_contract_declared_once(agent: str) -> None:
    declaring = set(_fragments_for(_lint(agent), "duplicate_contract"))
    if agent in OWN_REPORTING_FORMAT:
        assert declaring == {"generate/field_contract", f"domains/{agent}"}, agent
    else:
        assert declaring == set(), agent


def test_duplicate_contract_fires_only_where_a_domain_ships_its_own():
    """The tier's own duplication is gone; the identity's is what remains.

    BEFORE feature 0089 item 4.4 this test was
    `test_duplicate_contract_fires_on_every_generate_spec`, and it asserted the
    opposite: that the eight-field contract was stated TWICE in ALL SEVEN
    renders (three times for cwe and asvs), because `generate/field_contract`
    stated it in the user turn and `generate/json_fenced` stated it again in
    the system turn. Its docstring called that "tier-wide — not a cwe/asvs
    peculiarity". 4.4 made it exactly that peculiarity: `generate/json_fenced`
    no longer declares a list, so five renders declare it once and only the two
    agents whose `domains/` fragment carries a "## Reporting Format" block
    still declare it twice.

    Inverted rather than deleted, so the finding cannot come back unnoticed:
    add a second declaring fragment to any of the five and this fails.
    """
    for agent in sorted(SEVEN_AGENTS):
        _assert_contract_declared_once(agent)


def test_quote_obligation_field_is_in_the_schema():
    """`evidence_quote` is asked for by `generate/quote_obligation` and must be
    a real schema field, so no spec can orphan it.

    The fragment deliberately carries no `declares_fields`: it and
    `generate/field_contract` are two halves of ONE list returned by
    `audit_runner._field_contract()`, so declaring both would manufacture a
    `duplicate_contract` finding that does not exist in the prompt. This test
    keeps the field itself covered instead.
    """
    assert "evidence_quote" in get("generate/quote_obligation").text
    for spec in GENERATE_SPECS.values():
        assert "evidence_quote" in spec.schema_fields, spec.id
