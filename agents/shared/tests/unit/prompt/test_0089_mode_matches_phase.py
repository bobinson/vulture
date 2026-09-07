"""`test_mode_matches_phase` — the renderer mode of every call site, from source.

Feature 0089, Phase 1 Definition of Done. Written late, in Phase 4, because the
phase it gates had already started without it.

`render(spec, profile, mode=...)` takes a **call-site constant, not a flag**
(`render.py`'s own docstring; LLD §4.0; adversarial review R2-1). TRANSCRIBE
concatenates and does nothing else, which is what let Phases 0-3 move six call
sites onto the library without moving a byte. ADAPT turns the rules on, and
Phase 4 flips the sites one at a time so that each delta is attributable to one
item. The mode is therefore a *phase* fact, and this file is where the phase
table lives in executable form: flip a site without updating the table and the
build fails.

WHY A TEST AND NOT A COMMENT. Measured, before this file existed: setting
`shared/validate/llm_judge.py`'s constant to `Mode.ADAPT` broke **nothing** —
0 failures in `tests/unit/prompt` (364 tests) and 0 in the 619 validate/judge
tests of the wider suite. It is not that the coverage is thin; it is that on the
default `openai` profile the VALIDATE spec renders *byte-identical* under both
modes (fingerprint `7d249585896184aa` either way), so no golden, parity or byte
assertion in this feature can see the flip even in principle. The only
observable difference is `response_format`, which that call site discards today
and a later one will not. A prompt-bytes test cannot pin a mode; only reading
the constant can.

RE-MEASURED WHEN 4.1 ACTUALLY FLIPPED IT, because that paragraph stopped being
true and a stale measurement is worse than none. Items 4.7 (the mirror) and 4.8
(the language pin) landed in between, and both reach VALIDATE: on the default
profile the flip now moves the system turn 7143 -> 6667 bytes and the user turn
79 -> 2063, fingerprint `bc8f171cbb5ddfa0` -> `facaf0a7d7d42cc2`. So the flip
was visible to the goldens by the time it happened — and the file's own
argument survives it unchanged, because what a byte test still cannot see is a
mode, only its consequences, and the consequences were nil across the whole of
Phases 0-3, when this table was the only thing holding the sites in place.

THE MODES ARE READ FROM SOURCE, never from a list retyped here. A
hand-maintained inventory of call sites is a second source of truth about the
call sites — the exact defect this whole feature exists to remove — and it
drifts silently the moment someone adds a seventh site. The scan walks the
production tree, so a new site is a *new key* and fails the set-equality test
below until somebody puts it in the table on purpose.
"""

from __future__ import annotations

import ast
import inspect
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from shared.prompt.render import Mode, render

# ── where to look ─────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset({"tests", "node_modules", "site-packages", "build", "dist"})


def _repo_root() -> Path:
    """The vulture checkout, found by landmark rather than by parent count.

    `parents[N]` is how the sibling test in this directory finds the tree, and
    it is off by one there — which is invisible because the failure mode is a
    skip. A landmark cannot be off by one.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "agents").is_dir() and (parent / "backend").is_dir():
            return parent
    raise RuntimeError(f"no vulture checkout above {__file__}")


ROOT = _repo_root()
AGENTS = ROOT / "agents"


def _is_production(path: Path) -> bool:
    """Test trees, virtualenvs and vendored code are not call sites."""
    parts = path.relative_to(AGENTS).parts
    return not any(p in _SKIP_DIRS or p.startswith(".") for p in parts)


def _candidates() -> list[Path]:
    """Production `.py` files that mention `render` at all."""
    return [p for p in sorted(AGENTS.rglob("*.py"))
            if _is_production(p) and "render" in p.read_text(encoding="utf-8")]


# ── reading the mode out of the source ────────────────────────────────────
#
# `Mode.X`, `render.Mode.X`, `shared.prompt.Mode.X` — the attribute form is the
# only one accepted. A `mode=` whose value is a variable, an env read or a
# conditional is not a call-site constant and is reported as such rather than
# resolved: see `test_every_site_states_its_mode_as_a_literal_constant`.
_MODE_LITERAL = re.compile(r"\A(?:[\w.]+\.)?Mode\.(TRANSCRIBE|ADAPT)\Z")

# The default the renderer applies when a site names no mode. Read from the
# signature, so a site that omits `mode=` is recorded at its true effective
# value and a change to the default cannot hide behind an empty table diff.
DEFAULT_MODE: str = inspect.signature(render).parameters["mode"].default.name


@dataclass(frozen=True)
class Site:
    key: str          # "<path relative to the repo>::<enclosing qualname>"
    path: str
    line: int         # where the call begins — for navigation
    mode: str         # "TRANSCRIBE" | "ADAPT" | the unresolved source text
    explicit: bool    # False = the site omits `mode=` and inherits the default
    # Where `Mode.X` is WRITTEN, which is not `line`: four of the six calls wrap
    # their arguments, so the constant sits a line or two below the `render(`.
    # The text cross-check greps lines, so it needs the line the text is on.
    mode_line: int = 0


def _prompt_module(module: str | None) -> bool:
    """Does `from <module> import ...` reach the prompt library?

    Matches the three shapes in the tree — `shared.prompt` (absolute),
    `.render` and `..render` (relative, from inside the package, where
    `node.module` is just `render`). Deliberately generous: a false positive
    adds a key the table review will see, a false negative hides a call site,
    and only one of those two is recoverable.
    """
    return bool({"prompt", "render"} & {p for p in (module or "").split(".") if p})


def _from_import(node: ast.ImportFrom, direct: set[str], modules: set[str]) -> None:
    """`from shared.prompt import render`, `from shared import prompt`, `from . import render`."""
    is_prompt_pkg = _prompt_module(node.module)
    for a in node.names:
        if a.name == "render" and is_prompt_pkg:
            direct.add(a.asname or a.name)
        elif a.name in {"prompt", "render"}:
            modules.add(a.asname or a.name)


def _bindings(tree: ast.AST) -> tuple[set[str], set[str]]:
    """(names bound to `render` itself, names bound to a module that has one).

    `ast.walk`, not a scan of the module body: two of the six sites import
    inside the function that renders.
    """
    direct: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            _from_import(node, direct, modules)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if _prompt_module(a.name):
                    modules.add(a.asname or a.name.split(".")[0])
    return direct, modules


def _is_render_call(func: ast.expr, direct: set[str], modules: set[str]) -> bool:
    if isinstance(func, ast.Name):
        return func.id in direct
    if isinstance(func, ast.Attribute) and func.attr == "render":
        prefix = ast.unparse(func.value)
        return prefix in modules or prefix.split(".")[-1] in {"prompt", "render"}
    return False


def _mode_of(call: ast.Call) -> tuple[str, bool, int]:
    for kw in call.keywords:
        if kw.arg == "mode":
            src = ast.unparse(kw.value)
            m = _MODE_LITERAL.match(src)
            return (m.group(1) if m else src), True, kw.value.lineno
    return DEFAULT_MODE, False, call.lineno


def _qualname(stack: tuple[str, ...]) -> str:
    return ".".join(stack) or "<module>"


def _calls(node: ast.AST, stack: tuple[str, ...], out: list) -> None:
    """Depth-first walk that keeps the enclosing def/class names.

    The key is the qualname, not the line number: a Phase 4 item that edits the
    file above a call site must not renumber every entry in the table.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _calls(child, (*stack, child.name), out)
            continue
        if isinstance(child, ast.Call):
            out.append((stack, child))
        _calls(child, stack, out)


def _dedupe(keys: list[str]) -> list[str]:
    """Two renders in one function get `#0`/`#1`, so neither can hide."""
    seen = {k: keys.count(k) for k in keys}
    used: dict[str, int] = {}
    out = []
    for k in keys:
        if seen[k] == 1:
            out.append(k)
            continue
        used[k] = used.get(k, -1) + 1
        out.append(f"{k}#{used[k]}")
    return out


def _sites_in(path: Path, root: Path | None = None) -> list[Site]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    direct, modules = _bindings(tree)
    if not direct and not modules:
        return []
    found: list = []
    _calls(tree, (), found)
    hits = [(stack, c) for stack, c in found
            if _is_render_call(c.func, direct, modules)]
    hits.sort(key=lambda sc: sc[1].lineno)
    rel = path.relative_to(root or ROOT).as_posix()
    keys = _dedupe([f"{rel}::{_qualname(stack)}" for stack, _ in hits])
    return [Site(key, rel, call.lineno, *_mode_of(call))
            for key, (_, call) in zip(keys, hits, strict=True)]


def scan() -> dict[str, Site]:
    """Every production `render(...)` call in the agents tree, keyed."""
    return {s.key: s for p in _candidates() for s in _sites_in(p)}


SITES: dict[str, Site] = scan()


# ── the phase table ───────────────────────────────────────────────────────
#
# One row per call site. `item` names the Phase 4 item that owns that site's
# flip (plan §"Phase 4 — Behaviour changes, one rule at a time"); when the item
# lands it edits the row's `mode` here, in the same commit as the flip, and the
# goldens it re-captures. That is the rollback plan's stated contract:
#
#   "the site's `mode=ADAPT` constant … `test_mode_matches_phase` must be
#    updated in the same commit or it fails — that is the point"
#
# `production=False` marks a render that is not on any audit path. There is
# exactly one and it is the LINTER: `lint.sweep()` gates every manifest against
# every capability family, and gating a TRANSCRIBE render would be gating the
# transcription of today's prompt rather than the prompt the rules will emit.
# It is ADAPT on purpose and always has been; it is in this table so that it
# reads as an exemption with a reason instead of as the one violation nobody
# noticed.

@dataclass(frozen=True)
class Expected:
    mode: str
    item: str
    why: str
    production: bool = True


PHASE_TABLE: dict[str, Expected] = {
    "agents/shared/shared/validate/llm_judge.py::_judge_prompt": Expected(
        "ADAPT", "4.1",
        "the L5 judge — the last site to flip, and the only one where the "
        "prompt-TEXT half of its item landed first (4.1/4.1b qualified the "
        "three abstention sites and took the tool-call rate 0 -> 100% on "
        "qwen3.6-35b-a3b). FLIPPED. `response_format` is the one thing ADAPT "
        "arms that this site still discards: `_call_llm` decides structured "
        "output for itself (json_object first, plain on any failure, because "
        "local providers 400 on the parameter) and `_call_llm_with_tools` "
        "never sets it. What the flip actually ships is three rules — the 4.7 "
        "mirror into the user turn, 4.8's language pin narrowed to the four "
        "families that ask for it, and the no-system-role fold. The fold is "
        "why `_judge_turns` exists: `.instructions` comes back empty for "
        "gemma and the hand-built two-element literal would have sent "
        "`{'role': 'system', 'content': ''}` in front of the real turn (the "
        "judge's form of the ['user','user'] regression item 4.5 hit in "
        "PROVE).",
    ),
    "agents/shared/shared/audit_runner.py::_generate_rendered": Expected(
        "ADAPT", "4.4",
        "the GENERATE tier's live prompt, rendered from `live_spec`. FLIPPED "
        "(item 4.4). Two rules bite here and both had to be made safe first. "
        "Rule 4+5 drops the prose JSON contract for a profile that can enforce "
        "the shape, but `supports_structured_output()` is ALSO False behind any "
        "custom endpoint — a transport fact no family profile carries — so the "
        "site renders against a profile whose `structured` is narrowed to NONE "
        "when the call says the endpoint cannot enforce it, or an openai model "
        "behind a gateway would get no contract from either side. And the "
        "no-system-role fold moves the whole system turn into the user turn, "
        "which is only lossless because `_build_llm_prompt` is now given the "
        "same `vocabulary` / `fenced` facts as `_generate_system_prompt`: the "
        "tier renders its two turns from two separate renders, and the one "
        "that is kept has to fold the same set the other one dropped.",
    ),
    "agents/shared/shared/prompt/manifests/generate.py::domain_instructions": Expected(
        "ADAPT", "4.4",
        "the agent identity half of the same tier's system turn (Phase 2.5). "
        "FLIPPED with `_generate_rendered`, or the two halves of one system "
        "message would be rendered under two different rule sets. Byte-neutral "
        "across all ten families and asserted so per agent per family: a "
        "`domains/` fragment carries neither REQUIRES_FENCE nor BINDS_LANGUAGE, "
        "so the only rule that reaches it is the fold — and this function "
        "returns ONE string for ONE channel, so `.instructions or .user` is "
        "that fold's inverse.",
    ),
    "agents/prove/prove_agent/llm_helper.py::_render": Expected(
        "ADAPT", "4.5",
        "every PROVE prompt — system turn, plan, reflect, analyze — goes "
        "through this one helper. FLIPPED (Item 4.5): byte-identical to the "
        "transcription on the default openai profile (the armed "
        "`response_format` is discarded by this JSON call site); ADAPT earns "
        "its keep on a no-system-role profile (gemma), folding the JSON-API "
        "system turn into the front of the single user turn.",
    ),
    "agents/discover/discover_agent/plugins/llm_suggest.py::_suggest_messages": Expected(
        "ADAPT", "4.6",
        "the discover endpoint-suggestion round. FLIPPED: 4.6 split the one "
        "user turn into `discover/system` + `discover/suggest`, and ADAPT is "
        "what makes that placement conditional — a family whose chat template "
        "has no system role (gemma) gets the instructions folded into the "
        "front of its single user turn instead of a system message the "
        "template would drop. This site takes only `.messages`; the "
        "`response_format` ADAPT also arms is discarded, because the call "
        "site derives it from `uses_custom_endpoint()`, a transport fact the "
        "profile does not carry.",
    ),
    "agents/shared/shared/prompt/lint.py::sweep": Expected(
        "ADAPT", "n/a — the linter, not a call site",
        "promptlint must see what the RULES emit, not what the transcription "
        "emits: rules 4+5 drop the prose JSON contract for a structured-output "
        "profile and rule 9 the language pin, and a check that ran against "
        "TRANSCRIBE would report violations no model will ever be shown.",
        production=False,
    ),
}


# ── the gate ──────────────────────────────────────────────────────────────

def test_mode_matches_phase():
    """Each site renders in the mode its Phase 4 item says it does."""
    wrong = [
        f"{s.key} (line {s.line}) renders {s.mode}, phase table says "
        f"{PHASE_TABLE[k].mode} (item {PHASE_TABLE[k].item}: {PHASE_TABLE[k].why})"
        for k, s in sorted(SITES.items())
        if k in PHASE_TABLE and s.mode != PHASE_TABLE[k].mode
    ]
    assert wrong == [], (
        "a call site's renderer mode no longer matches the phase table. If the "
        "flip is the point, update the row in PHASE_TABLE in the same commit, "
        "re-capture that site's goldens and bump the manifest version:\n"
        + "\n".join(wrong)
    )


def test_the_table_covers_exactly_the_call_sites_in_the_tree():
    """A seventh site, or a deleted one, is a table review — not a silence."""
    found, pinned = set(SITES), set(PHASE_TABLE)
    assert found == pinned, (
        f"untabled call site(s): {sorted(found - pinned)}; "
        f"table row(s) matching no call site: {sorted(pinned - found)}"
    )


def test_every_site_states_its_mode_as_a_literal_constant():
    """`mode` is a call-site constant, not a flag (render.py; LLD §4.0).

    A `mode=` computed from an env var, a config value or a conditional would
    make the rendered prompt depend on deployment, which is the arrangement
    this feature replaced. It also defeats the table above, which can only pin
    what is written in the source.
    """
    computed = [f"{s.key} (line {s.line}): mode={s.mode}"
                for s in SITES.values() if s.mode not in ("TRANSCRIBE", "ADAPT")]
    assert computed == [], (
        "mode must be a literal `Mode.TRANSCRIBE` / `Mode.ADAPT` at the call "
        "site — no variable, no env read, no conditional:\n" + "\n".join(computed)
    )


def test_the_renderer_default_mode_is_transcribe():
    """The safe default: a site opts INTO adaptation, never out of it.

    Pinned separately because the table can only see sites that name a mode. If
    the signature default flipped, every site that omits `mode=` would adapt
    silently — there are none today, and this is what keeps that true.
    """
    default = inspect.signature(render).parameters["mode"].default
    assert default is Mode.TRANSCRIBE, default
    assert DEFAULT_MODE == "TRANSCRIBE"


def test_the_linter_is_the_only_render_exempt_from_the_phase_order():
    """`production=False` is an exemption, and exemptions do not multiply.

    Only a render that no audit can reach may sit outside the phase order. One
    does — `lint.sweep()` — and a second row quietly claiming the same status
    would be a production site removed from Phase 4's sequencing without a
    Phase 4 item, which is the whole thing this table exists to prevent.
    """
    exempt = {k for k, e in PHASE_TABLE.items() if not e.production}
    assert exempt == {"agents/shared/shared/prompt/lint.py::sweep"}, exempt


# How many audit-path sites Phase 4 has flipped to ADAPT so far. A RATCHET, the
# same shape as `test_0089_gate.COMMITTED_ALLOW_ENTRIES`: each item raises it by
# one, deliberately, in the commit that flips its site. Exact equality in both
# directions, so an accidental flip fails and so does a revert that leaves the
# count behind.
PRODUCTION_ADAPT_SITES = 5      # + 4.1 VALIDATE; 4.6 DISCOVER, 4.5 PROVE,
                                # 4.4 both GENERATE sites. Phase 4 is complete:
                                # every production site adapts, and the only
                                # TRANSCRIBE renders left in the tree are the
                                # suite's own oracles.


def test_the_number_of_flipped_production_sites_is_pinned():
    """One number for "how far into Phase 4 is the renderer", not a guess."""
    flipped = sorted(k for k, e in PHASE_TABLE.items()
                     if e.production and e.mode == "ADAPT")
    assert len(flipped) == PRODUCTION_ADAPT_SITES, (
        f"{len(flipped)} production site(s) render ADAPT ({flipped}), pinned at "
        f"{PRODUCTION_ADAPT_SITES}. Raise PRODUCTION_ADAPT_SITES in the commit "
        "that flips one; lower it if a flip is being rolled back."
    )


def test_every_row_names_the_item_that_owns_its_mode():
    """An unexplained row is indistinguishable from a mode nobody chose."""
    for key, exp in sorted(PHASE_TABLE.items()):
        assert exp.item.strip(), f"{key}: no Phase 4 item"
        assert exp.why.strip(), f"{key}: no reason"
        assert exp.mode in ("TRANSCRIBE", "ADAPT"), f"{key}: {exp.mode!r}"


# ── the scan itself must not go blind ─────────────────────────────────────

def test_the_scan_is_not_vacuous():
    """A scanner that matched nothing would satisfy every assertion above."""
    assert len(SITES) >= 6, SITES
    assert {s.path for s in SITES.values()} >= {
        "agents/shared/shared/validate/llm_judge.py",
        "agents/shared/shared/audit_runner.py",
        "agents/prove/prove_agent/llm_helper.py",
        "agents/discover/discover_agent/plugins/llm_suggest.py",
    }


def test_a_crude_text_scan_finds_the_same_explicit_sites():
    """An independent, dumber detector, so the AST walk cannot fail silently.

    `grep`-grade: every `mode=Mode.X` in the same files, by (path, line). It
    cannot see a site that omits `mode=`, so the comparison is against the
    EXPLICIT sites only — which is all six of them today, and the assertion
    below says so rather than letting the set quietly empty out.
    """
    pattern = re.compile(r"mode\s*=\s*(?:[\w.]+\.)?Mode\.(TRANSCRIBE|ADAPT)")
    text_hits = {
        (p.relative_to(ROOT).as_posix(), i): m.group(1)
        for p in _candidates()
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if (m := pattern.search(line))
    }
    ast_hits = {(s.path, s.mode_line): s.mode for s in SITES.values() if s.explicit}
    assert text_hits == ast_hits
    assert len(ast_hits) == len(SITES), "a site stopped naming its mode"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from shared.prompt import render\ndef f():\n"
         "    return render(S, P, mode=Mode.TRANSCRIBE)\n", ("f", "TRANSCRIBE", True)),
        ("from shared.prompt import render\ndef f():\n"
         "    return render(S, P, mode=Mode.ADAPT)\n", ("f", "ADAPT", True)),
        ("from ..render import render\ndef f():\n"
         "    return render(S, P)\n", ("f", DEFAULT_MODE, False)),
        ("from shared.prompt import render as _r\nclass C:\n    def m(self):\n"
         "        return _r(S, P, mode=Mode.ADAPT)\n", ("C.m", "ADAPT", True)),
        ("from shared import prompt\ndef f():\n"
         "    return prompt.render(S, P, mode=Mode.ADAPT)\n", ("f", "ADAPT", True)),
        ("from shared.prompt import render\ndef f():\n"
         "    return render(S, P, mode=_from_env())\n", ("f", "_from_env()", True)),
    ],
    ids=["transcribe", "adapt", "implicit-default", "aliased-import",
         "module-qualified", "computed-not-a-constant"],
)
def test_the_scanner_reads_the_mode_a_source_file_actually_states(
    tmp_path, source, expected,
):
    """Red team: prove the flip is detectable, without mutating the tree.

    Every shape the scanner claims to handle, on synthetic files: the two
    constants, the implicit default, an aliased import, a module-qualified
    call, and a computed mode (which must survive unresolved so that
    `test_every_site_states_its_mode_as_a_literal_constant` can fail on it).
    """
    path = tmp_path / "probe.py"
    path.write_text(source, encoding="utf-8")
    sites = _sites_in(path, tmp_path)
    assert len(sites) == 1, sites
    qual, mode, explicit = expected
    assert sites[0].key.endswith(f"::{qual}")
    assert (sites[0].mode, sites[0].explicit) == (mode, explicit)


def test_two_renders_in_one_function_get_distinct_keys(tmp_path):
    """Otherwise the second one inherits the first one's table row."""
    path = tmp_path / "two.py"
    path.write_text(
        "from shared.prompt import render\n"
        "def f():\n"
        "    a = render(S, P, mode=Mode.TRANSCRIBE)\n"
        "    return a, render(S, P, mode=Mode.ADAPT)\n",
        encoding="utf-8",
    )
    sites = _sites_in(path, tmp_path)
    assert [s.key.rsplit("::", 1)[1] for s in sites] == ["f#0", "f#1"]
    assert [s.mode for s in sites] == ["TRANSCRIBE", "ADAPT"]
