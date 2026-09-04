"""Feature 0079 E10: the shared per-audit kwargs, and a floor that keeps them shared.

Two contracts:

1. ``shared_audit_kwargs`` reproduces, exactly, what seven agents each computed
   inline. This is a behaviour-preserving refactor, so equivalence is asserted
   per input class rather than assumed.
2. Every scan agent USES it. The duplication this replaces was re-introduced by
   six separate features; without a guard the seventh will do it again.

The second contract carries a COVERAGE FLOOR. ``test_0070_fleet_skill_dispatch``
has no floor -- all seven of its tests are parametrized over a hand-written
AGENTS list -- so an agent absent from the list is simply never tested. That is
how CWE once shipped 24 skills against 22 categories and lost 41 findings, 6 of
them critical. A guard that enumerates nothing must FAIL, not pass.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from shared.audit_kwargs import shared_audit_kwargs

AGENTS_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Same glob the 0078 conformance guard and the vocabulary reporter use, so none
# of the three can see a different fleet.
AGENT_PKG_GLOB = "*/[a-z]*_agent"

# Agents that legitimately do not call run_combined_audit and so have no shared
# preamble: owasp is a CATEGORIZER over CWE findings, discover and prove have
# their own lifecycles. Every other discovered agent must use the helper.
NO_COMBINED_AUDIT = frozenset({"owasp_agent", "discover_agent", "prove_agent"})


def _discover_agent_packages() -> list[pathlib.Path]:
    return sorted(p for p in AGENTS_ROOT.glob(AGENT_PKG_GLOB) if p.is_dir())


# ── contract 1: equivalence with the inline form ─────────────────────────────


@pytest.mark.parametrize(
    "cfg,want_use_llm,want_validate",
    [
        ({}, None, None),
        ({"use_llm": True}, True, None),
        ({"use_llm": False}, False, None),
        # A non-bool must NOT read as True. Seven inline copies each guarded
        # this with isinstance; the helper is now the single place it happens.
        ({"use_llm": "true"}, None, None),
        ({"use_llm": 1}, None, None),
        ({"validate": {"llm": True}}, None, True),
        ({"validate": {"llm": False}}, None, False),
        ({"validate": {}}, None, None),
        # `validate` present but not a dict must not explode.
        ({"validate": "yes"}, None, None),
        ({"use_llm": True, "validate": {"llm": False}}, True, False),
    ],
)
def test_three_valued_toggles_match_the_inline_form(tmp_path, cfg, want_use_llm, want_validate):
    kw = shared_audit_kwargs(cfg, str(tmp_path), None, "cwe")
    assert kw["use_llm"] is want_use_llm
    assert kw["validate_use_llm"] is want_validate


def test_llm_tier3_is_passed_through_raw(tmp_path):
    """run_combined_audit applies no isinstance guard to llm_tier3 today, and
    this refactor must not quietly add one."""
    for value in (True, False, None, "yes", 3):
        kw = shared_audit_kwargs({"llm_tier3": value}, str(tmp_path), None, "cwe")
        assert kw["llm_tier3"] == value or kw["llm_tier3"] is value


def test_prior_findings_none_and_empty_are_equivalent(tmp_path):
    """The dropped ``preloaded = prior_findings if prior_findings else None``
    line was a no-op: build_prior_context already branches on truthiness."""
    a = shared_audit_kwargs({}, str(tmp_path), None, "cwe")
    b = shared_audit_kwargs({}, str(tmp_path), [], "cwe")
    assert a["prior_context"] == b["prior_context"]


def test_model_is_not_returned(tmp_path):
    """``model`` is deliberately absent: the four agents that passed the env
    fallback and the three that passed nothing behaved identically, because
    every consumer resolves ``model or os.environ.get(...)``. Returning it here
    would re-introduce the redundancy in one place instead of four."""
    assert "model" not in shared_audit_kwargs({}, str(tmp_path), None, "cwe")


def test_returns_exactly_the_shared_kwargs(tmp_path):
    """Pinned so a future addition is a deliberate act. Anything agent-specific
    -- skill_map, skill_tools, domain_label, instructions -- must STAY at the
    call site, where the 0070 fleet guard can see it."""
    # Feature 0083: `l5_top_n` and `l5_batch_size` added deliberately. They are
    # per-request L5 sizing, shared by every scan agent, so they belong at this
    # seam and not at seven call sites. `--validate-llm-top-n` was already being
    # sent by the CLI and read by nobody; this is the reader.
    assert set(shared_audit_kwargs({}, str(tmp_path), None, "cwe")) == {
        "prior_context",
        "l5_top_n",
        "l5_batch_size",
        "use_llm",
        "validate_use_llm",
        "llm_tier3",
    }


# ── contract 2: the fleet actually uses it, with a coverage floor ────────────


def test_agent_discovery_is_not_vacuous():
    """THE FLOOR. A guard that enumerates nothing passes silently; this is the
    failure mode that let a mis-wired agent ship. Seven scan agents exist today,
    so six is a floor that admits growth and refuses an empty sweep."""
    found = _discover_agent_packages()
    assert len(found) >= 6, (
        f"agent discovery found only {len(found)} packages under "
        f"{AGENTS_ROOT}/{AGENT_PKG_GLOB} — the guard below would be vacuous"
    )


def _calls_shared_helper(agent_py: pathlib.Path) -> bool:
    tree = ast.parse(agent_py.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "shared_audit_kwargs":
                return True
    return False


def test_every_scan_agent_uses_the_shared_kwargs():
    """No agent may hand-roll the preamble again. Checked by AST over the real
    source, not by grep, so a mention in a comment or docstring does not count."""
    offenders = []
    for pkg in _discover_agent_packages():
        if pkg.name in NO_COMBINED_AUDIT:
            continue
        agent_py = pkg / "agent.py"
        if not agent_py.exists():
            continue
        if "run_combined_audit" not in agent_py.read_text():
            continue
        if not _calls_shared_helper(agent_py):
            offenders.append(str(agent_py.relative_to(AGENTS_ROOT)))
    assert not offenders, (
        "these agents call run_combined_audit but hand-roll the shared preamble "
        f"instead of using shared_audit_kwargs: {offenders}"
    )


def test_exemptions_are_not_stale():
    """An exemption for an agent that no longer exists hides a real gap. The
    0078 suite records that the conformance guard's do178c exemption already
    went stale once."""
    names = {p.name for p in _discover_agent_packages()}
    stale = sorted(NO_COMBINED_AUDIT - names)
    assert not stale, f"NO_COMBINED_AUDIT names agents that no longer exist: {stale}"


def _has_preloaded_no_op(agent_py: pathlib.Path) -> bool:
    """True when the file CODE re-introduces the no-op, ignoring comments.

    Deliberately AST-based. A substring search over the file text flags the
    comment that explains why the line was removed -- a guard that fires on its
    own documentation is the same defect as a guard that cannot fire, and this
    exact trap has already cost time on this codebase.
    """
    tree = ast.parse(agent_py.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.IfExp):
            continue
        exp = node.value
        # match: <name> = prior_findings if prior_findings else None
        if (
            isinstance(exp.test, ast.Name)
            and exp.test.id == "prior_findings"
            and isinstance(exp.body, ast.Name)
            and exp.body.id == "prior_findings"
            and isinstance(exp.orelse, ast.Constant)
            and exp.orelse.value is None
        ):
            return True
    return False


def test_no_agent_reintroduces_the_dropped_no_op():
    """``preloaded = prior_findings if prior_findings else None`` was proven a
    no-op and removed from seven files. Pin its absence in CODE."""
    offenders = [
        str((pkg / "agent.py").relative_to(AGENTS_ROOT))
        for pkg in _discover_agent_packages()
        if (pkg / "agent.py").exists() and _has_preloaded_no_op(pkg / "agent.py")
    ]
    assert not offenders, f"the proven no-op is back in: {offenders}"


def test_the_no_op_detector_is_not_vacuous():
    """The detector above must actually fire on the pattern it claims to catch,
    or it is a green test over nothing."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write("def f(prior_findings=None):\n"
                 "    preloaded = prior_findings if prior_findings else None\n"
                 "    return preloaded\n")
        probe = pathlib.Path(fh.name)
    try:
        assert _has_preloaded_no_op(probe), "detector failed to flag the real pattern"
    finally:
        probe.unlink()


# ── contract 3: every agent's run_audit ACTUALLY INVOKES cleanly ─────────────
#
# The tests above are static. They all passed while the cwe agent was broken at
# RUNTIME with:
#
#   TypeError: run_combined_audit() got multiple values for keyword argument
#              'use_llm'
#
# because cwe resolves its own toggles and my conversion left an explicit
# `use_llm=` beside the `**_shared` splat. A **splat plus an explicit keyword is
# a TypeError, not an override -- and no static check sees it. Only invoking the
# generator does. This class of defect reached a live agent process once; the
# guard below is why it cannot again.


def _agent_entry(pkg: pathlib.Path):
    """Import <pkg>.agent and return its run_audit, or None if not applicable."""
    import importlib
    import sys

    agent_py = pkg / "agent.py"
    if not agent_py.exists() or "run_combined_audit" not in agent_py.read_text():
        return None
    # Each agent package sits beside its sibling on sys.path in production
    # (PYTHONPATH=shared:<agent>), so mirror that rather than importing by file.
    root = str(pkg.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        mod = importlib.import_module(f"{pkg.name}.agent")
    except Exception:  # noqa: BLE001 - an unimportable agent is reported below
        return "IMPORT_FAILED"
    return getattr(mod, "run_audit", None)


@pytest.mark.parametrize("pkg", _discover_agent_packages(), ids=lambda p: p.name)
def test_run_audit_starts_without_a_signature_error(pkg, tmp_path, monkeypatch):
    """Drive each agent's generator far enough to bind its runner arguments.

    Skills-only and one tiny file, so this stays a signature check rather than a
    scan. A TypeError here means the call site and run_combined_audit disagree --
    exactly the failure the static tests cannot see.
    """
    if pkg.name in NO_COMBINED_AUDIT:
        pytest.skip(f"{pkg.name} does not call run_combined_audit")
    entry = _agent_entry(pkg)
    if entry is None:
        pytest.skip(f"{pkg.name} has no applicable run_audit")
    if entry == "IMPORT_FAILED":
        pytest.skip(f"{pkg.name} is not importable in this environment")

    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    (tmp_path / "a.py").write_text("x = 1\n")

    gen = entry("sig-probe", str(tmp_path), {}, None)
    try:
        # One chunk is enough: argument binding happens before the first yield
        # inside run_combined_audit.
        next(gen)
    except StopIteration:
        pass
    except TypeError as exc:  # the defect this test exists for
        pytest.fail(f"{pkg.name}: run_audit signature error -> {exc}")
    finally:
        gen.close()


# ---- feature 0083: per-request L5 sizing (I4) --------------------------------

def test_0083_l5_sizing_is_none_when_the_request_is_silent(tmp_path):
    """Behaviour preservation: an empty config must yield None for both, so
    every existing deployment resolves exactly as before."""
    out = shared_audit_kwargs({}, str(tmp_path), None, "cwe")
    assert out["l5_top_n"] is None
    assert out["l5_batch_size"] is None


def test_0083_l5_sizing_is_extracted_from_the_validate_block(tmp_path):
    cfg = {"validate": {"llm": True, "llm_top_n": 40, "llm_batch_size": 3}}
    out = shared_audit_kwargs(cfg, str(tmp_path), None, "cwe")
    assert out["l5_top_n"] == 40
    assert out["l5_batch_size"] == 3
    assert out["validate_use_llm"] is True


def test_0083_non_int_sizing_is_rejected_not_coerced(tmp_path):
    """A stray string must not reach int() and raise mid-audit. Booleans are
    ints in Python, so they are excluded explicitly."""
    for bad in ("40", 4.5, True, None, [], {}):
        out = shared_audit_kwargs(
            {"validate": {"llm_top_n": bad, "llm_batch_size": bad}},
            str(tmp_path), None, "cwe")
        assert out["l5_top_n"] is None, f"{bad!r} leaked through"
        assert out["l5_batch_size"] is None, f"{bad!r} leaked through"
