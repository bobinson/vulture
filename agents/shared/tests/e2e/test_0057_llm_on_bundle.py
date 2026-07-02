"""Feature 0057 Phase 0 + Phase 1 — LLM-on bundle business-logic contracts.

TDD: these tests are the CONTRACT. They are written BEFORE the implementation
and MUST currently FAIL (RED) for the right reason — the feature is not yet
built — never error out for unrelated import/setup reasons.

All LLM behaviour is exercised through the deterministic, network-free
FakeLLMProvider / patch_l5_judge seams (see tests/_fake_llm.py). R9: the CI
gate never calls a live model.

Test map (plan §8):
    T1  code_snippet populated on every finding before validation
    T2  L5 skips findings whose code window is empty (judges only grounded ones)
    T3  skills stay authoritative — L5 never auto-suppresses a deterministic finding
    T4  LLM findings are deduped against skill findings (net-new only)
    T5  RC6 blast-radius cap — L5 freezes when it would demote >50% of judged findings
    T7  per-audit budget cap — VULTURE_LLM_BUDGET_USD stops the LLM phase early w/ a notice
    T12 batch sweep — the LLM phase iterates beyond a single context window

T6 (graceful no-model) is a CWE-agent contract — the model-availability gate
(P1a) lives in cwe_agent.agent + shared.llm.health, NOT in run_combined_audit.
It is tested in agents/cwe/tests/e2e/test_0057_cwe_llm_on.py.
"""

from __future__ import annotations

import json


from shared.audit_runner import run_combined_audit
from tests._fake_llm import (
    FakeLLMProvider,
    fake_finding,
    install_fake_runner,
    patch_l5_judge,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# A non-empty tools list is required for run_combined_audit to enter the LLM
# phase (`if effective_use_llm and skill_tools and instructions`). The agents
# SDK accepts arbitrary objects in the tools list when Runner.run is faked.
_DUMMY_TOOLS = ["__dummy_tool__"]


def _parse_event(events: list[str], event_name: str) -> dict:
    for event in events:
        if f"event: {event_name}" in event:
            data_line = [ln for ln in event.split("\n") if ln.startswith("data:")][0]
            return json.loads(data_line[5:])
    raise AssertionError(f"no '{event_name}' event found in SSE output")


def _result_findings(events: list[str]) -> list[dict]:
    return _parse_event(events, "result")["findings"]


def _all_text(events: list[str]) -> str:
    """Concatenate every thinking/text_message payload for notice assertions."""
    out: list[str] = []
    for event in events:
        if "event: thinking" in event or "event: text" in event.lower():
            for ln in event.split("\n"):
                if ln.startswith("data:"):
                    out.append(ln[5:])
    return "\n".join(out)


def _make_source(tmp_path, name: str, body: str) -> str:
    f = tmp_path / name
    f.write_text(body)
    return str(tmp_path)


def _skill_returning(findings: list[dict]):
    def _skill(_source_path: str) -> dict:
        return {"findings": [dict(f) for f in findings]}
    return _skill


# --------------------------------------------------------------------------- #
# T1 — code_snippet populated on every finding before validation (P0.1/P0.2)
# --------------------------------------------------------------------------- #


class TestT1CodeSnippetPopulated:
    """P0: a central _attach_code_snippet() populates a real code window on
    EVERY finding (skill + LLM) before validation. Skill findings that already
    carry a snippet keep it; LLM findings (which never carry one) get one read
    from the referenced source line."""

    def test_llm_finding_gets_code_snippet_from_source(self, tmp_path, monkeypatch):
        body = (
            "import sqlite3\n"
            "def q(user):\n"
            "    cur = db.cursor()\n"
            "    cur.execute(f\"SELECT * FROM t WHERE id={user}\")\n"  # line 4
            "    return cur.fetchall()\n"
        )
        src = _make_source(tmp_path, "app.py", body)

        fake = FakeLLMProvider(scripted=[
            fake_finding(
                title="SQL injection via f-string",
                category="CWE-89",
                file_path="app.py",
                line_start=4,
                line_end=4,
            ),
        ])
        install_fake_runner(monkeypatch, fake)

        events = list(run_combined_audit(
            run_id="t1-llm",
            source_path=src,
            categories=["x"],
            skill_map={"x": _skill_returning([])},
            skill_tools=_DUMMY_TOOLS,
            instructions="audit",
            model="gpt-4o",
            use_llm=True,
        ))

        findings = _result_findings(events)
        llm_f = next(f for f in findings if f["title"] == "SQL injection via f-string")
        assert llm_f.get("code_snippet"), (
            "LLM finding must carry a non-empty code_snippet read from source"
        )
        # The window must contain the actual offending source line.
        assert "SELECT * FROM t" in llm_f["code_snippet"]

    def test_skill_finding_without_snippet_gets_one(self, tmp_path, monkeypatch):
        body = "a = 1\nb = 2\ndangerous = eval(b)\nc = 3\n"  # line 3
        src = _make_source(tmp_path, "mod.py", body)

        skill = _skill_returning([{
            "severity": "high",
            "category": "CWE-95",
            "title": "eval of input",
            "description": "d",
            "file_path": f"{src}/mod.py",
            "line_start": 3,
            "line_end": 3,
            "recommendation": "r",
            "check_id": "cwe.eval",
            # deliberately NO code_snippet
        }])

        # LLM off — this is purely the P0 central populator on skill findings.
        events = list(run_combined_audit(
            run_id="t1-skill",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            use_llm=False,
        ))

        f = next(f for f in _result_findings(events) if f["title"] == "eval of input")
        assert f.get("code_snippet"), (
            "skill findings missing a snippet must be back-filled by _attach_code_snippet"
        )
        assert "eval(b)" in f["code_snippet"]


# --------------------------------------------------------------------------- #
# T2 — L5 skips blind findings (P0.3)
# --------------------------------------------------------------------------- #


class TestT2L5SkipsBlind:
    """The L5 judge must SKIP any finding whose code window is empty — it must
    never judge blind. After P0, every finding is grounded; but a finding whose
    snippet cannot be resolved (e.g. line_start=0) must not be sent to L5."""

    def test_blind_finding_not_sent_to_judge(self, tmp_path, monkeypatch):
        from shared.validate import validate, ValidateConfig

        seen_messages: list[str] = []
        patch_l5_judge(monkeypatch, default_exploitable=0.9,
                       record_seen_snippets=seen_messages)

        findings = [
            {
                "id": "grounded",
                "severity": "high", "category": "CWE-89",
                "title": "grounded", "description": "d",
                "file_path": "a.py", "line_start": 3, "line_end": 3,
                "code_snippet": "3: bad = f'SELECT {x}'",
            },
            {
                "id": "blind",
                "severity": "high", "category": "CWE-89",
                "title": "blind", "description": "d",
                "file_path": "b.py", "line_start": 0, "line_end": 0,
                "code_snippet": "",   # empty window — must be skipped
            },
        ]
        cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
        result = validate(findings, source_path="", config=cfg, audit_id="t2")

        ids_seen = set()
        for msg in seen_messages:
            import re as _re
            ids_seen.update(_re.findall(r"id=(\S+)", msg))

        assert "blind" not in ids_seen, (
            "L5 must NOT judge a finding with an empty code window"
        )

        def _judged(fid: str) -> bool:
            f = next(f for f in result.findings if f["id"] == fid)
            return any(
                c.get("id") == "llm_judge"
                for c in f.get("validation", {}).get("checks", [])
            )

        assert not _judged("blind"), "blind finding must carry no llm_judge check"
        assert _judged("grounded"), "grounded finding should still be judged"


# --------------------------------------------------------------------------- #
# T3 — skills stay authoritative (R2, voter floor + trusted tier)
# --------------------------------------------------------------------------- #


class TestT3SkillsAuthoritative:
    """A deterministic (skill) finding must NEVER be auto-suppressed to
    likely_fp by the LLM/L5 path alone. Even when the L5 judge returns
    exploitable=0.0, a skill finding must survive — and be marked as a
    trusted/deterministic provenance so the voter's 2-demoting floor protects
    it from the non-deterministic layer."""

    def test_l5_zero_verdict_does_not_suppress_skill_finding(self, tmp_path, monkeypatch):
        from shared.validate import validate, ValidateConfig

        # Place the finding in a test-path file so L1 adds a -0.20 demoting
        # path check; combined with an L5 exploitable=0.0 (weight -0.75) this
        # is two demoting checks + low confidence => today's voter rule would
        # classify likely_fp. The feature must keep deterministic findings safe.
        srcfile = tmp_path / "tests" / "sample_test.py"
        srcfile.parent.mkdir(parents=True)
        srcfile.write_text("x = 1\nbad = eval(x)\ny = 2\n")

        skill_finding = {
            "id": "skill-1",
            "severity": "high", "category": "CWE-95",
            "title": "eval of input", "description": "d",
            "file_path": str(srcfile), "line_start": 2, "line_end": 2,
            "recommendation": "r", "check_id": "cwe.eval",
            "code_snippet": "2: bad = eval(x)",
            # The pipeline tags deterministic findings; assert the contract
            # on the resulting status, not on a marker the test invents.
        }

        patch_l5_judge(monkeypatch, verdicts={"skill-1": 0.0})
        cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
        result = validate([skill_finding], source_path=str(tmp_path), config=cfg,
                          audit_id="t3")

        f = result.findings[0]
        assert f["validation_status"] != "likely_fp", (
            "L5 + path demotion must not auto-suppress a deterministic skill finding "
            "(R2: skills authoritative). The deterministic/trusted tier must hold the "
            "2-demoting floor against the non-deterministic L5 layer."
        )


# --------------------------------------------------------------------------- #
# T4 — LLM findings deduped against skill findings (R3)
# --------------------------------------------------------------------------- #


class TestT4LlmDeduped:
    """LLM findings that duplicate a skill finding are dropped; only genuinely
    net-new LLM findings surface (R3). The duplicate must be recognised even
    though the LLM reports a repo-RELATIVE path while the skill reports an
    ABSOLUTE path for the same file+check_id — the feature's cross-phase dedup
    must be path-robust, otherwise the same vuln double-reports."""

    def test_duplicate_llm_finding_dropped_new_one_kept(self, tmp_path, monkeypatch):
        body = "import os\nq = f\"SELECT {os.environ}\"\nweak = md5(x)\n"
        src = _make_source(tmp_path, "app.py", body)

        skill = _skill_returning([{
            "severity": "high", "category": "CWE-89",
            "title": "SQL injection", "description": "d",
            "file_path": f"{src}/app.py", "line_start": 2, "line_end": 2,  # absolute
            "recommendation": "r", "check_id": "cwe.injection.sql",
            "code_snippet": "2: q = f\"SELECT ...\"",
        }])

        fake = FakeLLMProvider(scripted=[
            # duplicate of the skill finding (same check_id, same file via a
            # repo-relative path) -> must be deduped despite the path form.
            fake_finding(title="SQL injection", category="CWE-89",
                         file_path="app.py", line_start=2, line_end=2,
                         check_id="cwe.injection.sql"),
            # net-new -> kept
            fake_finding(title="Weak hash MD5", category="CWE-328",
                         file_path="app.py", line_start=3, line_end=3,
                         check_id="cwe.crypto.weak_hash"),
        ])
        install_fake_runner(monkeypatch, fake)

        events = list(run_combined_audit(
            run_id="t4",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            skill_tools=_DUMMY_TOOLS,
            instructions="audit",
            model="gpt-4o",
            use_llm=True,
        ))

        findings = _result_findings(events)
        titles = [f["title"] for f in findings]
        # Exactly one "SQL injection" (the skill's) — the LLM duplicate is deduped.
        assert titles.count("SQL injection") == 1, (
            f"LLM duplicate must be deduped against the skill finding; got {titles}"
        )
        assert "Weak hash MD5" in titles, "net-new LLM finding must be kept"


# --------------------------------------------------------------------------- #
# T5 — RC6 blast-radius cap (P1b)
# --------------------------------------------------------------------------- #


class TestT5Rc6BlastRadiusCap:
    """RC6: if the L5 verdicts would demote MORE THAN 50% of the judged
    findings, the L5 layer is frozen (its verdicts are discarded) so a
    mass-FP run cannot gut the result. Below the cap, L5 verdicts apply."""

    def test_l5_frozen_when_majority_demoted(self, tmp_path, monkeypatch):
        from shared.validate import validate, ValidateConfig

        # 4 grounded findings; L5 would mark 3 of 4 (75% > 50%) non-exploitable.
        findings = []
        for i in range(4):
            findings.append({
                "id": f"f{i}",
                "severity": "high", "category": "CWE-89",
                "title": f"finding {i}", "description": "d",
                "file_path": f"f{i}.py", "line_start": 1, "line_end": 1,
                "code_snippet": f"1: bad{i} = f'SELECT {{x}}'",
            })

        verdicts = {"f0": 0.0, "f1": 0.0, "f2": 0.0, "f3": 0.9}
        patch_l5_judge(monkeypatch, verdicts=verdicts)
        cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
        result = validate(findings, source_path=str(tmp_path), config=cfg,
                          audit_id="t5")

        # RC6: because >50% would be demoted, NO finding should carry an
        # applied (weight-bearing) llm_judge demotion — the layer is frozen.
        def _has_demoting_l5(f: dict) -> bool:
            for c in f.get("validation", {}).get("checks", []):
                if c.get("id") == "llm_judge" and c.get("weight", 0.0) < 0:
                    return True
            return False

        demoted = [f["id"] for f in result.findings if _has_demoting_l5(f)]
        assert demoted == [], (
            "RC6 blast-radius cap must FREEZE L5 when it would demote >50% of "
            f"judged findings; found applied demotions for {demoted}"
        )

    def test_l5_applies_when_below_cap(self, tmp_path, monkeypatch):
        from shared.validate import validate, ValidateConfig

        findings = []
        for i in range(4):
            findings.append({
                "id": f"g{i}",
                "severity": "high", "category": "CWE-89",
                "title": f"finding {i}", "description": "d",
                "file_path": f"g{i}.py", "line_start": 1, "line_end": 1,
                "code_snippet": f"1: bad{i} = f'SELECT {{x}}'",
            })

        # Only 1 of 4 (25% <= 50%) demoted — L5 applies normally.
        verdicts = {"g0": 0.0, "g1": 0.9, "g2": 0.9, "g3": 0.9}
        patch_l5_judge(monkeypatch, verdicts=verdicts)
        cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
        result = validate(findings, source_path=str(tmp_path), config=cfg,
                          audit_id="t5b")

        g0 = next(f for f in result.findings if f["id"] == "g0")
        has_demoting = any(
            c.get("id") == "llm_judge" and c.get("weight", 0.0) < 0
            for c in g0.get("validation", {}).get("checks", [])
        )
        assert has_demoting, (
            "below the RC6 cap, L5 demoting verdicts must still apply"
        )


# --------------------------------------------------------------------------- #
# T7 — per-audit budget cap (P1d)
# --------------------------------------------------------------------------- #


class TestT7BudgetCap:
    """VULTURE_LLM_BUDGET_USD bounds the LLM phase: once the estimated spend
    crosses the cap, the batch loop stops and a partial-results notice is
    emitted. Real token counts are reported even when cost is 0 (local)."""

    def test_budget_exceeded_stops_phase_and_notices(self, tmp_path, monkeypatch):
        # gpt-4o has a non-zero cost, so token usage maps to USD spend.
        monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
        # A tiny budget that the very first batch's token usage blows past.
        monkeypatch.setenv("VULTURE_LLM_BUDGET_USD", "0.0000001")
        # 0059: exercises the multi-file budget cap → needs the full sweep
        # (Tier-3 on); the generic test files are Tier 3, off by default.
        monkeypatch.setenv("VULTURE_LLM_TIER3", "on")

        # Many files so the sweep WOULD otherwise issue several batches.
        for i in range(8):
            (tmp_path / f"f{i}.py").write_text(
                "\n".join(f"line{j} = {j}" for j in range(40))
            )
        src = str(tmp_path)

        # Each call returns a net-new finding + large token usage.
        fake = FakeLLMProvider(
            scripted_per_call=[
                [fake_finding(title=f"batch{i}", category="CWE-89",
                              file_path=f"f{i}.py", line_start=1, line_end=1,
                              check_id=f"cwe.x.{i}")]
                for i in range(8)
            ],
            input_tokens=500_000,
            output_tokens=100_000,
        )
        install_fake_runner(monkeypatch, fake)

        events = list(run_combined_audit(
            run_id="t7",
            source_path=src,
            categories=["x"],
            skill_map={"x": _skill_returning([])},
            skill_tools=_DUMMY_TOOLS,
            instructions="audit",
            model="gpt-4o",
            use_llm=True,
        ))

        # The budget must cut the sweep short — far fewer calls than 8 batches.
        assert fake.calls < 8, (
            f"budget cap must stop the LLM phase early; made {fake.calls} calls"
        )

        notice = _all_text(events).lower()
        assert "partial" in notice or "budget" in notice, (
            "a partial-results / budget notice must be emitted when the cap is hit"
        )


# --------------------------------------------------------------------------- #
# T12 — batch sweep beyond a single context window (P1f / R6b)
# --------------------------------------------------------------------------- #


class TestT12BatchSweep:
    """The LLM phase must iterate over multiple context-window-sized batches
    until the tree is covered (or the budget is hit) — not a single shot that
    silently tail-drops files. With a tiny context window forcing >1 batch and
    distinct findings per batch, all net-new findings must surface and the
    successive batches must carry different files."""

    def test_multiple_batches_cover_all_files(self, tmp_path, monkeypatch):
        # Force a very small source budget so the file set spans many batches.
        monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "400")
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "2000")
        # 0059: this asserts the WHOLE-TREE sweep (R6b), which requires Tier-3
        # ON. The generic test files are Tier 3, skipped under the new default.
        monkeypatch.setenv("VULTURE_LLM_TIER3", "on")

        # Several reasonably-sized files; one window cannot hold them all. With
        # this budget each file lands in its own batch, so n_files == n_batches.
        n_files = 6
        for i in range(n_files):
            (tmp_path / f"file{i}.py").write_text(
                f"# file {i}\n" + "\n".join(f"x{i}_{j} = {j}" for j in range(30))
            )
        src = str(tmp_path)

        # Each batch returns a finding keyed to a DIFFERENT file.
        fake = FakeLLMProvider(scripted_per_call=[
            [fake_finding(title=f"finding in file{i}", category="CWE-89",
                          file_path=f"file{i}.py", line_start=1, line_end=1,
                          check_id=f"cwe.sweep.{i}")]
            for i in range(n_files)
        ])
        install_fake_runner(monkeypatch, fake)

        events = list(run_combined_audit(
            run_id="t12",
            source_path=src,
            categories=["x"],
            skill_map={"x": _skill_returning([])},
            skill_tools=_DUMMY_TOOLS,
            instructions="audit",
            model="gpt-4o",
            use_llm=True,
        ))

        # R6b full coverage: the sweep must issue exactly one batch PER file
        # (no single-shot tail-drop, no redundant re-sweep). Each file is its
        # own window under this budget, so calls == windows == n_files.
        assert fake.calls == n_files, (
            f"LLM phase must batch-loop once per window with no tail-drop; "
            f"expected {n_files} calls, made {fake.calls}"
        )
        # Every batch the loop issued is recorded.
        assert len(fake.inputs) == fake.calls

        # FULL coverage: the net-new finding from EVERY batch must surface — not
        # just "at least two". Under R6b the sweep covers the whole tree, so all
        # n_files findings reach the result with none dropped.
        titles = {f["title"] for f in _result_findings(events)}
        covered = sum(1 for i in range(n_files) if f"finding in file{i}" in titles)
        assert covered == n_files, (
            f"R6b: net-new findings from ALL {n_files} batches must surface; "
            f"covered={covered}, titles={sorted(titles)}"
        )

        # Every window must be distinct — no batch repeats a previous window's
        # file set (proves the sweep advances through the whole tree, never
        # spinning on the same content).
        assert len(set(fake.inputs)) == n_files, (
            "each batch must carry a distinct file window (sweep must advance, "
            f"not repeat); distinct windows={len(set(fake.inputs))} of {n_files}"
        )
