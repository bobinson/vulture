"""Feature 0057/0059 — CWE-agent LLM contracts (TDD).

These tests define the business contract for the CWE agent's LLM phase.

UNIFORMITY decision (feature 0059, maintainer-approved): the CWE agent no
longer runs its LLM phase BY DEFAULT. It respects ``VULTURE_USE_LLM`` (default
``false``) EXACTLY like every other scan agent — the LLM phase is OPT-IN
(``VULTURE_USE_LLM=true`` in the environment, or a per-request ``use_llm=true``
in the audit config). The graceful model-health gate (when LLM IS wanted but no
model is reachable ⇒ skills-only + notice, exit 0) and the
``VULTURE_CWE_DISABLE_LLM`` escape hatch (force skills-only) are RETAINED.

All LLM behaviour runs through the deterministic, network-free seams in
agents/shared/tests/_fake_llm.py (R9 — the gate never calls a live model).

Test map:
    T6  graceful no-model — LLM enabled + no usable model => skills-only + notice, exit 0
    T8a default OFF — VULTURE_USE_LLM unset + no per-request use_llm => skills-only (LLM phase never runs)
    T8b opt-in ON via env — VULTURE_USE_LLM=true + reachable model => LLM phase runs
    T8c opt-in ON via request — config use_llm=true + reachable model => LLM phase runs
    T8d escape hatch — VULTURE_CWE_DISABLE_LLM forces skills-only even when use_llm=True
    T8e sample-code TDD — vulnerable sample: default => skills-only; VULTURE_USE_LLM=true => LLM runs
    T9  the LLM finds a cross-line / dataflow gap the regex skills structurally miss (LLM enabled)
    T10 crypto/policy CWEs (326/327/328/330/798/319) are never auto-suppressed by L5
    T11 clean-code FP gate — on clean source the (enabled) LLM phase adds no findings
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

# The fake-LLM helper lives in the SHARED test tree (agents/shared/tests/
# _fake_llm.py). Its package name `tests` collides with the CWE `tests`
# package, so load it directly by file path under a unique module name.
_FAKE_LLM_PATH = (
    Path(__file__).resolve().parents[3] / "shared" / "tests" / "_fake_llm.py"
)
_spec = importlib.util.spec_from_file_location("_fake_llm_0057", _FAKE_LLM_PATH)
_fake_llm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fake_llm)

FakeLLMProvider = _fake_llm.FakeLLMProvider
fake_finding = _fake_llm.fake_finding
install_fake_runner = _fake_llm.install_fake_runner
patch_l5_judge = _fake_llm.patch_l5_judge

from cwe_agent.agent import run_audit  # noqa: E402


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _parse_event(events: list[str], event_name: str) -> dict:
    for event in events:
        if f"event: {event_name}" in event:
            data_line = [ln for ln in event.split("\n") if ln.startswith("data:")][0]
            return json.loads(data_line[5:])
    raise AssertionError(f"no '{event_name}' event found in SSE output")


def _result_findings(events: list[str]) -> list[dict]:
    return _parse_event(events, "result")["findings"]


@pytest.fixture(autouse=True)
def _isolate_l5_cache(tmp_path, monkeypatch):
    """Point the L5 verdict cache at a fresh per-test SQLite file so a stored
    verdict from one test never short-circuits the patched judge in another."""
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "l5_cache.db"))
    from shared.validate import l5_cache
    monkeypatch.setattr(l5_cache, "_CONN", None)
    monkeypatch.setattr(l5_cache, "_DB_PATH", None)
    monkeypatch.setattr(l5_cache, "_DISABLED", False)
    yield


@pytest.fixture
def usable_model(monkeypatch):
    """Configure a usable, non-network model + force the provider health
    probe to report reachable, so the model gate (P1a) lets the LLM phase
    run. `check_llm_health` is the stable gate seam — patched at its source
    module so it works regardless of how agent.py imports it."""
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-for-test")

    from shared.llm import health

    class _Reachable:
        reachable = True
        provider = "openai"
        model = "gpt-4o"
        endpoint = "https://api.openai.com/v1"
        error = ""

        def message(self) -> str:
            return "LLM ready: openai (gpt-4o) at https://api.openai.com/v1"

    async def _fake_health(timeout: float = 3.0):
        return _Reachable()

    monkeypatch.setattr(health, "check_llm_health", _fake_health)
    return "gpt-4o"


def _all_text(events: list[str]) -> str:
    out: list[str] = []
    for event in events:
        if "event: thinking" in event or "event: text" in event.lower():
            for ln in event.split("\n"):
                if ln.startswith("data:"):
                    out.append(ln[5:])
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# T6 — graceful no-model degradation (R5)
# --------------------------------------------------------------------------- #


class TestT6GracefulNoModel:
    """When the LLM phase is ENABLED but meets NO usable model, the CWE agent
    must degrade gracefully: run skills-only, emit an explicit notice, and
    complete (exit 0). Mode-E no-key users are protected. The model gate uses
    the provider health probe; here it reports unreachable. The FakeLLM records
    0 calls, proving the phase was skipped despite being requested."""

    def test_no_usable_model_runs_skills_only_with_notice(self, tmp_path, monkeypatch):
        # LLM phase explicitly requested (per-request use_llm=True) so the
        # model-health gate is reached — under the uniform default it would
        # otherwise be off and this test would not exercise the gate at all.
        # Strip every provider credential / endpoint so no model is usable.
        for var in ("VULTURE_LLM_MODEL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                    "GEMINI_API_KEY", "OLLAMA_API_BASE", "OPENAI_BASE_URL"):
            monkeypatch.delenv(var, raising=False)

        # Health probe reports unreachable (the gate's signal — P1a).
        from shared.llm import health

        class _Unreachable:
            reachable = False
            provider = "unknown"
            model = ""
            endpoint = ""
            error = "cannot infer provider from VULTURE_LLM_MODEL and env"

            def message(self) -> str:
                return ("LLM unavailable: unknown (no model) at default "
                        "— no model. Audit will run skills-only.")

        async def _fake_health(timeout: float = 3.0):
            return _Unreachable()

        monkeypatch.setattr(health, "check_llm_health", _fake_health)

        (tmp_path / "app.py").write_text(
            "import hashlib\n"
            "def h(p):\n"
            "    return hashlib.md5(p).hexdigest()\n"
        )

        # A recording (non-raising) fake: if the LLM phase runs, calls becomes
        # >= 1. The model gate must keep it at 0. (A raising fake would be
        # swallowed by the runner's broad except and leave calls at 0, which
        # would falsely pass — so we assert on a successful-return signal.)
        fake = FakeLLMProvider(scripted=[])
        install_fake_runner(monkeypatch, fake)

        # Request the LLM phase explicitly; the unreachable model gate must
        # still degrade it to skills-only.
        events = list(run_audit("t6", str(tmp_path), {"use_llm": True}))

        # Completed (exit 0) — a result event was produced.
        result = _parse_event(events, "result")
        assert result["findings"], "skills-only result must still carry findings"
        assert fake.calls == 0, (
            "LLM phase must be skipped when no usable model is configured"
        )
        notice = _all_text(events).lower()
        assert "skills-only" in notice or "skills only" in notice, (
            "an explicit skills-only notice must be emitted when degrading"
        )


# --------------------------------------------------------------------------- #
# T8 — uniform LLM toggle: OFF by default, opt-in via env or request
# --------------------------------------------------------------------------- #


class TestT8UniformLlmToggle:
    """Feature 0059 uniformity: the CWE agent respects VULTURE_USE_LLM (default
    false) like every other scan agent. The LLM phase is OPT-IN — it runs only
    when VULTURE_USE_LLM=true in the environment OR the per-request config sets
    use_llm=true. The VULTURE_CWE_DISABLE_LLM escape hatch still forces it off.
    """

    def test_default_off_no_per_request_flag_runs_skills_only(
        self, tmp_path, usable_model, monkeypatch
    ):
        """T8a: VULTURE_USE_LLM unset + no per-request use_llm => the LLM phase
        does NOT run, even though a usable model is reachable. This is the
        uniform default that the old CWE LLM-on-by-default behaviour violated.
        """
        # Ensure the global flag is unset so the runtime default (false) applies.
        monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def q(uid):\n"
            "    return db.execute(f\"SELECT * FROM t WHERE id={uid}\")\n"
        )

        # Recording (non-raising) fake — calls == 0 proves the phase was
        # skipped (a raising fake would be swallowed and falsely read as 0).
        fake = FakeLLMProvider(scripted=[
            fake_finding(title="LLM net-new", category="CWE-89",
                         file_path="app.py", line_start=3, line_end=3,
                         check_id="cwe.llm.netnew"),
        ])
        install_fake_runner(monkeypatch, fake)

        # NOTE: config has no "use_llm" key and VULTURE_USE_LLM is unset.
        events = list(run_audit("t8a", str(tmp_path), {}))

        # Completed (exit 0) on the skills-only path.
        result = _parse_event(events, "result")
        assert result["findings"], "skills-only result must still carry findings"
        assert fake.calls == 0, (
            "CWE must NOT run the LLM phase by default — it respects "
            f"VULTURE_USE_LLM (default false); fake.calls={fake.calls}"
        )
        titles = [f["title"] for f in result["findings"]]
        assert "LLM net-new" not in titles, (
            "the LLM-sourced finding must NOT surface when the LLM phase is off"
        )

    def test_env_opt_in_runs_llm_phase(self, tmp_path, usable_model, monkeypatch):
        """T8b: VULTURE_USE_LLM=true + a reachable model => the LLM phase runs,
        with no per-request use_llm needed (env opt-in, uniform with the fleet).
        """
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def q(uid):\n"
            "    return db.execute(f\"SELECT * FROM t WHERE id={uid}\")\n"
        )

        fake = FakeLLMProvider(scripted=[
            fake_finding(title="LLM net-new", category="CWE-89",
                         file_path="app.py", line_start=3, line_end=3,
                         check_id="cwe.llm.netnew"),
        ])
        install_fake_runner(monkeypatch, fake)

        # config has no "use_llm" key — the env flag turns it on.
        events = list(run_audit("t8b", str(tmp_path), {}))

        assert fake.calls >= 1, (
            "CWE must run the LLM phase when VULTURE_USE_LLM=true and a usable "
            f"model exists (model-gated); fake.calls={fake.calls}"
        )
        titles = [f["title"] for f in _result_findings(events)]
        assert "LLM net-new" in titles, "the opt-in LLM finding must surface"

    def test_request_opt_in_runs_llm_phase(self, tmp_path, usable_model, monkeypatch):
        """T8c: per-request use_llm=true + a reachable model => the LLM phase
        runs even with VULTURE_USE_LLM unset (request override turns it on)."""
        monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def q(uid):\n"
            "    return db.execute(f\"SELECT * FROM t WHERE id={uid}\")\n"
        )

        fake = FakeLLMProvider(scripted=[
            fake_finding(title="LLM net-new", category="CWE-89",
                         file_path="app.py", line_start=3, line_end=3,
                         check_id="cwe.llm.netnew"),
        ])
        install_fake_runner(monkeypatch, fake)

        events = list(run_audit("t8c", str(tmp_path), {"use_llm": True}))

        assert fake.calls >= 1, (
            "per-request use_llm=true must run the LLM phase even when "
            f"VULTURE_USE_LLM is unset; fake.calls={fake.calls}"
        )
        titles = [f["title"] for f in _result_findings(events)]
        assert "LLM net-new" in titles, "the request-opt-in LLM finding must surface"

    def test_disable_escape_hatch_forces_skills_only(self, tmp_path, usable_model, monkeypatch):
        """T8d: VULTURE_CWE_DISABLE_LLM forces skills-only even when the request
        explicitly turns the LLM ON (the escape hatch wins)."""
        monkeypatch.setenv("VULTURE_CWE_DISABLE_LLM", "true")
        (tmp_path / "app.py").write_text("x = eval(input())\n")

        # Recording (non-raising) fake — calls == 0 proves the phase was
        # skipped (a raising fake would be swallowed and falsely read as 0).
        fake = FakeLLMProvider(scripted=[])
        install_fake_runner(monkeypatch, fake)

        # Request explicitly asks for the LLM phase; the env hatch must override.
        events = list(run_audit("t8d", str(tmp_path), {"use_llm": True}))
        # Completed (exit 0) and LLM never invoked.
        _parse_event(events, "result")
        assert fake.calls == 0, (
            "VULTURE_CWE_DISABLE_LLM must force skills-only (no LLM call) even "
            "when use_llm=True is requested"
        )

    def test_sample_code_default_off_then_env_on(self, tmp_path, usable_model, monkeypatch):
        """T8e (sample-code TDD): run the CWE agent over a small vulnerable
        sample file with the FAKE provider and assert the uniform toggle end to
        end. (a) default (VULTURE_USE_LLM unset, no per-request flag) =>
        skills-only, no LLM-phase findings; (b) VULTURE_USE_LLM=true => the LLM
        phase runs and its net-new finding surfaces."""
        sample = tmp_path / "vuln_sample.py"
        sample.write_text(
            "import hashlib\n"
            "import sqlite3\n"
            "\n"
            "def login(conn, user, password):\n"
            "    # weak hash (CWE-328) — caught by the skill phase\n"
            "    digest = hashlib.md5(password.encode()).hexdigest()\n"
            "    # SQL injection via f-string (CWE-89)\n"
            "    return conn.execute(f\"SELECT * FROM users WHERE name='{user}'\")\n"
        )

        # (a) Default OFF: VULTURE_USE_LLM unset, config has no use_llm.
        monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
        fake_off = FakeLLMProvider(scripted=[
            fake_finding(title="LLM-only dataflow", category="CWE-89",
                         file_path="vuln_sample.py", line_start=8, line_end=8,
                         check_id="cwe.llm.dataflow"),
        ])
        install_fake_runner(monkeypatch, fake_off)

        events_off = list(run_audit("t8e-off", str(tmp_path), {}))
        result_off = _parse_event(events_off, "result")
        assert result_off["findings"], (
            "skills-only must still report the deterministic weak-hash/SQLi findings"
        )
        assert fake_off.calls == 0, (
            "default path (VULTURE_USE_LLM unset) must NOT run the LLM phase; "
            f"fake.calls={fake_off.calls}"
        )
        off_titles = [f["title"] for f in result_off["findings"]]
        assert "LLM-only dataflow" not in off_titles, (
            "no LLM-phase finding may appear on the skills-only default path"
        )
        off_llm_marked = [
            f["title"] for f in result_off["findings"]
            if str(f.get("check_id", "")).startswith("cwe.llm")
            or f.get("provenance") == "llm"
        ]
        assert off_llm_marked == [], (
            f"no llm-provenance findings on the default path; got {off_llm_marked}"
        )

        # (b) Opt-in ON: VULTURE_USE_LLM=true makes the LLM phase run.
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        fake_on = FakeLLMProvider(scripted=[
            fake_finding(title="LLM-only dataflow", category="CWE-89",
                         file_path="vuln_sample.py", line_start=8, line_end=8,
                         check_id="cwe.llm.dataflow"),
        ])
        install_fake_runner(monkeypatch, fake_on)
        patch_l5_judge(monkeypatch, default_exploitable=0.95)

        events_on = list(run_audit("t8e-on", str(tmp_path), {}))
        assert fake_on.calls >= 1, (
            "VULTURE_USE_LLM=true must run the LLM phase over the sample; "
            f"fake.calls={fake_on.calls}"
        )
        on_titles = [f["title"] for f in _result_findings(events_on)]
        assert "LLM-only dataflow" in on_titles, (
            "the LLM-phase finding must surface when VULTURE_USE_LLM=true"
        )


# --------------------------------------------------------------------------- #
# T9 — LLM finds a cross-line gap the skills miss
# --------------------------------------------------------------------------- #


class TestT9LlmFindsCrossLineGap:
    """The LLM phase surfaces a dataflow/cross-line weakness the single-line
    regex skills structurally cannot. The scripted FakeLLM stands in for that
    semantic capability; the contract is that such a net-new finding is added
    to the result (the skills alone do not report it)."""

    def test_dataflow_finding_added_by_llm(self, tmp_path, usable_model, monkeypatch):
        # A taint that spans several lines: source on L2, sink on L5. The
        # line-oriented skills do not connect them; the LLM does.
        (tmp_path / "flow.py").write_text(
            "def handler(request):\n"
            "    user_input = request.args.get('q')\n"   # source
            "    parts = user_input.split(',')\n"
            "    joined = ' '.join(parts)\n"
            "    return run_shell(joined)\n"              # sink (line 5)
        )

        # Baseline: skills-only must NOT already report this cross-line flow.
        monkeypatch.setenv("VULTURE_CWE_DISABLE_LLM", "true")
        baseline = list(run_audit("t9-base", str(tmp_path), {}))
        baseline_titles = {f["title"] for f in _result_findings(baseline)}
        assert "Command injection via tainted dataflow" not in baseline_titles, (
            "precondition: skills-only must not already report the cross-line flow"
        )
        monkeypatch.delenv("VULTURE_CWE_DISABLE_LLM", raising=False)

        fake = FakeLLMProvider(scripted=[
            fake_finding(
                title="Command injection via tainted dataflow",
                category="CWE-78",
                file_path="flow.py",
                line_start=5, line_end=5,
                check_id="cwe.llm.cmdi.dataflow",
                description="request.args flows into run_shell across lines 2->5",
            ),
        ])
        install_fake_runner(monkeypatch, fake)
        # Make the L5 judge confirm the LLM finding so it is not demoted away.
        patch_l5_judge(monkeypatch, default_exploitable=0.95)

        # LLM phase must be explicitly enabled (uniform default is off).
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        events = list(run_audit("t9", str(tmp_path), {}))
        titles = [f["title"] for f in _result_findings(events)]
        assert "Command injection via tainted dataflow" in titles, (
            "the LLM must add the cross-line dataflow finding the skills miss"
        )


# --------------------------------------------------------------------------- #
# T10 — crypto/policy CWEs never auto-suppressed by L5
# --------------------------------------------------------------------------- #


class TestT10CryptoNotAutoSuppressed:
    """The crypto/policy CWE family (326/327/328/330/798/319) must be EXEMPT
    from L5 auto-suppression: even if the judge returns exploitable=0.0, a
    real weak-crypto skill finding must never be classified likely_fp."""

    def test_weak_hash_finding_survives_zero_verdict(self, tmp_path, usable_model, monkeypatch):
        # The crypto skill reports CWE-328 (weak hash, MD5) deterministically.
        # Place it under a fixtures/ path so L1's path classifier adds a
        # demoting check (-0.20). Combined with an L5 exploitable=0.0 verdict
        # (-0.75) that is TWO demoting checks + low confidence — which the
        # voter would classify likely_fp UNLESS the crypto/policy exemption
        # protects it. That is exactly the contract under test.
        # `examples/` is demoted by the L1 path classifier but is NOT skipped
        # by the file scanner (unlike `fixtures/`), so the crypto skill still
        # fires on it and L1 still adds its -0.20 demotion.
        cryptofile = tmp_path / "examples" / "auth.py"
        cryptofile.parent.mkdir(parents=True)
        cryptofile.write_text(
            "import hashlib\n"
            "def hash_password(p):\n"
            "    return hashlib.md5(p.encode()).hexdigest()\n"
        )

        # No net-new LLM findings; the LLM phase still runs (model-gated on).
        fake = FakeLLMProvider(scripted=[])
        install_fake_runner(monkeypatch, fake)
        # The judge tries to demote EVERYTHING to non-exploitable.
        patch_l5_judge(monkeypatch, default_exploitable=0.0)

        # Force the LLM + L5 ON explicitly so the contract does not depend on
        # the default flip — the crypto finding IS judged, and only the
        # crypto/policy exemption (P1b) can save it from likely_fp.
        events = list(run_audit("t10", str(tmp_path),
                                {"use_llm": True, "validate": {"llm": True}}))
        findings = _result_findings(events)

        crypto = [
            f for f in findings
            if f.get("category") in {"CWE-326", "CWE-327", "CWE-328",
                                     "CWE-330", "CWE-798", "CWE-319"}
        ]
        assert crypto, "precondition: the crypto skill must report a weak-crypto CWE"
        for f in crypto:
            assert f.get("validation_status") != "likely_fp", (
                f"crypto/policy CWE {f.get('category')} must be EXEMPT from L5 "
                "auto-suppression (never likely_fp on the judge's verdict alone)"
            )


# --------------------------------------------------------------------------- #
# T11 — clean-code FP gate
# --------------------------------------------------------------------------- #


class TestT11CleanCodeFpGate:
    """On clean source the LLM phase must not invent findings. When the LLM
    returns nothing, the audit surfaces no net-new LLM findings — the enabled
    LLM phase does not flood a clean tree."""

    def test_clean_code_no_llm_findings(self, tmp_path, usable_model, monkeypatch):
        (tmp_path / "clean.py").write_text(
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
            "\n"
            "def greet(name: str) -> str:\n"
            "    return f'hello {name}'\n"
        )

        # A well-behaved LLM finds nothing on clean code.
        fake = FakeLLMProvider(scripted=[])
        install_fake_runner(monkeypatch, fake)

        # Enable the LLM phase explicitly (uniform default is off).
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        events = list(run_audit("t11", str(tmp_path), {}))

        # The LLM phase ran (opt-in via env, model-gated) ...
        assert fake.calls >= 1, (
            "LLM phase should run on the opt-in path "
            f"(fake.calls={fake.calls})"
        )
        # ... but produced zero findings: result carries no LLM-sourced finding.
        findings = _result_findings(events)
        llm_titles = [
            f["title"] for f in findings
            if str(f.get("check_id", "")).startswith("cwe.llm")
            or f.get("provenance") == "llm"
        ]
        assert llm_titles == [], (
            f"the LLM phase must add no findings to clean code; got {llm_titles}"
        )
