"""Feature 0101 (review round 2) E2E: two more paths that leaked repository
content into the persisted proof evidence and the prove stream.

1. Timeout synthesis CUT the last attempt's evidence at 200 characters and
   only then handed it to the scrubbing emitter. A path or code line crossing
   the cut no longer matched any marker, so a fragment of it was persisted
   (measured: ``... see src/payments/alpha_g Status codes seen: [200]``).

2. Cross-finding learnings are one list shared by every finding in the run,
   and every later plan prompt includes it. A learning the model wrote about
   finding A (after being shown A's path and code) therefore reaches finding
   B's plan, reflection and verdict. B's events must not carry A's content
   either: every emitter in the run scrubs every finding's markers.

Fixtures are synthetic; no network is touched.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.runner import prove_finding_with_timeout
from prove_agent.strategies.base import (
    ExecutionResult,
    ProbeProtocol,
    ProofPlan,
    ReflectionResult,
    ReviewResult,
)
from shared.transport.event_emitter import AgUiEventEmitter
from tests.e2e.test_0101_proof_evidence_privacy import (
    FINDING,
    SNIPPET_LINE,
    SOURCE_ROOT,
    STAGING,
    _events,
)

# --- 1. Timeout evidence: scrub BEFORE the 200-character cut ---

_PATH_ACROSS_CUT = ("z" * 190) + " see src/billing/ledger.py line 42"
_LINE_ACROSS_CUT = ("z" * 185) + f" `{SNIPPET_LINE}` is reached"


class _SlowAfterAttempt:
    """One inconclusive attempt, then a reflection that outlives the timeout."""

    def __init__(self, evidence: str):
        self.evidence = evidence

    async def plan(self, finding, staging_url, iteration, **_kw):
        return ProofPlan(description="probe", method="GET", url_path="/api/orders",
                         protocol=ProbeProtocol.HTTP)

    async def review(self, plan, staging_url):
        return ReviewResult(safe=True, concerns=[])

    async def execute(self, plan, staging_url, capabilities=None):
        return ExecutionResult(conclusive=False, evidence=self.evidence,
                               status_code=200, protocol_used="http")

    async def reflect(self, finding, attempts):
        await asyncio.sleep(5)


@pytest.mark.parametrize(("evidence", "fragments"), [
    (_PATH_ACROSS_CUT, ("src/b", "src/billing", "ledger")),
    (_LINE_ACROSS_CUT, ("raise Led", "raise LedgerErr", "LedgerError")),
])
async def test_timeout_evidence_is_scrubbed_before_truncation(evidence, fragments):
    with patch("prove_agent.runner.stepped_backoff_delay_adaptive", return_value=0):
        raw = [e async for e in prove_finding_with_timeout(
            FINDING, _SlowAfterAttempt(evidence), STAGING, 3,
            AgUiEventEmitter("run-0101r2"), timeout=0.3,
        )]
    results = [d for n, d in _events(raw) if n == "proof_result"]
    final = results[-1]["evidence"]
    assert final.startswith("Timed out after")
    assert "Evidence: zzz" in final  # the attempt evidence is still reported
    assert [f for f in fragments if f in final] == []
    assert "[source" in final  # replaced, not silently dropped


# --- 2. Cross-finding learnings: B's events never carry A's content ---

A_PATH = "src/payments/alpha_gateway.go"
A_LINE = 'token := os.Getenv("PAYMENT_GATEWAY_SECRET")'
A_LEAKS = (A_PATH, "alpha_gateway", A_LINE, "PAYMENT_GATEWAY_SECRET")
FINDING_A = {
    "id": "f-a", "title": "Hardcoded gateway secret", "category": "CWE-798",
    "agent_type": "cwe", "file_path": A_PATH, "line_start": 10,
    "code_snippet": f"10: {A_LINE}\n",
}
FINDING_B = {
    "id": "f-b", "title": "Profile page exposure", "category": "CWE-209",
    "agent_type": "cwe", "file_path": "web/views/profile_page.rb", "line_start": 3,
    "code_snippet": "",
}
# Batches are 3 wide: A and two fillers run first, B runs in the second batch
# and therefore plans with A's learning in the shared list.
_FILLERS = [dict(FINDING_B, id=f"f-fill-{i}", file_path=f"lib/fill_{i}.rb") for i in range(2)]


class _LearningStrategy:
    """A reflects (confidence 95) with a learning that names A's path and
    line; every later plan quotes the shared learnings, as a model does."""

    async def plan(self, finding, staging_url, iteration, *, cross_learnings=None, **_kw):
        prior = " | ".join(cross_learnings or [])
        return ProofPlan(description=f"Per prior learning: {prior}", method="GET",
                         url_path="/api/profile", protocol=ProbeProtocol.HTTP)

    async def review(self, plan, staging_url):
        return ReviewResult(safe=True, concerns=[])

    async def execute(self, plan, staging_url, capabilities=None):
        conclusive = "alpha" not in plan.description and not plan.description.endswith(": ")
        return ExecutionResult(conclusive=conclusive, reproduced=False,
                               evidence="probe answered 200", status_code=200,
                               protocol_used="http")

    async def reflect(self, finding, attempts):
        learning = f"{finding['file_path']} reads the secret via `{A_LINE}`"
        return ReflectionResult(analysis=f"Echoing: {learning}",
                                suggested_approach="retry", confidence=95,
                                learnings=[learning])


def _run_prove_iterating(findings: list[dict]) -> list[str]:
    """run_prove with 3 iterations: reflection (and so a learning) only
    happens on a non-final iteration."""
    from prove_agent.agent import run_prove

    patches = {
        "prove_agent.agent.validate_staging_url": MagicMock(return_value=None),
        "shared.llm.provider.get_model": MagicMock(return_value="test-model"),
        "prove_agent.agent.detect_capabilities": AsyncMock(
            return_value=(TargetCapabilities(http=True), "HTTP ok")),
        "prove_agent.agent.load_cached_discovery": MagicMock(return_value=None),
        "prove_agent.agent.call_discover": MagicMock(return_value=(None, "", [])),
        "prove_agent.agent.probe_api_endpoints": AsyncMock(return_value=[]),
        "prove_agent.agent._get_findings": MagicMock(return_value=findings),
        "prove_agent.runner.stepped_backoff_delay_adaptive": MagicMock(return_value=0),
    }
    started = [patch(target, new=value) for target, value in patches.items()]
    for p in started:
        p.start()
    try:
        return list(run_prove(
            run_id="run-0101r2", source_path=SOURCE_ROOT,
            config={"staging_url": STAGING, "types": ["cwe"], "max_iterations": 3},
        ))
    finally:
        for p in started:
            p.stop()


def test_cross_finding_learning_is_scrubbed_in_another_findings_events(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    strategy = _LearningStrategy()
    findings = [FINDING_A, *_FILLERS, FINDING_B]
    with patch("prove_agent.agent.STRATEGY_MAP", {"cwe": lambda: strategy}):
        raw = _run_prove_iterating(findings)
    b_events = [d for _n, d in _events(raw) if d.get("finding_id") == "f-b"]
    b_plans = [d["plan_text"] for d in b_events if "plan_text" in d]
    # Not vacuous: B's plan really did quote the shared learning.
    assert any("Per prior learning: [source" in p for p in b_plans), b_plans
    b_text = "\n".join(str(d) for d in b_events)
    assert [leak for leak in A_LEAKS if leak in b_text] == []
    # And nothing anywhere in the run carries A's content.
    assert [leak for leak in A_LEAKS if leak in "\n".join(raw)] == []
