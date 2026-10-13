"""Feature 0101 (review round 3) E2E: a model that answers with a JSON array
or object instead of a string must not carry repository content past the
scrub.

The strategies copy model JSON straight into ``ProofPlan.description``,
``ReflectionResult.analysis`` / ``suggested_approach`` and the analyze step's
``ExecutionResult.evidence`` without coercion. Small and local models often
answer ``"analysis": ["...", "..."]``. The scrub skipped every non-string
value, so (measured) the stream carried
``proof_reflection {"analysis": ["handler in src/payments/alpha_gateway.go
reads the secret"]}`` verbatim, and a list-valued proof_result evidence was
also dropped by the backend, whose ``Evidence`` field is a string.

Contract: every free-text field of every proof_* event is a STRING, and it
carries neither the finding's path nor its quoted code line, whatever JSON
shape the model used. Driven through the REAL OwaspStrategy plan/reflect and
the REAL HTTP execute_and_analyze; only the LLM call and the transport are
stubbed. Fixtures are synthetic.
"""

import json
from unittest.mock import patch

import httpx
import pytest

from prove_agent.runner import prove_finding_with_timeout
from prove_agent.strategies.base import ExecutionResult, ReviewResult
from prove_agent.strategies.owasp import OwaspStrategy
from prove_agent.strategies.shared import execute_and_analyze
from shared.transport.event_emitter import AgUiEventEmitter
from tests.e2e.test_0101_proof_evidence_privacy import STAGING, _events

PATH = "src/payments/alpha_gateway.go"
LINE = 'token := os.Getenv("PAYMENT_GATEWAY_SECRET")'
FINDING = {
    "id": "f-alpha-1", "title": "Secret read in handler", "category": "A02",
    "agent_type": "owasp", "file_path": PATH, "line_start": 30,
    "code_snippet": f"29: func charge() {{\n30:     {LINE}\n31: }}\n",
}
LEAKS = (PATH, "alpha_gateway", "payments/", 'os.Getenv("PAYMENT')
TEXT_FIELDS = {
    "proof_plan": ("title", "plan_text"),
    "proof_attempt": ("evidence",),
    "proof_reflection": ("analysis", "suggested_approach"),
    "proof_result": ("evidence",),
}


def _list(*items):
    return list(items)


def _dict(*items):
    return {f"k{i}": item for i, item in enumerate(items)}


def _nested(*items):
    return [{"note": items[0], "more": list(items[1:])}]


SHAPES = {"list": _list, "dict": _dict, "nested": _nested}


def _llm(shape):
    """Plan, reflect and analyze answers, each echoing the path and line in
    the given JSON shape instead of a string."""
    echo = shape(f"handler in {PATH} reads the secret", f"via {LINE}")
    analyses = iter([
        {"conclusive": False, "reproduced": False, "evidence": echo},
        {"conclusive": True, "reproduced": True, "evidence": echo},
    ])

    async def strategy_call(prompt, **kw):
        if kw.get("required_fields"):
            return {"url_path": "/api/charge", "method": "GET", "description": echo}
        return {"analysis": echo, "suggested_approach": echo, "confidence": 40,
                "learnings": []}

    async def analyze_call(prompt, **kw):
        return next(analyses)
    return strategy_call, analyze_call


def _client():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class _Owasp(OwaspStrategy):
    """Real plan/reflect; real HTTP execute_and_analyze on a stub transport."""

    async def review(self, plan, staging_url):
        return ReviewResult(safe=True, concerns=[])

    async def execute(self, plan, staging_url, capabilities=None) -> ExecutionResult:
        return await execute_and_analyze(plan, staging_url, "OWASP", "t", client=_client())


async def _run(shape):
    strategy_call, analyze_call = _llm(shape)
    with patch("prove_agent.strategies.owasp.llm_json_call", side_effect=strategy_call), \
         patch("prove_agent.strategies.shared.llm_json_call", side_effect=analyze_call), \
         patch("prove_agent.runner.stepped_backoff_delay_adaptive", return_value=0):
        raw = [e async for e in prove_finding_with_timeout(
            FINDING, _Owasp(), STAGING, 2, AgUiEventEmitter("run-0101r3"), timeout=10,
        )]
    return _events(raw)


@pytest.mark.parametrize("shape", sorted(SHAPES))
async def test_non_string_model_fields_are_scrubbed_strings(shape):
    events = await _run(SHAPES[shape])
    seen = {name for name, _ in events}
    assert {"proof_plan", "proof_attempt", "proof_reflection", "proof_result"} <= seen
    for name, data in events:
        for field in TEXT_FIELDS.get(name, ()):
            value = data[field]
            assert isinstance(value, str), (name, field, value)
            assert [leak for leak in LEAKS if leak in value] == [], (name, field, value)
    whole = json.dumps([d for _, d in events], ensure_ascii=False)
    assert [leak for leak in LEAKS if leak in whole] == []
    # Non-vacuity: the model's words survive around the placeholders.
    result = [d for n, d in events if n == "proof_result"][-1]
    assert "[source file]" in result["evidence"]
    assert "[source excerpt]" in result["evidence"]
    assert "reads the secret" in result["evidence"]


async def test_review_concerns_given_as_one_string_are_not_split():
    """``concerns`` is iterated item by item; a model-supplied string must be
    scrubbed as one text, not character by character (which defeats every
    marker)."""
    from prove_agent.evidence_scrub import scrubbing
    em = scrubbing(AgUiEventEmitter("r"), FINDING)
    raw = em.proof_review_event("f", True, f"see {PATH}", 1)  # type: ignore[arg-type]
    data = _events([raw])[0][1]
    assert data["concerns"] == ["see [source file]"]
