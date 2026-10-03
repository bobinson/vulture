"""E2E: the OWASP agent answers in mapping mode ONLY when asked (feature 0096).

The backend advertises that it can consume a mapping result by sending
``accepts_mapping: 1`` as a TOP-LEVEL field of the /run body (a sibling of
``run_id``/``config``/``prior_findings``, H1), which the transport hands to
``run_audit`` as the ``accepts_mapping`` keyword. Then, and only then, the
agent answers with its edition's CWE->category table and emits no findings of
its own; the backend labels the CWE findings with it.

``config["accepts_mapping"]`` is IGNORED entirely: a pre-0096 backend forwards
arbitrary user config keys to agents, so a capability read from config could
be claimed by a user on a backend that would then mass-close OWASP lineage.

Every other request — the field absent, ``0``, or anything that is not the
integer ``1`` — gets the legacy (feature 0063) answer: one OWASP copy row per
mapped CWE finding. A backend that predates 0096 never sends the key, and it
would read a zero-finding OWASP result as "every OWASP issue was fixed" and
close its lineage, so the legacy answer must stay exactly what it was. It is
pinned byte for byte against ``tests/fixtures/owasp_0096_legacy_stream.json``,
captured from the agent BEFORE the mapping path existed.
"""

import json
import pathlib

import pytest
from httpx import ASGITransport, AsyncClient

from owasp_agent.agent import run_audit

_GOLDEN = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "fixtures"
     / "owasp_0096_legacy_stream.json").read_text("utf-8")
)
_CASES = sorted(_GOLDEN["cases"])


def _events(chunks):
    out = []
    for chunk in chunks:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _case(name):
    case = _GOLDEN["cases"][name]
    priors = _GOLDEN["priors"] if case["use_priors"] else []
    return dict(case["config"]), json.loads(json.dumps(priors)), case["stream"]


def _run(name, config, priors, accepts_mapping=None):
    return list(run_audit(f"golden-{name}", "/unused", config, prior_findings=priors,
                          accepts_mapping=accepts_mapping))


# --- legacy mode: unchanged, byte for byte ---------------------------------


@pytest.mark.parametrize("name", _CASES)
def test_absent_capability_answers_legacy_byte_for_byte(name):
    config, priors, golden = _case(name)
    assert _run(name, config, priors) == golden


# Anything but the integer 1 is "not asked". `True == 1` and `1.0 == 1` in
# Python, so a boolean and a float must be refused explicitly; a string and a
# future version this agent does not speak are refused by the same rule.
_NOT_V1 = [0, None, False, True, 1.0, "1", 2, -1, [1], {"v": 1}]


@pytest.mark.parametrize("value", _NOT_V1)
@pytest.mark.parametrize("name", _CASES)
def test_non_v1_capability_answers_legacy_byte_for_byte(name, value):
    config, priors, golden = _case(name)
    assert _run(name, config, priors, accepts_mapping=value) == golden, (
        f"accepts_mapping={value!r} must get the unchanged legacy answer"
    )


# H1: the capability in CONFIG is not the capability. Without the out-of-band
# value the answer is legacy, byte for byte, whatever config says.
@pytest.mark.parametrize("value", [1, True, 2, "1"])
@pytest.mark.parametrize("name", _CASES)
def test_config_capability_is_ignored(name, value):
    config, priors, golden = _case(name)
    config["accepts_mapping"] = value
    assert _run(name, config, priors) == golden, (
        f"config accepts_mapping={value!r} must not change the answer"
    )


def test_config_cannot_suppress_the_out_of_band_capability():
    config, priors, _ = _case("edition_2025")
    config["accepts_mapping"] = 0
    events = _events(_run("edition_2025", config, priors, accepts_mapping=1))
    result = next(d for t, d in events if t == "result")
    assert "finding" not in [t for t, _ in events]
    assert isinstance(result.get("mapping"), dict)


def test_legacy_answer_still_carries_copies():
    """Guards the golden itself: the legacy answer is the copy-row shape."""
    config, priors, _ = _case("edition_2025")
    events = _events(_run("edition_2025", config, priors))
    result = next(d for t, d in events if t == "result")
    assert [d for t, d in events if t == "finding"], "legacy mode emits finding events"
    assert result["findings"], "legacy result carries the copies"
    assert "mapping" not in result, "legacy result must not carry a mapping object"


# --- mapping mode -----------------------------------------------------------


@pytest.mark.parametrize("name", _CASES)
def test_v1_capability_answers_with_mapping_and_no_findings(name):
    config, priors, _ = _case(name)
    events = _events(_run(name, config, priors, accepts_mapping=1))
    types = [t for t, _ in events]

    assert types[0] == "agent_start" and types[-1] == "agent_end"
    assert "finding" not in types, "mapping mode emits ZERO finding events (0096 I1)"
    result = next(d for t, d in events if t == "result")
    assert result["findings"] == []
    assert result["findings_count"] == 0
    assert isinstance(result.get("mapping"), dict), "the mapping OBJECT is the mode marker"
    assert result["mapping"]["version"] == 1
    assert "owasp_coverage" in result and "score" in result and "summary" in result
    assert next(d for t, d in events if t == "agent_end")["status"] == "completed"


def test_v1_capability_emits_no_progress_findings():
    config, priors, _ = _case("edition_2025")
    events = _events(_run("edition_2025", config, priors, accepts_mapping=1))
    progress = next(d for t, d in events if t == "progress")
    assert progress["findings_count"] == 0


@pytest.fixture
def owasp_app():
    from owasp_agent.main import app

    return app


_ABSENT = object()


async def _post_run(app, config, priors, accepts_mapping=_ABSENT):
    # The transport admits only objects as priors; the golden's deliberate
    # non-dict entry is for the in-process runs above.
    priors = [p for p in priors if isinstance(p, dict)]
    body = {"run_id": "e2e-0096", "source_path": "/tmp/x",
            "config": config, "prior_findings": priors}
    if accepts_mapping is not _ABSENT:
        body["accepts_mapping"] = accepts_mapping  # top level, out of band
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=body)
    assert resp.status_code == 200
    blocks = [b for b in resp.text.split("\n\n") if b.strip()]
    return _events(b + "\n\n" for b in blocks)


@pytest.mark.anyio
async def test_run_endpoint_negotiates_mapping(owasp_app):
    """Through the real /run transport: the top-level capability reaches run_audit."""
    _, priors, _ = _case("edition_2025")
    events = await _post_run(owasp_app, {"edition": "2025", "cwe_stage_status": "completed"},
                             priors, accepts_mapping=1)
    types = [t for t, _ in events]
    result = next(d for t, d in events if t == "result")
    assert "finding" not in types
    assert result["findings"] == [] and result["mapping"]["edition"] == "2025"


@pytest.mark.anyio
async def test_run_endpoint_without_capability_stays_legacy(owasp_app):
    _, priors, _ = _case("edition_2025")
    events = await _post_run(owasp_app, {"edition": "2025"}, priors)
    result = next(d for t, d in events if t == "result")
    assert [d for t, d in events if t == "finding"]
    assert result["findings"] and "mapping" not in result


@pytest.mark.anyio
async def test_run_endpoint_ignores_config_capability(owasp_app):
    """H1 through the real /run transport: config {"accepts_mapping": 1} with
    no top-level field is the legacy answer."""
    _, priors, _ = _case("edition_2025")
    events = await _post_run(owasp_app, {"edition": "2025", "accepts_mapping": 1,
                                         "cwe_stage_status": "completed"}, priors)
    result = next(d for t, d in events if t == "result")
    assert [d for t, d in events if t == "finding"]
    assert result["findings"] and "mapping" not in result


@pytest.mark.anyio
@pytest.mark.parametrize("value", [True, 1.0, "1", 2, 0, None])
async def test_run_endpoint_non_v1_top_level_stays_legacy(owasp_app, value):
    """The transport must not coerce ``true``/``1.0``/``"1"`` into ``1``."""
    _, priors, _ = _case("edition_2025")
    events = await _post_run(owasp_app, {"edition": "2025"}, priors, accepts_mapping=value)
    result = next(d for t, d in events if t == "result")
    assert [d for t, d in events if t == "finding"]
    assert result["findings"] and "mapping" not in result
