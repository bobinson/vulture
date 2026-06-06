"""Unit tests for src/wrapper.py (FastAPI app).

RED phase (feature 0053). All tests use FastAPI's TestClient with
subprocess.run mocked — no real Semgrep process ever starts.
"""

import json
import subprocess
import time
from unittest.mock import patch

import httpx
import pytest

# RED-phase import — fails until src/wrapper.py exists.
from src.wrapper import app  # noqa: E402

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixture: canned Semgrep JSON output (subset of the real fixture, enough
# to drive the SSE event sequence assertions).
# ---------------------------------------------------------------------------

CANNED_SEMGREP_OUTPUT = {
    "version": "1.84.0",
    "results": [
        {
            "check_id": "python.django.security.injection.sql.sql-injection-using-raw",
            "path": "/audit-inputs/app/views.py",
            "start": {"line": 42, "col": 5, "offset": 0},
            "end": {"line": 44, "col": 30, "offset": 0},
            "extra": {
                "message": "SQL injection via string concatenation.",
                "severity": "ERROR",
                "lines": "cursor.execute(...)",
                "metadata": {
                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                },
            },
        },
        {
            "check_id": "javascript.express.security.audit.xss",
            "path": "/audit-inputs/src/x.js",
            "start": {"line": 7, "col": 1, "offset": 0},
            "end": {"line": 7, "col": 20, "offset": 0},
            "extra": {
                "message": "XSS via res.send.",
                "severity": "WARNING",
                "lines": "res.send(req.query.name)",
                "metadata": {
                    "cwe": ["CWE-79: Cross-site Scripting"],
                },
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": [], "skipped": []},
}


def _make_completed_process(returncode=0, stdout=None, stderr=""):
    """Build a subprocess.CompletedProcess stand-in for mocking."""
    return subprocess.CompletedProcess(
        args=["semgrep"],
        returncode=returncode,
        stdout=json.dumps(stdout) if stdout is not None else json.dumps(CANNED_SEMGREP_OUTPUT),
        stderr=stderr,
    )


def _envelope_body(source_path="/audit-inputs/src-1", run_id="run-test-1"):
    return {
        "envelope": "vulture-plugin/1.0",
        "run_id": run_id,
        "stage": "scan",
        "input": {"source_path": source_path},
        "config": {},
    }


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def patched_realpath(tmp_path, monkeypatch):
    """The wrapper insists source_path is under /audit-inputs. In CI we
    don't have that directory. Patch normalise_source_path to accept
    any string that starts with "/audit-inputs" (matching the production
    semantics on a real container)."""
    # Set up a fake root so realpath checks pass for any "/audit-inputs/*"
    # input. We patch the module-level constant referenced by /run.
    fake_root = tmp_path / "audit-inputs"
    fake_root.mkdir()
    (fake_root / "src-1").mkdir()
    monkeypatch.setattr("src.wrapper.AUDIT_INPUTS_ROOT", str(fake_root))
    return fake_root


# ---------------------------------------------------------------------------
# /health and /info
# ---------------------------------------------------------------------------


def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_info_returns_capabilities(client):
    resp = client.get("/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "semgrep"
    # At least one capability of phase=scan, per the manifest.
    caps = body.get("capabilities", [])
    assert any(c.get("phase") == "scan" for c in caps)


# ---------------------------------------------------------------------------
# Envelope validation (MAJOR #11)
# ---------------------------------------------------------------------------


def test_run_rejects_bad_envelope_BLOCKER11(client):
    # Missing envelope field entirely.
    resp = client.post("/run", json={"run_id": "r1", "input": {"source_path": "/audit-inputs"}})
    assert resp.status_code in (400, 422), f"got {resp.status_code}: {resp.text}"


def test_run_rejects_wrong_envelope_BLOCKER11(client):
    body = _envelope_body()
    body["envelope"] = "wrong/2.0"
    resp = client.post("/run", json=body)
    assert resp.status_code == 400, f"got {resp.status_code}: {resp.text}"


def test_run_rejects_missing_source_path(client, patched_realpath):
    body = _envelope_body()
    body["input"] = {}  # no source_path
    resp = client.post("/run", json=body)
    assert resp.status_code == 400


def test_run_rejects_invalid_source_path(client, patched_realpath):
    body = _envelope_body(source_path="-foo")
    resp = client.post("/run", json=body)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Happy-path SSE event sequence (AC #4)
# ---------------------------------------------------------------------------


def _collect_sse_events(resp):
    """Parse an SSE response body into a list of (event_name, json_data)."""
    events = []
    current_event = None
    for raw_line in resp.text.splitlines():
        if raw_line.startswith("event:"):
            current_event = raw_line.split(":", 1)[1].strip()
        elif raw_line.startswith("data:"):
            data_str = raw_line.split(":", 1)[1].strip()
            try:
                parsed = json.loads(data_str)
            except (json.JSONDecodeError, ValueError):
                parsed = data_str
            events.append((current_event, parsed))
        elif raw_line == "":
            current_event = None
    return events


def test_run_happy_path_emits_event_sequence(client, patched_realpath):
    body = _envelope_body(source_path=str(patched_realpath / "src-1"))

    with patch("src.wrapper.subprocess.run", return_value=_make_completed_process(returncode=1)):
        resp = client.post("/run", json=body)

    assert resp.status_code == 200
    events = _collect_sse_events(resp)
    names = [e[0] for e in events]

    # Expected sequence: run_started, agent_start, finding (x2), result, agent_end, run_finished.
    assert names[0] == "run_started"
    assert names[1] == "agent_start"
    finding_count = sum(1 for n in names if n == "finding")
    assert finding_count == 2
    # The three terminal events arrive in this order at the end.
    assert names[-3:] == ["result", "agent_end", "run_finished"]


# ---------------------------------------------------------------------------
# Exit-code handling
# ---------------------------------------------------------------------------


def test_run_exit_code_7_clear_message_MINOR16(client, patched_realpath):
    """MINOR #16: Semgrep exit 7 means auth required. The wrapper must
    surface a clear operator-facing message naming SEMGREP_APP_TOKEN
    rather than the raw cryptic stderr."""
    body = _envelope_body(source_path=str(patched_realpath / "src-1"))

    with patch(
        "src.wrapper.subprocess.run",
        return_value=_make_completed_process(returncode=7, stdout={}, stderr="some cryptic semgrep auth error"),
    ):
        resp = client.post("/run", json=body)

    assert resp.status_code == 200
    events = _collect_sse_events(resp)
    # Find the result event.
    result_events = [e for e in events if e[0] == "result"]
    assert result_events, f"no result event in {[e[0] for e in events]}"
    payload = result_events[0][1]
    blob = json.dumps(payload) if isinstance(payload, dict) else str(payload)
    assert "SEMGREP_APP_TOKEN" in blob


def test_run_exit_code_2_includes_stderr(client, patched_realpath):
    body = _envelope_body(source_path=str(patched_realpath / "src-1"))
    with patch(
        "src.wrapper.subprocess.run",
        return_value=_make_completed_process(returncode=2, stdout={}, stderr="oops something blew up"),
    ):
        resp = client.post("/run", json=body)

    assert resp.status_code == 200
    events = _collect_sse_events(resp)
    result_events = [e for e in events if e[0] == "result"]
    assert result_events
    payload = result_events[0][1]
    blob = json.dumps(payload) if isinstance(payload, dict) else str(payload)
    assert "oops" in blob


def test_run_subprocess_timeout(client, patched_realpath):
    body = _envelope_body(source_path=str(patched_realpath / "src-1"))

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1500)

    with patch("src.wrapper.subprocess.run", side_effect=_raise_timeout):
        resp = client.post("/run", json=body)

    assert resp.status_code == 200
    events = _collect_sse_events(resp)
    names = [e[0] for e in events]
    # Expected tail: result (with timeout error), agent_end, run_finished.
    assert names[-3:] == ["result", "agent_end", "run_finished"]
    result_payload = next(e[1] for e in events if e[0] == "result")
    blob = json.dumps(result_payload) if isinstance(result_payload, dict) else str(result_payload)
    assert "timeout" in blob.lower()


# ---------------------------------------------------------------------------
# BLOCKER #2 — the asyncio loop must NOT be blocked while Semgrep runs.
# ---------------------------------------------------------------------------


def test_wrapper_uses_run_in_executor_BLOCKER2(patched_realpath):
    """If the wrapper called subprocess.run() inline (no executor), the
    asyncio loop would block for the duration of the call. A concurrent
    GET /health would have to wait for /run to finish.

    To prove the implementation uses loop.run_in_executor, we mock
    subprocess.run to sleep for ~0.5s, fire /run in a background thread,
    and assert that /health completes in well under 0.5s.

    With run_in_executor the slow subprocess.run runs in the threadpool;
    the event loop stays free; /health finishes in milliseconds. Without
    it, /health waits for /run.
    """
    SLEEP_DURATION = 0.5
    HEALTH_BUDGET = 0.3  # comfortably less than SLEEP_DURATION

    def slow_run(*args, **kwargs):
        time.sleep(SLEEP_DURATION)
        return _make_completed_process(returncode=0, stdout={"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}})

    # Use httpx.AsyncClient for true concurrency. The TestClient is sync
    # and would serialise requests at the transport layer, defeating the
    # measurement. We need an ASGI transport that drives the app via
    # the real asyncio loop.
    import asyncio

    async def _drive():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            body = _envelope_body(source_path=str(patched_realpath / "src-1"))

            with patch("src.wrapper.subprocess.run", side_effect=slow_run):
                # Fire /run; do NOT await yet.
                run_task = asyncio.create_task(ac.post("/run", json=body))

                # Give the run task a chance to enter subprocess.run.
                await asyncio.sleep(0.05)

                # Time a concurrent /health call.
                health_start = time.monotonic()
                health_resp = await ac.get("/health")
                health_elapsed = time.monotonic() - health_start

                # Drain /run so the test cleans up.
                await run_task

            assert health_resp.status_code == 200
            assert health_elapsed < HEALTH_BUDGET, (
                f"/health took {health_elapsed:.3f}s while /run was sleeping {SLEEP_DURATION}s; "
                f"the asyncio loop is being blocked — wrapper must use loop.run_in_executor "
                f"(BLOCKER #2)."
            )

    asyncio.run(_drive())
