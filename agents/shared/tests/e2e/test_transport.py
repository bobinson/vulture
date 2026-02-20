"""E2E tests for shared transport (SSE app factory, event emitter)."""

import json

import pytest
from httpx import ASGITransport, AsyncClient

from shared.transport.sse_app import create_sse_app
from shared.transport.event_emitter import AgUiEventEmitter


def _dummy_run_handler(run_id: str, source_path: str, config: dict, prior_findings=None):
    """Dummy run handler that yields SSE events."""
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()
    yield emitter.text_message("Analyzing...")
    yield emitter.finding_event(
        severity="high",
        category="test",
        title="Test finding",
        description="A test finding",
        file_path="main.py",
        line_start=1,
        line_end=5,
        recommendation="Fix it",
    )
    yield emitter.progress_event(files_analyzed=1, total_files=10, findings_count=1)
    yield emitter.result_event(findings=[], summary="Done", score=85.0)
    yield emitter.run_finished()


AGENT_INFO = {
    "name": "Test Agent",
    "type": "test",
    "description": "A test agent",
    "config_schema": {"type": "object", "properties": {}},
    "skills": ["test_skill"],
}


@pytest.fixture
def test_app():
    """Create a test SSE app."""
    return create_sse_app(
        agent_name="test",
        agent_info=AGENT_INFO,
        run_handler=_dummy_run_handler,
    )


class TestSseApp:
    """Tests for the SSE app factory."""

    @pytest.mark.anyio
    async def test_health_endpoint(self, test_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "test"

    @pytest.mark.anyio
    async def test_info_endpoint(self, test_app) -> None:
        """GET /info returns agent info with config_schema."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Test Agent"
        assert "config_schema" in body
        assert "skills" in body

    @pytest.mark.anyio
    async def test_run_endpoint_returns_sse(self, test_app) -> None:
        """POST /run returns SSE event stream."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-123",
                    "source_path": "/tmp/test",
                    "config": {},
                },
            )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body

    @pytest.mark.anyio
    async def test_run_endpoint_validates_request(self, test_app) -> None:
        """POST /run with invalid body returns 422."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.post("/run", json={"invalid": "body"})
        assert resp.status_code == 422


class TestEventEmitter:
    """Tests for AgUiEventEmitter."""

    def test_run_started_event(self) -> None:
        """run_started emits agent_start event."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.run_started()
        assert "event: agent_start" in event
        data = json.loads(event.split("data: ")[1])
        assert data["run_id"] == "run-1"

    def test_text_message_event(self) -> None:
        """text_message emits thinking event."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.text_message("Analyzing code...")
        assert "event: thinking" in event
        data = json.loads(event.split("data: ")[1])
        assert data["content"] == "Analyzing code..."

    def test_finding_event(self) -> None:
        """finding_event emits finding with all fields."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.finding_event(
            severity="high",
            category="security",
            title="SQL Injection",
            description="Found SQL injection",
            file_path="app.py",
            line_start=10,
            line_end=15,
            recommendation="Use parameterized queries",
        )
        assert "event: finding" in event
        data = json.loads(event.split("data: ")[1])
        assert data["severity"] == "high"
        assert data["title"] == "SQL Injection"

    def test_progress_event(self) -> None:
        """progress_event emits progress data."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.progress_event(
            files_analyzed=5, total_files=10, findings_count=2
        )
        assert "event: progress" in event
        data = json.loads(event.split("data: ")[1])
        assert data["files_analyzed"] == 5
        assert data["total_files"] == 10

    def test_result_event(self) -> None:
        """result_event emits final result."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.result_event(findings=[], summary="All clear", score=100.0)
        assert "event: result" in event
        data = json.loads(event.split("data: ")[1])
        assert data["score"] == 100.0

    def test_run_finished_event(self) -> None:
        """run_finished emits agent_end."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.run_finished()
        assert "event: agent_end" in event

    def test_tool_call_event(self) -> None:
        """tool_call emits tool_call event."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.tool_call("list_files", {"path": "/tmp"})
        assert "event: tool_call" in event
        data = json.loads(event.split("data: ")[1])
        assert data["tool"] == "list_files"

    def test_step_started_event(self) -> None:
        """step_started emits tool_result-like event."""
        emitter = AgUiEventEmitter("run-1")
        event = emitter.step_started("Scanning files")
        assert "event:" in event
