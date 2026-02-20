"""SSE app factory for agent microservices."""

from collections.abc import Generator
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from shared.models.audit_request import AuditRequest


RunHandler = Callable[[str, str, dict, list[dict[str, Any]]], Generator[str, None, None]]


def create_sse_app(
    agent_name: str,
    agent_info: dict[str, Any],
    run_handler: RunHandler,
) -> FastAPI:
    """Create a FastAPI app with /run, /health, and /info endpoints.

    Args:
        agent_name: Short agent identifier (e.g. 'chaos').
        agent_info: Info dict returned by GET /info.
        run_handler: Generator function(run_id, source_path, config, prior_findings)
                     yielding SSE strings.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(title=f"Vulture {agent_name} Agent")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "healthy", "agent": agent_name}

    @app.get("/info")
    def info() -> dict[str, Any]:
        return agent_info

    @app.post("/run")
    def run(request: AuditRequest) -> StreamingResponse:
        return StreamingResponse(
            run_handler(
                request.run_id,
                request.source_path,
                request.config,
                request.prior_findings,
            ),
            media_type="text/event-stream",
        )

    return app
