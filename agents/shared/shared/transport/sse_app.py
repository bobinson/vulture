"""SSE app factory for agent microservices."""

import os
from collections.abc import Generator
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.responses import StreamingResponse

from shared.models.audit_request import AuditRequest


RunHandler = Callable[[str, str, dict, list[dict[str, Any]]], Generator[str, None, None]]

_AGENT_TOKEN = os.environ.get("VULTURE_AGENT_TOKEN", "")


def _verify_agent_token(
    x_vulture_agent_token: str | None = Header(None),
) -> None:
    """Verify the shared agent token on /run requests.

    When VULTURE_AGENT_TOKEN is set, requests without a matching
    X-Vulture-Agent-Token header are rejected. When unset (local dev),
    all requests are allowed.
    """
    if _AGENT_TOKEN and x_vulture_agent_token != _AGENT_TOKEN:
        raise HTTPException(status_code=403, detail="invalid or missing agent token")


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
    def run(
        request: AuditRequest,
        _token: None = Depends(_verify_agent_token),
    ) -> StreamingResponse:
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
