"""SSE app factory for agent microservices."""

import asyncio
import contextvars
import logging
import os
from collections.abc import AsyncGenerator, Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.responses import StreamingResponse

from shared.cancellation import CancelToken, set_cancel_token
from shared.models.audit_request import AuditRequest


RunHandler = Callable[[str, str, dict, list[dict[str, Any]]], Generator[str, None, None]]

_AGENT_TOKEN = os.environ.get("VULTURE_AGENT_TOKEN", "")

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """Positive int from env; unset/blank/invalid/≤0 ⇒ *default* (feature 0061)."""
    raw = os.environ.get(name, "").strip()
    try:
        val = int(raw)
        return val if val > 0 else default
    except (TypeError, ValueError):
        return default


# Dedicated pool for driving audit generators (feature 0061 F4). A Phase-2
# sweep holds one thread for minutes; keeping that off the default asyncio
# executor prevents it from starving health checks / other to-thread work.
# The (N+1)th concurrent audit queues here rather than exhausting shared threads.
_AUDIT_POOL = ThreadPoolExecutor(
    max_workers=_int_env("VULTURE_AUDIT_EXECUTOR_WORKERS", 8),
    thread_name_prefix="vulture-audit",
)


async def _cancellable_stream(
    run_handler: RunHandler, req: AuditRequest,
) -> AsyncGenerator[str, None]:
    """Drive the synchronous audit generator in one dedicated worker thread,
    streaming SSE chunks to the async consumer, and cancel the audit on
    client disconnect (feature 0061).

    On disconnect Starlette cancels this async generator, raising
    ``CancelledError`` at the ``await`` — the ``finally`` then flips the
    ``CancelToken`` that the audit's batch loops poll, so the worker thread
    stops issuing new LLM calls within one bounded operation.
    """
    cancel = CancelToken()
    ctx = contextvars.copy_context()
    ctx.run(set_cancel_token, cancel)                 # token bound into ctx
    loop = asyncio.get_running_loop()
    # UNBOUNDED by design (feature 0061 §3.2 R-3): a bounded queue would block
    # the producer on `put` once a disconnected consumer stops draining,
    # preventing it from ever reaching its cancel checkpoint — the very hang we
    # are eliminating. Event volume is naturally bounded by finding/progress count.
    q: "asyncio.Queue[Any]" = asyncio.Queue()
    _DONE = object()

    def _produce() -> None:
        try:
            for chunk in run_handler(
                req.run_id, req.source_path, req.config, req.prior_findings,
            ):
                loop.call_soon_threadsafe(q.put_nowait, chunk)
        except BaseException as exc:  # noqa: BLE001 — surface to consumer (F8), never swallow
            loop.call_soon_threadsafe(q.put_nowait, exc)
        finally:
            loop.call_soon_threadsafe(q.put_nowait, _DONE)

    loop.run_in_executor(_AUDIT_POOL, ctx.run, _produce)
    try:
        while True:
            item = await q.get()
            if item is _DONE:
                break
            if isinstance(item, BaseException):
                raise item
            yield item
    finally:
        # Consumer gone (disconnect → CancelledError here) or normal completion.
        # Signal the worker thread to stop; it unwinds at its next checkpoint.
        cancel.cancel("stream_closed")


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
    async def health() -> dict[str, Any]:
        """Process liveness + LLM reachability sub-status.

        The 'llm' sub-object is the canonical LLMHealthStatus.as_dict();
        the backend /api/llm/health aggregator reads it verbatim from any
        one agent. Backwards-compatible — `status` and `agent` keys are
        preserved.
        """
        # Lazy-import so this module stays usable in environments without
        # the new shared.llm.health module (e.g. older agent images mid-rollout).
        try:
            from shared.llm.health import check_llm_health
            llm_status = await check_llm_health(timeout=2.0)
            return {
                "status": "healthy",
                "agent": agent_name,
                "llm": llm_status.as_dict(),
                "llm_message": llm_status.message(),
            }
        except Exception:
            return {"status": "healthy", "agent": agent_name}

    @app.get("/info")
    def info() -> dict[str, Any]:
        return agent_info

    @app.post("/run")
    async def run(
        request: AuditRequest,
        _token: None = Depends(_verify_agent_token),
    ) -> StreamingResponse:
        # feature 0061: drive the (synchronous) run_handler through a
        # cancellable wrapper so a client disconnect stops the audit.
        return StreamingResponse(
            _cancellable_stream(run_handler, request),
            media_type="text/event-stream",
        )

    return app
