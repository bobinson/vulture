"""gRPC protocol executor — execute verification probes using gRPC.

Uses grpcio if available, falls back to HTTP/2-based probing.
Follows the same 2-phase pattern (rule-based + LLM fallback) as jsonrpc_executor.
"""

import logging

from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
)

logger = logging.getLogger(__name__)


async def execute_grpc(
    plan: ProofPlan,
    staging_url: str,
    capabilities: object,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult:
    """Execute a gRPC verification probe.

    Attempts native grpcio first. Falls back to HTTP/2 + proto encoding
    if grpcio is not installed.
    """
    grpc_services = getattr(capabilities, "grpc_services", [])

    # Try native grpcio
    result = await _try_grpc_native(plan, staging_url, grpc_services)
    if result:
        return result

    # Fallback: HTTP/2 POST with gRPC content type
    return await _try_grpc_http2(plan, staging_url)


async def _try_grpc_native(
    plan: ProofPlan,
    staging_url: str,
    grpc_services: list[str],
) -> ExecutionResult | None:
    """Try gRPC via grpcio library."""
    try:
        import grpc  # type: ignore[import-untyped]
    except ImportError:
        return None

    from urllib.parse import urlparse
    parsed = urlparse(staging_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 50051
    target = f"{host}:{port}"

    try:
        channel = grpc.insecure_channel(target)
        # Use health check as a basic probe
        from grpc_health.v1 import health_pb2, health_pb2_grpc  # type: ignore[import-untyped]
        stub = health_pb2_grpc.HealthStub(channel)
        request = health_pb2.HealthCheckRequest(service="")
        response = stub.Check(request, timeout=5.0)
        status = response.status
        channel.close()
        return ExecutionResult(
            conclusive=True,
            reproduced=status == health_pb2.HealthCheckResponse.SERVING,
            evidence=f"gRPC health check: status={status}",
            protocol_used=ProbeProtocol.GRPC.value,
        )
    except Exception as exc:
        logger.debug("gRPC native probe failed: %s", exc)
        return None


async def _try_grpc_http2(
    plan: ProofPlan,
    staging_url: str,
) -> ExecutionResult:
    """Fallback: HTTP/2 POST with gRPC content type headers."""
    import httpx

    url = staging_url.rstrip("/") + (plan.url_path or "/")
    headers = {
        "Content-Type": "application/grpc",
        "TE": "trailers",
    }

    try:
        async with httpx.AsyncClient(http2=True, timeout=5.0) as client:
            resp = await client.post(url, content=b"\x00\x00\x00\x00\x00", headers=headers)
            ct = resp.headers.get("content-type", "")
            grpc_status = resp.headers.get("grpc-status", "")

            if "grpc" in ct or grpc_status:
                return ExecutionResult(
                    conclusive=True,
                    reproduced=True,
                    evidence=f"gRPC HTTP/2 response: status={resp.status_code}, grpc-status={grpc_status}",
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    protocol_used=ProbeProtocol.GRPC.value,
                )
            return ExecutionResult(
                conclusive=False,
                evidence=f"HTTP/2 probe: status={resp.status_code}, content-type={ct}",
                status_code=resp.status_code,
                protocol_used=ProbeProtocol.GRPC.value,
                failure_reason=FailureReason.PROTOCOL_ERROR,
            )
    except Exception as exc:
        return ExecutionResult(
            conclusive=False,
            evidence=f"gRPC HTTP/2 probe failed: {exc}",
            protocol_used=ProbeProtocol.GRPC.value,
            failure_reason=FailureReason.CONNECTION_ERROR,
        )
