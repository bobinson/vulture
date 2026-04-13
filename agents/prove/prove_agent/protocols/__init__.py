"""Multi-protocol support for prove agent verification probes.

Provides WebSocket and JSON-RPC protocol executors alongside existing HTTP,
with automatic target capability detection and fallback routing.
"""

from prove_agent.protocols.detection import (
    TargetCapabilities,
    detect_capabilities,
    is_ws_rpc_target,
    to_ws_url,
)
from prove_agent.protocols.dispatcher import execute_plan
from prove_agent.protocols.fallback import execute_with_fallback
from prove_agent.strategies.base import ProbeProtocol

__all__ = [
    "ProbeProtocol",
    "TargetCapabilities",
    "detect_capabilities",
    "execute_plan",
    "execute_with_fallback",
    "is_ws_rpc_target",
    "to_ws_url",
]
