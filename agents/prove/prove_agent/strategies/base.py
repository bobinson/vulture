"""Base strategy for finding verification."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prove_agent.protocols.detection import TargetCapabilities


class ProbeProtocol(str, Enum):
    """Protocol to use for verification probes."""

    HTTP = "http"
    WEBSOCKET = "websocket"
    JSONRPC = "jsonrpc"
    GRPC = "grpc"


class FailureReason(Enum):
    """Classified reason for a probe failure — inspired by prior deployments' FailoverReason."""

    AUTH_REQUIRED = "auth_required"       # 401/403 — needs credentials
    RATE_LIMITED = "rate_limited"          # 429 — too many requests
    TIMEOUT = "timeout"                   # Request timed out
    NOT_FOUND = "not_found"               # 404 — endpoint doesn't exist
    CONNECTION_ERROR = "connection_error"  # DNS/TCP failure
    SERVER_ERROR = "server_error"         # 5xx — server-side issue
    FORMAT_ERROR = "format_error"         # 400 — bad request format
    PAYLOAD_TOO_LARGE = "payload_too_large"  # Response body exceeds size limit
    PROTOCOL_ERROR = "protocol_error"    # Wrong protocol for target
    NONE = "none"                         # No failure


@dataclass
class ProofPlan:
    """Verification plan for a single finding."""

    description: str
    method: str  # HTTP method
    url_path: str  # Path to probe on staging
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    expected_indicators: list[str] = field(default_factory=list)
    is_multipart: bool = False  # Send as multipart/form-data file upload
    filename: str = ""  # Filename for multipart upload (e.g., "shell.php")
    protocol: ProbeProtocol = ProbeProtocol.HTTP
    rpc_method: str = ""  # JSON-RPC method name (e.g., "system_health")
    rpc_params: list | dict | None = None  # JSON-RPC params


@dataclass
class ReviewResult:
    """Safety review of a verification plan."""

    safe: bool
    concerns: list[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class ExecutionResult:
    """Result of executing a verification plan."""

    conclusive: bool
    reproduced: bool = False
    evidence: str = ""
    status_code: int = 0
    response_snippet: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    failure_reason: FailureReason = FailureReason.NONE
    protocol_used: str = ""  # Protocol that produced this result


@dataclass
class AttemptRecord:
    """Rich record of a single verification attempt for self-learning."""

    iteration: int
    method: str
    url_path: str
    status_code: int
    response_snippet: str
    response_headers: dict[str, str]
    evidence: str
    conclusive: bool
    reproduced: bool
    plan_description: str
    failure_reason: FailureReason = FailureReason.NONE
    protocol: str = "http"  # Protocol used for this attempt


@dataclass
class ReflectionResult:
    """LLM reflection on why an attempt was inconclusive."""

    analysis: str  # Why this attempt didn't prove/disprove
    suggested_approach: str  # What to try differently next
    confidence: int  # 0-100 how confident the vulnerability exists
    learnings: list[str] = field(default_factory=list)  # Reusable cross-finding insights


class BaseStrategy(ABC):
    """Abstract base for scanner-type-specific verification strategies."""

    @abstractmethod
    async def plan(
        self, finding: dict, staging_url: str, iteration: int,
        *, site_context: str = "",
        prior_attempts: list[AttemptRecord] | None = None,
        reflection: ReflectionResult | None = None,
        cross_learnings: list[str] | None = None,
    ) -> ProofPlan:
        """Generate a verification plan for a finding."""

    @abstractmethod
    async def review(
        self, plan: ProofPlan, staging_url: str,
    ) -> ReviewResult:
        """Review a plan for safety before execution."""

    @abstractmethod
    async def execute(
        self, plan: ProofPlan, staging_url: str,
        *, capabilities: TargetCapabilities | None = None,
    ) -> ExecutionResult:
        """Execute the verification plan against staging."""

    @abstractmethod
    async def reflect(
        self, finding: dict, attempts: list[AttemptRecord],
    ) -> ReflectionResult:
        """Reflect on attempts so far — analyze WHY inconclusive and what to try next."""
