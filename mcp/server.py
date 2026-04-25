"""Vulture MCP Server — exposes audit findings to MCP-compatible agent harnesses."""

import asyncio
import os
import re
from collections import deque
from time import monotonic

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_REDACT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(
        r'(?i)(password|passwd|secret|token|api_key|apikey|auth)\s*[:=]\s*["\'][^"\']{4,}["\']'
    ), r'\1=***'),
    (re.compile(r'(?i)(Bearer\s+)\S{20,}'), r'\1***'),
    (re.compile(r'(?i)(?:ghp_|gho_|github_pat_|sk-|sk-proj-|vk_|glpat-|AKIA)[A-Za-z0-9\-_]{10,}'), '***'),
    (re.compile(r'(?i)postgres(?:ql)?://[^@\s]+@'), 'postgres://***@'),
    (re.compile(r'(?i)mongodb(?:\+srv)?://[^@\s]+@'), 'mongodb://***@'),
]


def redact_secrets(text: str | None) -> str:
    """Strip secrets from text using regex patterns. Returns empty string for None/empty."""
    if not text:
        return ""
    for pattern, replacement in _REDACT_RULES:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Vulture API Client
# ---------------------------------------------------------------------------


class VultureClient:
    """Async HTTP client for Vulture API. Holds credentials; never exposes them."""

    def __init__(self, base_url: str, api_key: str | None, rate_limit: int = 10):
        self._base = base_url.rstrip("/")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=headers,
            timeout=30.0,
            verify=True,
        )
        self._rate_limit = rate_limit
        self._timestamps: deque[float] = deque()
        self._rate_lock = asyncio.Lock()

    async def _enforce_rate_limit(self) -> None:
        async with self._rate_lock:
            now = monotonic()
            while self._timestamps and now - self._timestamps[0] > 1.0:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._rate_limit:
                raise Exception(f"Rate limit exceeded ({self._rate_limit} req/s)")
            self._timestamps.append(now)

    async def _request(self, method: str, path: str, **kwargs) -> dict | list:
        await self._enforce_rate_limit()
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            safe_body = redact_secrets(resp.text[:200])
            raise Exception(f"Vulture API error ({resp.status_code}): {safe_body}")
        return resp.json()

    async def list_audits(self, limit: int = 10, status: str | None = None) -> list:
        params: dict = {"limit": limit}
        if status:
            params["status"] = status
        return await self._request("GET", "/api/audits", params=params)

    async def get_audit(self, audit_id: str) -> dict:
        return await self._request("GET", f"/api/audits/{audit_id}")

    async def get_comparison(self, audit_id: str) -> dict:
        return await self._request("GET", f"/api/audits/{audit_id}/comparison")

    async def search_memories(self, query: str, limit: int = 20) -> list:
        return await self._request("GET", "/api/memories/search", params={"q": query, "limit": limit})

    async def update_lineage(self, lineage_id: str, status: str, notes: str = "") -> dict:
        return await self._request("PATCH", f"/api/lineage/{lineage_id}", json={"status": status, "notes": notes})

    async def get_audit_lineage(self, audit_id: str) -> list:
        return await self._request("GET", f"/api/audits/{audit_id}/lineage")

    async def close(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# MCP Server + helpers
# ---------------------------------------------------------------------------

mcp = FastMCP("vulture-mcp")

_client: VultureClient | None = None
_client_lock = asyncio.Lock()

_VALID_STATUSES = {"open", "in_progress", "resolved", "false_positive", "accepted_risk", "fixed"}

_SENSITIVE_FIELDS = ("code_snippet", "description", "recommendation", "content", "remediation_notes")


async def _get_client() -> VultureClient:
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is not None:
            return _client
        url = os.environ.get("VULTURE_URL", "")
        if not url:
            raise ValueError("VULTURE_URL environment variable is required")
        key = os.environ.get("VULTURE_API_KEY")
        rate = int(os.environ.get("VULTURE_MCP_RATE_LIMIT", "10"))
        os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
        _client = VultureClient(url, key, rate_limit=rate)
    return _client


def _allow_write() -> bool:
    return os.environ.get("VULTURE_MCP_ALLOW_WRITE", "false").lower() == "true"


def _redact_record(f: dict) -> dict:
    """Return a copy with sensitive fields redacted."""
    out = dict(f)
    for key in _SENSITIVE_FIELDS:
        if key in out and out[key]:
            out[key] = redact_secrets(out[key])
    out.pop("webhook_url", None)
    return out


def _filter_findings(
    findings: list[dict],
    severity: str | None,
    category: str | None,
    agent_type: str | None,
) -> list[dict]:
    """Filter findings by optional criteria. Extracted to keep tool CC < 5."""
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    if agent_type:
        findings = [f for f in findings if f.get("agent_type") == agent_type]
    return findings


def _redact_comparison(comparison: dict) -> dict:
    """Redact sensitive fields in comparison finding lists."""
    out = dict(comparison)
    for key in ("new_findings", "fixed_findings", "changed_findings"):
        if key in out and isinstance(out[key], list):
            out[key] = [_redact_record(f) for f in out[key]]
    return out


async def _build_lineage_map(client: VultureClient, audit_id: str) -> dict:
    """Build fingerprint -> lineage dict for an audit. Returns empty dict on failure."""
    try:
        lineages = await client.get_audit_lineage(audit_id)
        return {ln.get("fingerprint", ""): ln for ln in lineages if ln.get("fingerprint")}
    except Exception:
        return {}


def _compute_ref(lineage: dict) -> str:
    """Compute a VLT-NNNN ref string from a lineage record."""
    ref = lineage.get("ref", "")
    if ref:
        return ref
    rn = lineage.get("ref_number", 0)
    return f"VLT-{rn:04d}" if rn and rn > 0 else ""


def _enrich_finding(finding: dict, lineage_map: dict) -> dict:
    """Add lineage_id, lineage_status, and ref to a finding."""
    result = _redact_record(finding)
    fp = finding.get("fingerprint", "")
    lineage = lineage_map.get(fp)
    if lineage:
        result["lineage_id"] = lineage.get("id", "")
        result["lineage_status"] = lineage.get("current_status", "open")
        result["ref"] = _compute_ref(lineage)
    return result


async def _resolve_lineage_id(
    ref: str | None, fingerprint: str | None, lineage_id: str | None, audit_id: str | None,
) -> str:
    """Resolve a finding reference to a lineage ID."""
    if lineage_id:
        return lineage_id

    client = await _get_client()

    if ref or fingerprint:
        audit_id = audit_id or await _resolve_audit_id(client)
        lineages = await client.get_audit_lineage(audit_id)
        return _match_lineage(lineages, ref, fingerprint, audit_id)

    raise ValueError("Provide one of: ref, fingerprint, or lineage_id")


async def _resolve_audit_id(client: VultureClient) -> str:
    """Get audit_id from most recent audit when none provided."""
    audits = await client.list_audits(limit=1)
    if not audits:
        raise ValueError("No audits found — provide audit_id explicitly")
    return audits[0].get("id", "")


def _match_lineage(lineages: list, ref: str | None, fingerprint: str | None, audit_id: str) -> str:
    """Find matching lineage ID by ref or fingerprint."""
    if ref:
        for ln in lineages:
            if _compute_ref(ln) == ref:
                return ln["id"]
        raise ValueError(f"Finding ref '{ref}' not found in audit {audit_id}")
    if fingerprint:
        for ln in lineages:
            if ln.get("fingerprint") == fingerprint:
                return ln["id"]
        raise ValueError(f"Fingerprint '{fingerprint}' not found in audit {audit_id}")
    raise ValueError("Provide one of: ref, fingerprint, or lineage_id")


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def vulture_list_audits(limit: int = 10, status: str | None = None) -> list[dict]:
    """List recent Vulture audits. Returns summaries (no full findings)."""
    client = await _get_client()
    audits = await client.list_audits(limit=limit, status=status)
    for a in audits:
        a.pop("findings", None)
        a.pop("prove_results", None)
        a.pop("webhook_url", None)
    return audits


@mcp.tool()
async def vulture_get_findings(
    audit_id: str,
    severity: str | None = None,
    category: str | None = None,
    agent_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Get findings from a specific audit with filtering and pagination."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    findings = _filter_findings(audit.get("findings", []), severity, category, agent_type)

    # Enrich with lineage status and ref
    lineage_map = await _build_lineage_map(client, audit_id)

    total = len(findings)
    page = findings[offset : offset + limit]
    enriched = [_enrich_finding(f, lineage_map) for f in page]
    has_more = offset + limit < total
    return {
        "findings": enriched,
        "total": total,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }


@mcp.tool()
async def vulture_get_finding_detail(audit_id: str, fingerprint: str) -> dict:
    """Get detailed info for one finding, including current lineage record if available."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    finding = next((f for f in audit.get("findings", []) if f.get("fingerprint") == fingerprint), None)
    if not finding:
        raise ValueError(f"Finding with fingerprint {fingerprint} not found in audit {audit_id}")
    result = _redact_record(finding)
    try:
        lineages = await client.get_audit_lineage(audit_id)
        lineage = next((ln for ln in lineages if ln.get("fingerprint") == fingerprint), None)
        if lineage:
            result["lineage"] = _redact_record(lineage)
    except Exception as exc:
        result["lineage_error"] = f"Failed to fetch lineage: {type(exc).__name__}"
    return result


@mcp.tool()
async def vulture_get_comparison(audit_id: str) -> dict:
    """Compare an audit with the previous one. Shows new, fixed, and changed findings."""
    client = await _get_client()
    comparison = await client.get_comparison(audit_id)
    return _redact_comparison(comparison)


@mcp.tool()
async def vulture_search_findings(query: str, limit: int = 20) -> list[dict]:
    """Semantic search across all audit findings using pgvector embeddings."""
    client = await _get_client()
    results = await client.search_memories(query, limit=limit)
    return [_redact_record(r) for r in results]


@mcp.tool()
async def vulture_list_lineage(audit_id: str, status: str | None = None) -> list[dict]:
    """List finding lineage for an audit, optionally filtered by status."""
    client = await _get_client()
    lineages = await client.get_audit_lineage(audit_id)
    if status:
        lineages = [ln for ln in lineages if ln.get("current_status") == status]
    return [_redact_record(ln) for ln in lineages]


@mcp.tool()
async def vulture_update_status(
    status: str,
    ref: str | None = None,
    fingerprint: str | None = None,
    lineage_id: str | None = None,
    audit_id: str | None = None,
    notes: str = "",
) -> dict:
    """Update finding triage status. Accepts ref (VLT-0042), fingerprint, or lineage_id.
    Requires VULTURE_MCP_ALLOW_WRITE=true."""
    if not _allow_write():
        raise PermissionError("write access disabled — set VULTURE_MCP_ALLOW_WRITE=true to enable finding triage")
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {', '.join(sorted(_VALID_STATUSES))}")
    resolved_id = await _resolve_lineage_id(ref, fingerprint, lineage_id, audit_id)
    client = await _get_client()
    return await client.update_lineage(resolved_id, status, notes)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
    transport = os.environ.get("VULTURE_MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        url = os.environ.get("VULTURE_URL", "")
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            raise SystemExit("ERROR: VULTURE_URL must use https:// for streamable-http transport")
        port = int(os.environ.get("VULTURE_MCP_PORT", "8100"))
        mcp.run(transport="streamable-http", port=port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
