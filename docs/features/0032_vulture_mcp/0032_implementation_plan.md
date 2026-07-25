# 0032 Vulture MCP Server Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship a minimal, secure, redistributable MCP server that exposes Vulture audit findings to any MCP-compatible agent harness — Claude Code, Codex CLI, OpenCode, Cursor, Zed, Windsurf, Continue, and future tools. The server is a thin, stateless API client that speaks MCP over stdio (universal) and streamable-http (remote). It holds the Vulture API key; the agent never sees it.

**Design principles:**
- **Zero trust in the agent.** The MCP server is the security boundary. It authenticates to Vulture, redacts sensitive content, enforces read-only by default, and rate-limits all calls.
- **Single file, no framework, pip-installable.** One `server.py` (~200 lines), one `pyproject.toml`, one README. No FastAPI, no database, no config files beyond env vars.
- **Every MCP client works.** stdio transport is universal (Claude Code, Codex, Cursor, Zed, Continue). streamable-http for remote/shared setups. Both from the same binary.
- **No embarrassing mistakes.** API keys never in tool responses. Secrets redacted from snippets. No eval/exec. No pickle. No dynamic imports. Type-annotated. Tested.

**Tech stack:** Python 3.12+, `mcp` SDK (FastMCP), `httpx` for Vulture API calls. Zero other dependencies.

---

## Architecture

```
┌─────────────────────┐    stdio or           ┌────────────────────┐
│ Agent Harness        │    streamable-http    │ vulture-mcp        │
│ ─────────────────── │◄═════════════════════►│ ────────────────── │
│ Claude Code          │    MCP protocol       │ server.py          │
│ Codex CLI            │    (JSON-RPC)         │                    │
│ Cursor               │                       │ Holds: API key     │
│ Zed                  │                       │ Redacts: secrets   │
│ Windsurf             │                       │ Enforces: read-only│
│ Continue             │                       │ Rate-limits: 10/s  │
│ OpenCode             │                       └─────────┬──────────┘
│                      │                                  │ HTTPS
│ Has: file access     │                                  │ Authorization: Bearer vk_...
└──────────────────────┘                       ┌──────────▼──────────┐
                                               │ Vulture Backend     │
                                               │ (any mode: A/B/C)   │
                                               └─────────────────────┘
```

**Data flow for a triage session:**
1. Agent calls `vulture_list_audits` → MCP server → Vulture API → response
2. Agent calls `vulture_get_findings(severity="critical")` → findings
3. Agent reads local file at `finding.file_path` (its own capability, not MCP)
4. Agent evaluates finding against code context
5. Agent calls `vulture_update_status(id, "false_positive", "method call on different object")` → MCP → Vulture
6. Repeat for next finding

---

## Compatibility matrix

| Client | Transport | Config location | Status |
|--------|-----------|-----------------|--------|
| Claude Code | stdio | `~/.claude/mcp.json` | Primary target |
| Codex CLI | stdio | `.codex/mcp.json` | Primary target |
| Cursor | stdio | `.cursor/mcp.json` | Primary target |
| Zed | stdio | `settings.json` → `context_servers` | Primary target |
| Windsurf | stdio | `~/.codeium/windsurf/mcp_config.json` | Primary target |
| Continue | stdio | `~/.continue/config.yaml` | Primary target |
| OpenCode | stdio | `mcp.json` | Primary target |
| Remote/shared | streamable-http | URL-based | Secondary (team use) |

All clients support stdio. That's the universal transport. streamable-http is additive for team/remote scenarios.

---

## File structure

```
mcp/
  server.py              # The entire MCP server (~200 lines)
  pyproject.toml         # pip install vulture-mcp
  README.md              # Setup for every supported client
  tests/
    test_server.py       # Tool tests with mocked Vulture API
    test_redaction.py    # Secret redaction tests
    conftest.py          # Shared fixtures
```

**That's it.** No `src/` directory, no `__init__.py` chains, no config loading framework. The server is the package.

---

## Security design

### Threat model

| Threat | Mitigation |
|--------|-----------|
| Agent extracts API key via tool calls | Key is in env var, never in any tool response. Tools return findings data only. |
| Agent reads arbitrary Vulture data | Tools are scoped to specific audit IDs. No admin endpoints exposed. |
| Findings contain detected secrets (`password=hunter2`) | Redaction layer strips patterns from `code_snippet` and `description` before returning. |
| Agent floods Vulture API | MCP server enforces 10 req/s rate limit (configurable). Token bucket in-process. |
| Agent marks all findings as false_positive | `vulture_update_status` requires `VULTURE_MCP_ALLOW_WRITE=true`. Off by default. |
| MCP server compromised | It's stateless — no DB, no disk writes, no persistence. Kill and restart. |
| Man-in-the-middle on Vulture API | httpx verifies TLS by default. When `transport=streamable-http`, enforce `VULTURE_URL` starts with `https://` or raise at startup. stdio transport allows http (localhost dev). |
| API key leak via httpx debug logging | Set `HTTPX_LOG_LEVEL=warn` at startup. httpx trace mode dumps Authorization headers to stderr which the agent harness could read. |
| Dependency supply chain | Only 2 deps: `mcp` + `httpx`. Both are Anthropic/Encode maintained. Pin versions. |

### Redaction rules

Applied to every `code_snippet` and `description` field before returning:

```python
REDACT_PATTERNS = [
    (r'(?i)(password|passwd|secret|token|api_key|apikey|auth)\s*[:=]\s*["\'][^"\']{4,}["\']', r'\1=***'),
    (r'(?i)(Bearer\s+)[A-Za-z0-9._\-]{20,}', r'\1***'),
    (r'(?i)(ghp_|gho_|github_pat_|sk-|vk_)[A-Za-z0-9]{10,}', '***'),
    (r'postgres://[^@]+@', 'postgres://***@'),
]
```

### Read-only by default

```
VULTURE_MCP_ALLOW_WRITE=false  (default)
  → vulture_update_status returns error: "write access disabled"

VULTURE_MCP_ALLOW_WRITE=true   (opt-in)
  → vulture_update_status works
```

---

## Tools specification (7 tools)

### 1. `vulture_list_audits`

```
Args:    limit (int, default 10), status (str, optional: "completed"|"running"|"failed")
Returns: [{id, source_path, types, status, findings_count, scores, created_at, completed_at}]
```

Maps to: `GET /api/audits?limit=N`

**Security:** Strip `webhook_url`, `findings`, `prove_results` from response — these are internal/large.

### 2. `vulture_get_findings`

```
Args:    audit_id (str, required), severity (str, optional), category (str, optional),
         agent_type (str, optional), limit (int, default 50), offset (int, default 0)
Returns: {"findings": [{fingerprint, severity, category, agent_type, title, description (redacted),
           file_path, line_start, line_end, recommendation (redacted), check_id}],
          "total": int, "has_more": bool, "next_offset": int}
```

Maps to: `GET /api/audits/:id` → extract findings, filter client-side, paginate, redact.

**Performance note:** The Vulture API does not support server-side finding filters. This tool fetches all findings and filters in Python. For audits with 500+ findings, the first call is O(N). Subsequent calls with different filters reuse the same HTTP response (cache the audit object per-session). Future: add `GET /api/audits/:id/findings?severity=X` to the backend.

**Redaction:** Applied to `description`, `recommendation`, and `content` fields. The `code_snippet` field is NOT persisted by the backend (model has it with `omitempty` but DB schema doesn't store it) — redact it defensively if present.

### 3. `vulture_get_finding_detail`

```
Args:    audit_id (str), fingerprint (str)
Returns: {finding fields + lineage: {current_status, notes, ticket_url, first_found_at,
          latest_found_at, fixed_at, first_commit, latest_commit, fixed_commit}}
```

Maps to: `GET /api/audits/:id` (find by fingerprint) + `GET /api/audits/:id/lineage` (lineage list, match by fingerprint).

**Field mapping:** Lineage uses `current_status` (not `status`), `first_found_at` (not `first_found`), `latest_found_at` (not `latest_found`). Match the actual `FindingLineage` struct in `backend/internal/model/lineage.go`.

### 4. `vulture_get_comparison`

```
Args:    audit_id (str)
Returns: {has_previous, previous_audit_id, previous_date, previous_findings_count,
          current_findings_count, new_count, fixed_count, changed_count, persistent_count,
          new_findings: [{fingerprint, title, severity, file_path}],
          fixed_findings: [{fingerprint, title, severity, file_path}],
          changed_findings: [{fingerprint, title, old_severity, new_severity, file_path}]}
```

Maps to: `GET /api/audits/:id/comparison`. Return shape matches `AuditComparison` struct in `backend/internal/model/audit.go`.

### 5. `vulture_search_findings`

```
Args:    query (str), limit (int, default 20)
Returns: [{title, content (redacted), severity, category, agent_type, codebase_path,
           file_paths, remediation_status, similarity}]
```

Maps to: `GET /api/memories/search?q=...`. Returns `AuditMemory` objects (not `Finding`). Key differences: field is `content` (not `description`), `codebase_path` (not `file_path`), `file_paths` (array). Redaction applied to `content`, `title`, and `remediation_notes`.

### 6. `vulture_list_lineage`

```
Args:    audit_id (str), status (str, optional: "open"|"false_positive"|"fixed"|...)
Returns: [{id, fingerprint, current_status, severity, category, title, file_path,
           first_found_at, latest_found_at, notes}]
```

Maps to: `GET /api/audits/:id/lineage`, optionally filtered by `current_status`. Enables the agent to see which findings are already triaged vs still open.

### 7. `vulture_update_status`

```
Args:    lineage_id (str), status (str: "open"|"in_progress"|"resolved"|"false_positive"|"accepted_risk"|"fixed"),
         notes (str, optional)
Returns: {id, current_status, updated_at, ...full FindingLineage}  OR  error if writes disabled
```

Maps to: `PATCH /api/lineage/:id`. Return field is `current_status` (not `status`). Valid statuses: `open`, `in_progress`, `resolved`, `false_positive`, `accepted_risk`, `fixed`. Note: `regression` is NOT a valid backend status — do not accept it.

**Gated by `VULTURE_MCP_ALLOW_WRITE=true`.** Returns clear error otherwise.

Maps to: `PATCH /api/lineage/:id`

**Gated by `VULTURE_MCP_ALLOW_WRITE=true`.** Returns clear error otherwise.

---

## Environment variables (the only config)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `VULTURE_URL` | Yes | — | Vulture backend URL (e.g. `http://localhost:28080`) |
| `VULTURE_API_KEY` | No* | — | API key (`vk_...`). Required if backend has API keys enabled. |
| `VULTURE_MCP_ALLOW_WRITE` | No | `false` | Enable `vulture_update_status` tool |
| `VULTURE_MCP_RATE_LIMIT` | No | `10` | Max requests/second to Vulture API |
| `VULTURE_MCP_TRANSPORT` | No | `stdio` | Transport: `stdio` or `streamable-http` |
| `VULTURE_MCP_PORT` | No | `8100` | Port for streamable-http transport |

*When running against Mode A dev-local with `VULTURE_LOCAL_MODE=true`, no API key is needed.

---

## Task 1: Project scaffolding

**Files:**
- Create: `mcp/pyproject.toml`
- Create: `mcp/tests/__init__.py`
- Create: `mcp/tests/conftest.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "vulture-mcp"
version = "0.1.0"
description = "MCP server for Vulture compliance audit platform"
readme = "README.md"
requires-python = ">=3.12"
license = "MIT"
dependencies = [
    "mcp>=1.20.0",
    "httpx>=0.27.0",
]

[project.scripts]
vulture-mcp = "server:main"

[tool.hatch.build.targets.wheel]
packages = ["."]
include = ["server.py"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "respx>=0.22",
]
```

Key decisions:
- `project.scripts` makes `vulture-mcp` a command after `pip install`.
- Only `server.py` is included — no package directory.
- `respx` for mocking httpx in tests.

- [ ] **Step 2: Create test fixtures**

```python
# mcp/tests/conftest.py
import os
import pytest

@pytest.fixture(autouse=True)
def vulture_env(monkeypatch):
    """Set minimal env for all tests."""
    monkeypatch.setenv("VULTURE_URL", "http://localhost:28080")
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "false")
```

- [ ] **Step 3: Commit**

---

## Task 2: Redaction module (inside server.py)

**This is the security-critical code. It ships before any tools.**

- [ ] **Step 1: Write redaction tests first**

```python
# mcp/tests/test_redaction.py
from server import redact_secrets

def test_redacts_password_in_snippet():
    assert '***' in redact_secrets('password = "hunter2"')
    assert 'hunter2' not in redact_secrets('password = "hunter2"')

def test_redacts_bearer_token():
    assert '***' in redact_secrets('Authorization: Bearer ghp_abc123xyz456def789')
    assert 'ghp_abc123xyz456def789' not in redact_secrets('Authorization: Bearer ghp_abc123xyz456def789')

def test_redacts_postgres_dsn():
    out = redact_secrets('postgres://admin:s3cret@db.neon.tech/vulture')
    assert 's3cret' not in out
    assert 'postgres://***@' in out

def test_redacts_vulture_api_key():
    assert 'vk_abc' not in redact_secrets('key=vk_abcdefghij1234567890')

def test_preserves_non_secret_content():
    safe = 'def process(data):\n    return data.upper()\n'
    assert redact_secrets(safe) == safe

def test_redacts_multiple_patterns_in_one_string():
    text = 'token="sk-abc123" and password="hunter2"'
    out = redact_secrets(text)
    assert 'sk-abc123' not in out
    assert 'hunter2' not in out

def test_none_input_returns_empty():
    assert redact_secrets(None) == ''
    assert redact_secrets('') == ''
```

- [ ] **Step 2: Implement redact_secrets in server.py**

```python
import re

_REDACT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)(password|passwd|secret|token|api_key|apikey|auth)\s*[:=]\s*["\'][^"\']{4,}["\']'), r'\1=***'),
    (re.compile(r'(?i)(Bearer\s+)\S{20,}'), r'\1***'),
    (re.compile(r'(?i)(?:ghp_|gho_|github_pat_|sk-|vk_|glpat-|AKIA)[A-Za-z0-9\-_]{10,}'), '***'),
    (re.compile(r'(?i)postgres(?:ql)?://[^@\s]+@'), 'postgres://***@'),
    (re.compile(r'(?i)mongodb(?:\+srv)?://[^@\s]+@'), 'mongodb://***@'),
]

def redact_secrets(text: str | None) -> str:
    if not text:
        return ''
    for pattern, replacement in _REDACT_RULES:
        text = pattern.sub(replacement, text)
    return text
```

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

---

## Task 3: Vulture API client (inside server.py)

**Thin httpx wrapper. Holds the API key. Never exposes it.**

- [ ] **Step 1: Write tests**

```python
# mcp/tests/test_server.py (start)
import pytest
import respx
import httpx
from server import VultureClient

@respx.mock
@pytest.mark.asyncio
async def test_client_sends_auth_header():
    route = respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = VultureClient("http://localhost:28080", "vk_test123")
    await client.list_audits()
    assert route.calls[0].request.headers["authorization"] == "Bearer vk_test123"

@respx.mock
@pytest.mark.asyncio
async def test_client_works_without_api_key():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = VultureClient("http://localhost:28080", None)
    result = await client.list_audits()
    assert result == []

@respx.mock
@pytest.mark.asyncio
async def test_client_raises_on_401():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    client = VultureClient("http://localhost:28080", "vk_bad")
    with pytest.raises(Exception, match="401"):
        await client.list_audits()
```

- [ ] **Step 2: Implement VultureClient**

```python
import httpx
import asyncio
from collections import deque
from time import monotonic

class VultureClient:
    """Stateless HTTP client for Vulture API. Holds credentials; never exposes them."""

    def __init__(self, base_url: str, api_key: str | None, rate_limit: int = 10):
        self._base = base_url.rstrip('/')
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=self._headers,
            timeout=30.0,
            verify=True,  # TLS verification always on
        )
        self._rate_limit = rate_limit
        self._timestamps: deque[float] = deque()
        self._rate_lock = asyncio.Lock()  # async-safe for streamable-http

    async def _request(self, method: str, path: str, **kwargs) -> dict | list:
        await self._enforce_rate_limit()
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            # Scrub response body — it might contain echoed auth headers from a proxy
            safe_body = redact_secrets(resp.text[:200])
            raise Exception(f"Vulture API error ({resp.status_code}): {safe_body}")
        return resp.json()

    async def _enforce_rate_limit(self):
        async with self._rate_lock:
            now = monotonic()
            while self._timestamps and now - self._timestamps[0] > 1.0:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._rate_limit:
                raise Exception(f"Rate limit exceeded ({self._rate_limit} req/s)")
            self._timestamps.append(now)

    async def list_audits(self, limit: int = 10, status: str | None = None) -> list:
        params = {"limit": limit}
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
        return await self._request("PATCH", f"/api/lineage/{lineage_id}",
                                   json={"status": status, "notes": notes})

    async def get_audit_lineage(self, audit_id: str) -> list:
        return await self._request("GET", f"/api/audits/{audit_id}/lineage")

    async def close(self):
        await self._client.aclose()
```

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

---

## Task 4: MCP tools (the core — inside server.py)

- [ ] **Step 1: Write tool tests**

```python
# mcp/tests/test_server.py (extend)
@respx.mock
@pytest.mark.asyncio
async def test_tool_list_audits_returns_summary():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[{
            "id": "a1", "source_path": "/src", "types": ["owasp"],
            "status": "completed", "findings_count": 5, "scores": {"owasp": 72},
            "created_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:01:00Z",
        }])
    )
    # call the tool function directly
    from server import tool_list_audits
    result = await tool_list_audits(limit=10)
    assert len(result) == 1
    assert result[0]["id"] == "a1"
    assert "findings" not in result[0]  # summary only, no full findings

@respx.mock
@pytest.mark.asyncio
async def test_tool_get_findings_redacts_secrets():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json={
            "id": "a1", "findings": [{
                "fingerprint": "fp1", "severity": "critical", "category": "injection",
                "title": "SQL injection", "description": "Found query",
                "file_path": "/app/db.py", "line_start": 10,
                "code_snippet": 'password = "hunter2"', "recommendation": "parameterize",
            }]
        })
    )
    from server import tool_get_findings
    result = await tool_get_findings(audit_id="a1")
    assert 'hunter2' not in result[0].get("code_snippet", "")

@pytest.mark.asyncio
async def test_tool_update_status_blocked_by_default(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "false")
    from server import tool_update_status
    with pytest.raises(Exception, match="write access disabled"):
        await tool_update_status(lineage_id="l1", status="false_positive")
```

- [ ] **Step 2: Implement all 6 tools**

```python
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "vulture-mcp",
    version="0.1.0",
    description="Vulture compliance audit findings for AI-assisted triage",
)

# Lazy-init client with async lock (safe under streamable-http concurrency)
_client: VultureClient | None = None
_client_lock = asyncio.Lock()

async def _get_client() -> VultureClient:
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is not None:  # double-check after acquiring lock
            return _client
        url = os.environ.get("VULTURE_URL", "")
        if not url:
            raise ValueError("VULTURE_URL environment variable is required")
        key = os.environ.get("VULTURE_API_KEY")
        rate = int(os.environ.get("VULTURE_MCP_RATE_LIMIT", "10"))
        # Suppress httpx debug logging — trace mode leaks Authorization headers to stderr
        os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
        _client = VultureClient(url, key, rate_limit=rate)
    return _client

def _allow_write() -> bool:
    return os.environ.get("VULTURE_MCP_ALLOW_WRITE", "false").lower() == "true"

def _redact_record(f: dict) -> dict:
    """Return a copy with sensitive fields redacted.
    Works for both Finding objects and AuditMemory objects."""
    out = dict(f)
    for key in ("code_snippet", "description", "recommendation", "content", "remediation_notes"):
        if key in out and out[key]:
            out[key] = redact_secrets(out[key])
    # Never expose webhook URLs (internal endpoints)
    out.pop("webhook_url", None)
    return out


@mcp.tool()
async def vulture_list_audits(limit: int = 10, status: str | None = None) -> list[dict]:
    """List recent Vulture audits. Returns summaries (no full findings)."""
    client = await _get_client()
    audits = await client.list_audits(limit=limit, status=status)
    for a in audits:
        a.pop("findings", None)
        a.pop("prove_results", None)
        a.pop("webhook_url", None)  # internal endpoint — don't expose
    return audits


@mcp.tool()
async def vulture_get_findings(
    audit_id: str,
    severity: str | None = None,
    category: str | None = None,
    agent_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Get findings from a specific audit. Supports filtering by severity/category/agent_type."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    findings = audit.get("findings", [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    if agent_type:
        findings = [f for f in findings if f.get("agent_type") == agent_type]
    total = len(findings)
    page = findings[offset:offset + limit]
    return {
        "findings": [_redact_record(f) for f in page],
        "total": total,
        "has_more": offset + limit < total,
        "next_offset": offset + limit if offset + limit < total else None,
    }


@mcp.tool()
async def vulture_get_finding_detail(audit_id: str, fingerprint: str) -> dict:
    """Get detailed info for one finding, including lineage history."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    finding = next((f for f in audit.get("findings", []) if f.get("fingerprint") == fingerprint), None)
    if not finding:
        raise ValueError(f"Finding with fingerprint {fingerprint} not found in audit {audit_id}")
    result = _redact_record(finding)
    # Attach lineage if available
    try:
        lineages = await client.get_audit_lineage(audit_id)
        lineage = next((l for l in lineages if l.get("fingerprint") == fingerprint), None)
        if lineage:
            result["lineage"] = lineage
    except Exception:
        pass  # lineage is supplemental; don't fail the tool
    return result


@mcp.tool()
async def vulture_get_comparison(audit_id: str) -> dict:
    """Compare an audit with the previous one. Shows new, fixed, and changed findings."""
    client = await _get_client()
    return await client.get_comparison(audit_id)


@mcp.tool()
async def vulture_search_findings(query: str, limit: int = 20) -> list[dict]:
    """Semantic search across all audit findings using pgvector embeddings."""
    client = await _get_client()
    results = await client.search_memories(query, limit=limit)
    return [_redact_record(r) for r in results]


@mcp.tool()
async def vulture_update_status(
    lineage_id: str,
    status: str,
    notes: str = "",
) -> dict:
    """Update finding triage status. Requires VULTURE_MCP_ALLOW_WRITE=true.

    Valid statuses: open, in_progress, resolved, false_positive, accepted_risk, fixed, regression.
    """
    if not _allow_write():
        raise PermissionError(
            "write access disabled — set VULTURE_MCP_ALLOW_WRITE=true to enable finding triage"
        )
    valid = {"open", "in_progress", "resolved", "false_positive", "accepted_risk", "fixed"}
    if status not in valid:
        raise ValueError(f"Invalid status '{status}'. Valid: {', '.join(sorted(valid))}")
    client = await _get_client()
    return await client.update_lineage(lineage_id, status, notes)


def main():
    # Suppress httpx debug logging that would leak auth headers to stderr
    os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
    transport = os.environ.get("VULTURE_MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        # Enforce TLS for remote transport — API key travels over this connection
        url = os.environ.get("VULTURE_URL", "")
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            raise SystemExit("ERROR: VULTURE_URL must use https:// for streamable-http transport")
        port = int(os.environ.get("VULTURE_MCP_PORT", "8100"))
        mcp.run(transport="streamable-http", port=port)
    else:
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run all tests, verify pass**
- [ ] **Step 4: Commit**

---

## Task 5: README with setup for every client

**Files:**
- Create: `mcp/README.md`

Content must cover:

### Installation

```bash
pip install vulture-mcp
# or from source:
cd mcp && pip install -e .
```

### Configuration by client

**Claude Code** (`~/.claude/mcp.json`):
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": {
        "VULTURE_URL": "http://localhost:28080",
        "VULTURE_API_KEY": "vk_your_key_here"
      }
    }
  }
}
```

**Codex CLI** (`.codex/mcp.json`):
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

**Cursor** (Settings → MCP → Add Server):
```json
{
  "vulture": {
    "command": "vulture-mcp",
    "env": { "VULTURE_URL": "http://localhost:28080" }
  }
}
```

**Zed** (`settings.json`):
```json
{
  "context_servers": {
    "vulture": {
      "command": { "path": "vulture-mcp" },
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`):
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

**Continue** (`~/.continue/config.yaml`):
```yaml
mcpServers:
  - name: vulture
    command: vulture-mcp
    env:
      VULTURE_URL: http://localhost:28080
```

**Remote/shared** (streamable-http):
```bash
VULTURE_URL=https://vulture.example.com \
VULTURE_API_KEY=vk_... \
VULTURE_MCP_TRANSPORT=streamable-http \
VULTURE_MCP_PORT=8100 \
vulture-mcp
```

### Available tools

Table of all 6 tools with args and descriptions.

### Security notes

- API key lives in MCP server env — the agent never sees it.
- Code snippets are redacted: passwords, tokens, DSNs, API keys masked.
- Writes disabled by default. Set `VULTURE_MCP_ALLOW_WRITE=true` to enable triage.
- Rate limited to 10 req/s (configurable via `VULTURE_MCP_RATE_LIMIT`).

### Dev-local quick start

```bash
# Start Vulture
scripts/vulture.sh dev skills

# In another terminal, test the MCP
VULTURE_URL=http://localhost:28080 vulture-mcp
```

- [ ] **Step 1: Write README**
- [ ] **Step 2: Commit**

---

## Task 6: Integration test

- [ ] **Step 1: Write a real integration test against a running Vulture**

```python
# mcp/tests/test_integration.py
"""Integration test — requires a running Vulture backend.
   Skip if VULTURE_URL is not reachable.
"""
import os
import pytest
import httpx

VULTURE_URL = os.environ.get("VULTURE_URL", "http://localhost:28080")

@pytest.fixture
def skip_if_no_vulture():
    try:
        httpx.get(f"{VULTURE_URL}/health", timeout=2)
    except Exception:
        pytest.skip("Vulture backend not reachable")

@pytest.mark.asyncio
async def test_list_audits_real(skip_if_no_vulture):
    from server import VultureClient
    client = VultureClient(VULTURE_URL, os.environ.get("VULTURE_API_KEY"))
    audits = await client.list_audits(limit=5)
    assert isinstance(audits, list)
    await client.close()
```

- [ ] **Step 2: Wire into Makefile**

Add to project Makefile:
```makefile
test-mcp:
	cd mcp && python -m pytest tests/ -v
```

- [ ] **Step 3: Commit**

---

## Task 7: Feature documentation

**Files:**
- Create: `docs/features/0032_vulture_mcp/0032_implementation_status.md`
- Create: `docs/features/0032_vulture_mcp/0032_rollback_plan.md`

- [ ] **Step 1: Write status + rollback**
- [ ] **Step 2: Commit**

---

## Self-review checklist

### Security
- [ ] API key never appears in any tool response (grep server.py for `api_key`, `vk_`, `Bearer`)
- [ ] `redact_secrets` covers: passwords, bearer tokens, GitHub PATs, Postgres DSNs, MongoDB DSNs, Vulture keys, AWS keys
- [ ] `_redact_record` applied to `description`, `recommendation`, `content`, `remediation_notes`, `code_snippet`
- [ ] `webhook_url` stripped from list_audits responses (internal endpoint)
- [ ] `vulture_update_status` returns `PermissionError` when `ALLOW_WRITE` is false
- [ ] `vulture_update_status` valid set matches backend exactly (no `regression`)
- [ ] httpx `verify=True` (TLS verification) is never disabled
- [ ] `HTTPX_LOG_LEVEL=warn` set at startup — prevents trace-mode auth header leak to stderr
- [ ] TLS enforced for streamable-http transport (http:// rejected unless localhost)
- [ ] Error responses from Vulture API are redacted before surfacing to agent
- [ ] No `eval`, `exec`, `pickle`, `subprocess`, `__import__` anywhere in server.py
- [ ] No file reads or writes — the server is purely an API client
- [ ] Rate limit async-safe: uses `asyncio.Lock` around deque operations
- [ ] Client init async-safe: `_get_client()` uses `asyncio.Lock` for double-checked locking

### Compatibility
- [ ] stdio transport works (default)
- [ ] streamable-http transport works
- [ ] `pip install .` produces a `vulture-mcp` command
- [ ] README has copy-pasteable config for: Claude Code, Codex, Cursor, Zed, Windsurf, Continue

### Quality
- [ ] Total lines in server.py < 250
- [ ] Zero dependencies beyond `mcp` + `httpx`
- [ ] All 6 tools have tests with mocked API
- [ ] Redaction has 7+ test cases covering all patterns
- [ ] No global mutable state except the lazy-init client
- [ ] Type annotations on all public functions
- [ ] `pyproject.toml` has pinned minimum versions

### Correctness
- [ ] `list_audits` strips `findings`, `prove_results`, `webhook_url` from response
- [ ] `get_findings` returns `{"findings": [...], "total": N, "has_more": bool, "next_offset": int}`
- [ ] `get_finding_detail` lineage fields match backend: `current_status`, `first_found_at`, `latest_found_at`
- [ ] `get_comparison` return shape matches `AuditComparison` struct (includes `changed_findings` with `old_severity`/`new_severity`)
- [ ] `search_findings` returns `AuditMemory` objects (field `content`, not `description`) — redacted via `_redact_record`
- [ ] `list_lineage` filters by `current_status` when specified
- [ ] `update_status` validates against backend's exact valid set: `open, in_progress, resolved, false_positive, accepted_risk, fixed` (no `regression`)
- [ ] All `_get_client()` calls use `await` (async client init)

### Test fixtures
- [ ] `conftest.py` resets `server._client = None` between tests (prevents cross-test leaks)
- [ ] Redaction tests cover `content` field (AuditMemory) not just `code_snippet` (Finding)
- [ ] `code_snippet` tests document that the field is NOT persisted by the backend — test as defense-in-depth

---

## Out of scope

- **MCP prompts:** Not needed — the agent harness provides its own reasoning.
- **MCP resources:** Tools are sufficient; resources add complexity without value here.
- **WebSocket transport:** Not supported by enough clients to justify.
- **Caching layer:** The MCP server is stateless. Agent harnesses cache tool results natively.
- **Auth to the MCP server itself:** stdio is process-local (trusted). streamable-http should be behind a reverse proxy with its own auth if exposed.
- **Multi-tenant:** One MCP server = one Vulture instance. Run multiple for multiple instances.
- **Finding auto-fix:** The MCP provides data. The agent decides what to do with it. Fix logic lives in the agent, not the MCP.

---

## Estimated effort

| Task | Lines | Time |
|------|-------|------|
| 1. Scaffolding (pyproject, fixtures) | 40 | 30 min |
| 2. Redaction module + tests | 50 | 1 hour |
| 3. VultureClient + tests | 70 | 1 hour |
| 4. MCP tools (6) + tests | 120 | 2 hours |
| 5. README (7 client configs) | 150 | 1 hour |
| 6. Integration test + Makefile | 30 | 30 min |
| 7. Feature docs | 30 | 15 min |
| **Total** | **~490** | **~6 hours** |

Server.py itself: **~200 lines** (redaction + client + 6 tools + main). The rest is tests and docs.
