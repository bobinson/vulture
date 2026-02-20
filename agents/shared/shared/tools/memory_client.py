"""HTTP client for the Vulture memory API.

Enables agents to search prior findings, store new memories, and retrieve
context for a codebase — reducing redundant analysis and saving tokens.
"""

import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx

_BACKEND_URL = os.environ.get("VULTURE_BACKEND_URL", "http://backend:8080")
_TIMEOUT = 10.0


def _url(path: str) -> str:
    return f"{_BACKEND_URL}{path}"


def memory_search(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Search memories by semantic text query.

    Args:
        query: Natural language search string.
        limit: Maximum results to return.

    Returns:
        List of matching memory dicts sorted by relevance.
    """
    try:
        resp = httpx.get(
            _url("/api/memories/search"),
            params={"q": query, "limit": limit},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return []


def memory_get_context(codebase_path: str, agent_type: str = "", limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve prior findings for a codebase path.

    Used before scanning to understand what was found previously,
    enabling agents to skip known issues and focus on new ones.

    Args:
        codebase_path: Path to the codebase being audited.
        agent_type: Optional filter by agent type (chaos, owasp, soc2).
        limit: Maximum results.

    Returns:
        List of prior finding memories for the codebase.
    """
    try:
        params: dict[str, Any] = {
            "path": codebase_path,
            "limit": limit,
        }
        if agent_type:
            params["agent_type"] = agent_type
        resp = httpx.get(
            _url("/api/memories/by-path"),
            params=params,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        # Fallback to text search if dedicated endpoint unavailable
        try:
            resp = httpx.get(
                _url("/api/memories/search"),
                params={"q": codebase_path, "limit": limit},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return []


def memory_get_edges(memory_id: str) -> list[dict[str, Any]]:
    """Get related memories (edges) for a specific memory.

    Args:
        memory_id: UUID of the memory to get edges for.

    Returns:
        List of edge dicts with source_id, target_id, relation_type, strength.
    """
    try:
        resp = httpx.get(
            _url(f"/api/memories/{memory_id}/edges"),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return []


def memory_update_remediation(memory_id: str, status: str, notes: str = "") -> bool:
    """Update the remediation status of a memory.

    Args:
        memory_id: UUID of the memory to update.
        status: New status (open, in_progress, resolved, accepted_risk, false_positive).
        notes: Optional remediation notes.

    Returns:
        True if update succeeded.
    """
    try:
        resp = httpx.patch(
            _url(f"/api/memories/{memory_id}"),
            json={"status": status, "notes": notes},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return True
    except httpx.HTTPError:
        return False


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SKIP_STATUSES = {"resolved", "false_positive"}
_MAX_CONTEXT_FINDINGS = 25
_STALENESS_DAYS = 180


def estimate_tokens(text: str) -> int:
    """Estimate token count using ~4 chars per token heuristic."""
    return max(1, len(text) // 4)


def _staleness_weight(m: dict[str, Any]) -> float:
    """Return a 0.0-1.0 weight based on age. 1.0 = fresh, 0.0 = stale (>=180 days)."""
    created = m.get("created_at", "")
    if not created:
        return 0.5  # unknown age, neutral weight
    try:
        if isinstance(created, str):
            # Handle ISO format with or without Z suffix
            created = created.replace("Z", "+00:00")
            dt = datetime.fromisoformat(created)
        else:
            dt = created
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days >= _STALENESS_DAYS:
            return 0.0
        return 1.0 - (age_days / _STALENESS_DAYS)
    except (ValueError, TypeError):
        return 0.5


def _normalize_title(title: str) -> str:
    """Normalize a finding title for fuzzy deduplication.

    Strips line numbers, file-specific details, and normalizes casing
    so that 'SQL Injection in login handler' and 'SQL Injection in auth handler'
    map to the same deduplicated concept.
    """
    t = title.strip().lower()
    # Remove line number references like "at line 42", "line 15"
    t = re.sub(r"\s*(at\s+)?line\s+\d+", "", t)
    # Remove "in <identifier>" suffixes like "in login handler"
    t = re.sub(r"\s+in\s+\S+(\s+\S+)?$", "", t)
    return t.strip()


def _dedup_key(m: dict[str, Any]) -> str:
    """Create a deduplication key from normalized title and first file path."""
    title = _normalize_title(m.get("title", ""))
    paths = m.get("file_paths", [])
    first_path = paths[0].strip().lower() if paths else ""
    return f"{title}|{first_path}"


def _fetch_edge_clusters(memories: list[dict[str, Any]], max_fetch: int = 10) -> dict[str, str]:
    """Build memory-ID-to-cluster-representative mapping using embedding edges.

    For each memory, fetches its edges and groups strongly-connected memories
    into clusters via Union-Find. Returns a mapping: memory_id -> representative_id
    (lexicographically smallest ID in cluster). This allows dedup to treat
    semantically similar findings as the same.

    Args:
        memories: List of memory dicts (must have ``id`` fields for clustering).
        max_fetch: Maximum number of edge-fetch HTTP calls to make.

    Returns:
        Mapping from memory ID to its cluster representative ID.
    """
    if not memories:
        return {}

    mem_ids = {m.get("id", "") for m in memories if m.get("id")}
    if not mem_ids:
        return {}

    # Union-Find for clustering
    parent: dict[str, str] = {mid: mid for mid in mem_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # Use lexicographically smaller as root for determinism
            if ra > rb:
                ra, rb = rb, ra
            parent[rb] = ra

    # Fetch edges for top N memories only (limit HTTP calls)
    fetched = 0
    for m in memories:
        if fetched >= max_fetch:
            break
        mid = m.get("id", "")
        if not mid:
            continue
        try:
            edges = memory_get_edges(mid)
            for edge in edges:
                target = edge.get("target_id", "")
                source = edge.get("source_id", "")
                other = target if source == mid else source
                strength = edge.get("strength", 0.0)
                rel_type = edge.get("relation_type", "")
                if other in mem_ids and strength >= 0.75 and rel_type == "same_issue":
                    union(mid, other)
            fetched += 1
        except Exception:
            continue

    return {mid: find(mid) for mid in mem_ids}


def _filter_and_dedup(
    memories: list[dict[str, Any]],
    max_count: int = _MAX_CONTEXT_FINDINGS,
    use_edges: bool = False,
) -> list[dict[str, Any]]:
    """Filter out resolved findings and deduplicate by title+file_path.

    When *use_edges* is True, a second dedup pass clusters memories that share
    strong ``same_issue`` embedding edges (strength >= 0.75), catching
    synonym-style duplicates (e.g. "Hardcoded Password" vs "Hardcoded Secret")
    that text-based normalization misses.

    Returns unique, actionable findings sorted by severity (critical first).
    """
    # Phase 1: Text-based dedup
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for m in memories:
        status = m.get("remediation_status", "open")
        if status in _SKIP_STATUSES:
            continue
        key = _dedup_key(m)
        if key in seen:
            continue
        seen.add(key)
        unique.append(m)

    # Filter out stale findings (older than 180 days)
    unique = [m for m in unique if _staleness_weight(m) > 0.0]

    # Phase 2: Edge-based semantic dedup (when available)
    if use_edges and len(unique) > 1:
        clusters = _fetch_edge_clusters(unique)
        if clusters:
            seen_clusters: set[str] = set()
            edge_deduped: list[dict[str, Any]] = []
            for m in unique:
                mid = m.get("id", "")
                cluster_id = clusters.get(mid, mid) if mid else ""
                if cluster_id and cluster_id in seen_clusters:
                    continue
                if cluster_id:
                    seen_clusters.add(cluster_id)
                edge_deduped.append(m)
            unique = edge_deduped

    unique.sort(key=lambda m: (
        _SEVERITY_RANK.get(m.get("severity", "info"), 4),
        -_staleness_weight(m),  # fresher findings first within same severity
    ))
    return unique[:max_count]


def build_prior_context(
    codebase_path: str,
    agent_type: str,
    preloaded: list[dict[str, Any]] | None = None,
    max_findings: int = _MAX_CONTEXT_FINDINGS,
) -> str:
    """Build a compact, deduplicated summary of prior findings for agent context.

    When ``preloaded`` is provided (from Go backend), uses those directly
    instead of re-fetching from the memory API — avoiding a redundant HTTP
    round-trip and saving latency.

    Optimized for minimal token usage:
    - Deduplicates by title + file_path (eliminates repeated findings)
    - Excludes resolved / false_positive findings (no wasted context)
    - Prioritizes by severity (critical first)
    - Caps at configurable max (default 25) most relevant findings
    - Uses compact single-line format (~15 tokens per finding vs ~30 before)

    Args:
        codebase_path: Path to the codebase being audited.
        agent_type: Agent type to filter by.
        preloaded: Optional pre-loaded findings from Go backend (avoids re-fetch).

    Returns:
        Formatted text summary of prior findings, or empty string.
    """
    if preloaded:
        raw = _adapt_prior_findings(preloaded)
    else:
        raw = memory_get_context(codebase_path, agent_type, limit=30)
    if not raw:
        return ""

    use_edges = not bool(preloaded)  # Only use edges for API-sourced memories (have IDs)
    findings = _filter_and_dedup(raw, max_count=max_findings, use_edges=use_edges)
    if not findings:
        return ""

    lines = [f"Known issues ({len(findings)}):"]
    for m in findings:
        sev = m.get("severity", "info")[0].upper()  # C/H/M/L/I
        title = m.get("title", "?")
        paths = m.get("file_paths", [])
        loc = paths[0].rsplit("/", 1)[-1] if paths else ""
        cat = m.get("category", "")
        cat_tag = f"[{cat}] " if cat else ""
        lines.append(f" {sev}:{cat_tag}{title}" + (f" @{loc}" if loc else ""))

    lines.append("Skip known issues. Report NEW findings only.")

    deduped_count = len(raw) - len(findings)
    if deduped_count > 0:
        lines.append(f"({deduped_count} duplicates/resolved excluded)")

    return "\n".join(lines)


def _adapt_prior_findings(preloaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt Go PriorFinding structs to the memory dict format expected by _filter_and_dedup."""
    adapted = []
    for pf in preloaded:
        adapted.append({
            "title": pf.get("title", ""),
            "severity": pf.get("severity", "info"),
            "category": pf.get("category", ""),
            "file_paths": [pf["file_path"]] if pf.get("file_path") else [],
            "remediation_status": pf.get("remediation_status", "open"),
        })
    return adapted
