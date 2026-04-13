"""HTTP client for the Vulture memory API.

Enables agents to search prior findings, store new memories, and retrieve
context for a codebase — reducing redundant analysis and saving tokens.
"""

import logging
import math
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable

# Safety margin for token estimates: code is ~3 chars/token (not 4), so a 1.2x
# multiplier prevents context overflow when packing prompts.
_SAFETY_MARGIN = max(1.0, float(os.environ.get("VULTURE_TOKEN_SAFETY_MARGIN", "1.2")))

import httpx

logger = logging.getLogger(__name__)

# Lazy-loaded tiktoken encoder for accurate OpenAI token counting.
_ENCODER: Any = None
_ENCODER_LOADED: bool = False
_ENCODER_LOCK = threading.Lock()


def _get_encoder() -> Any:
    """Lazily load tiktoken encoder matched to the active model.

    Uses cl200k_base for GPT-4o, cl100k_base for Claude/Gemini (closer
    approximation than gpt-4o's encoding). Returns None if unavailable.
    Thread-safe: uses a lock to prevent races during initialization.
    """
    global _ENCODER, _ENCODER_LOADED
    if _ENCODER_LOADED:
        return _ENCODER
    with _ENCODER_LOCK:
        if _ENCODER_LOADED:
            return _ENCODER
        try:
            import tiktoken
            model_key = os.environ.get("VULTURE_LLM_MODEL", "gpt-4o")
            try:
                _ENCODER = tiktoken.encoding_for_model(model_key)
            except KeyError:
                # Non-OpenAI models: cl100k_base is a closer approximation
                _ENCODER = tiktoken.get_encoding("cl100k_base")
        except Exception:
            logger.debug("tiktoken unavailable, using heuristic token counting")
        _ENCODER_LOADED = True
    return _ENCODER


def _provider_token_multiplier() -> float:
    """Return a provider-aware correction multiplier for tiktoken estimates.

    tiktoken (cl100k_base) is exact for OpenAI but underestimates for other
    providers due to different tokenizers:
    - OpenAI (gpt-4o): 1.0 (exact)
    - Anthropic (Claude): 1.1 (Claude tokenizer is ~10% more efficient)
    - Google (Gemini): 1.15 (Gemini tokenizer differs ~15%)
    - Ollama/local: 1.2 (varies widely, conservative estimate)
    """
    model_key = os.environ.get("VULTURE_LLM_MODEL", "gpt-4o")
    if model_key.startswith("gpt") or model_key == "gpt-4o":
        return 1.0
    if model_key.startswith("claude"):
        return 1.1
    if model_key.startswith("gemini"):
        return 1.15
    # Ollama / local models — tokenizers vary widely
    return 1.2

_BACKEND_URL = os.environ.get("VULTURE_BACKEND_URL", "http://backend:28080")
_TIMEOUT = 10.0


def _url(path: str) -> str:
    return f"{_BACKEND_URL}{path}"


def memory_search(query: str, limit: int = 20, mode: str = "hybrid") -> list[dict[str, Any]]:
    """Search memories by semantic text query.

    Args:
        query: Natural language search string.
        limit: Maximum results to return.
        mode: Search mode — 'hybrid' (vector + text, default), 'vector', or 'text'.

    Returns:
        List of matching memory dicts sorted by relevance.
    """
    try:
        params: dict[str, Any] = {"q": query, "limit": limit}
        if mode != "hybrid":
            params["mode"] = mode
        resp = httpx.get(
            _url("/api/memories/search"),
            params=params,
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
def _safe_int_env(name: str, default: int) -> int:
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float_env(name: str, default: float) -> float:
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


_MAX_CONTEXT_FINDINGS = _safe_int_env("VULTURE_MEMORY_MAX_FINDINGS", 25)
_HALF_LIFE_DAYS = max(1, _safe_int_env("VULTURE_MEMORY_HALF_LIFE_DAYS", 90))
_MMR_LAMBDA = _safe_float_env("VULTURE_MMR_LAMBDA", 0.8)
_MIN_CONFIDENCE = _safe_float_env("VULTURE_MIN_CONFIDENCE", 0.1)


def estimate_tokens(text: str) -> int:
    """Count tokens with provider-aware correction.

    Uses tiktoken (cl100k_base) as baseline, then applies a provider-specific
    multiplier: 1.0 for OpenAI (exact), 1.1 for Claude, 1.15 for Gemini,
    1.2 for Ollama/local. Falls back to ~4 chars/token when tiktoken is unavailable.
    """
    enc = _get_encoder()
    if enc is not None:
        try:
            raw = len(enc.encode(text, disallowed_special=()))
            return max(1, int(raw * _provider_token_multiplier()))
        except Exception:
            pass
    return max(1, len(text) // 4)


def safe_estimate_tokens(text: str) -> int:
    """Estimate tokens with provider correction and safety margin.

    Applies provider-aware multiplier then adds a 10% safety margin on top.
    Falls back to ~4 chars/token with _SAFETY_MARGIN when tiktoken is unavailable.
    """
    enc = _get_encoder()
    if enc is not None:
        try:
            raw = len(enc.encode(text, disallowed_special=()))
            return max(1, int(raw * _provider_token_multiplier() * 1.1))
        except Exception:
            pass
    return max(1, int(len(text) / 4 * _SAFETY_MARGIN))


def _staleness_weight(m: dict[str, Any]) -> float:
    """Return a 0.0-1.0 weight based on age using exponential decay.

    Uses half-life formula: weight = exp(-0.693 * age / half_life).
    At half_life days (default 90), weight = 0.5. Never reaches exactly 0.
    """
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
        if age_days < 0:
            return 1.0
        return math.exp(-0.693 * age_days / _HALF_LIFE_DAYS)
    except (ValueError, TypeError):
        return 0.5


def _confidence_weight(m: dict[str, Any]) -> float:
    """Return confidence score for a memory (0.0-1.0). Default 0.5 if missing."""
    return max(0.0, min(1.0, float(m.get("confidence_score", 0.5))))


def _norm(v: list[float]) -> float:
    """L2 norm of a vector."""
    return sum(x * x for x in v) ** 0.5


def _cosine_similarity_with_norms(
    a: list[float], b: list[float], norm_a: float, norm_b: float,
) -> float:
    """Cosine similarity using pre-computed norms to avoid redundant work."""
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (norm_a * norm_b)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two embedding vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return _cosine_similarity_with_norms(a, b, _norm(a), _norm(b))


def _similarity_with_norms(
    cand: dict[str, Any],
    selected_item: dict[str, Any],
    cand_tokens: set[str],
    sel_tokens: set[str],
    cand_norm: float,
    sel_norm: float,
) -> float:
    """Compute similarity using embeddings (preferred) or Jaccard (fallback).

    Uses pre-computed norms to avoid O(embed_dim) norm recomputation per pair.
    """
    cand_emb = cand.get("embedding")
    sel_emb = selected_item.get("embedding")
    if cand_emb and sel_emb and isinstance(cand_emb, list) and isinstance(sel_emb, list):
        return _cosine_similarity_with_norms(cand_emb, sel_emb, cand_norm, sel_norm)
    return _jaccard(cand_tokens, sel_tokens)


def _similarity(
    cand: dict[str, Any],
    selected_item: dict[str, Any],
    cand_tokens: set[str],
    sel_tokens: set[str],
) -> float:
    """Compute similarity (convenience wrapper that computes norms on the fly)."""
    cand_emb = cand.get("embedding")
    sel_emb = selected_item.get("embedding")
    cn = _norm(cand_emb) if isinstance(cand_emb, list) else 0.0
    sn = _norm(sel_emb) if isinstance(sel_emb, list) else 0.0
    return _similarity_with_norms(cand, selected_item, cand_tokens, sel_tokens, cn, sn)


def _prove_confidence_boost(m: dict[str, Any]) -> float:
    """Adjust confidence based on prove agent verification results.

    Returns a multiplier:
    - 1.3 for verified findings (prove confirmed)
    - 0.6 for not_reproduced findings (prove rejected)
    - 1.0 for unverified or inconclusive
    """
    prove_status = m.get("prove_status", "")
    if prove_status == "verified":
        return 1.3
    if prove_status == "not_reproduced":
        return 0.6
    return 1.0


def _best_mmr_candidate(
    candidates: list[dict[str, Any]],
    used: set[int],
    raw_scores: list[float],
    selected: list[dict[str, Any]],
    selected_tokens: list[set[str]],
    selected_norms: list[float],
    all_tokens: list[set[str]],
    all_norms: list[float],
    lam: float,
) -> int:
    """Find the candidate index with the highest MMR score.

    Uses pre-computed embedding norms to avoid O(candidates × selected × dim)
    norm recalculation. Returns -1 if no candidates remain.
    """
    remaining_scores = [raw_scores[i] for i in range(len(candidates)) if i not in used]
    max_remaining = max(remaining_scores) if remaining_scores else 1.0

    best_idx = -1
    best_mmr = -1.0
    for i, cand in enumerate(candidates):
        if i in used:
            continue
        relevance = raw_scores[i] / max_remaining if max_remaining > 0 else 0.0
        max_sim = 0.0
        for j, st in enumerate(selected_tokens):
            sim = _similarity_with_norms(
                cand, selected[j], all_tokens[i], st,
                all_norms[i], selected_norms[j],
            )
            if sim > max_sim:
                max_sim = sim
        mmr = lam * relevance - (1.0 - lam) * max_sim
        if mmr > best_mmr:
            best_mmr = mmr
            best_idx = i
    return best_idx


def _mmr_select(
    candidates: list[dict[str, Any]],
    max_count: int,
    lam: float = _MMR_LAMBDA,
) -> list[dict[str, Any]]:
    """Select diverse findings using Maximal Marginal Relevance.

    Greedily picks candidates that balance relevance (staleness * confidence
    * prove_boost) against diversity (embedding cosine similarity when
    available, falling back to title-based Jaccard dissimilarity).

    Pre-computes embedding norms once to avoid O(candidates² × embed_dim)
    repeated norm computation in the inner loop.

    Args:
        candidates: Pre-sorted list of memory dicts.
        max_count: Maximum items to select.
        lam: Lambda tradeoff (1.0 = pure relevance, 0.0 = pure diversity).

    Returns:
        Diverse subset of candidates.
    """
    if len(candidates) <= max_count:
        return candidates

    raw_scores = [
        _staleness_weight(m) * _confidence_weight(m) * _prove_confidence_boost(m)
        for m in candidates
    ]
    all_tokens = [_title_tokens(c.get("title", "")) for c in candidates]
    # Pre-compute embedding norms once — O(N × dim) instead of O(N² × dim)
    all_norms = [
        _norm(c["embedding"]) if isinstance(c.get("embedding"), list) else 0.0
        for c in candidates
    ]

    selected: list[dict[str, Any]] = []
    selected_tokens: list[set[str]] = []
    selected_norms: list[float] = []
    used: set[int] = set()

    for _ in range(max_count):
        best_idx = _best_mmr_candidate(
            candidates, used, raw_scores, selected, selected_tokens,
            selected_norms, all_tokens, all_norms, lam,
        )
        if best_idx < 0:
            break
        used.add(best_idx)
        selected.append(candidates[best_idx])
        selected_tokens.append(all_tokens[best_idx])
        selected_norms.append(all_norms[best_idx])

    return selected


def _title_tokens(title: str) -> set[str]:
    """Tokenize a title into lowercase word tokens for Jaccard comparison."""
    return {w for w in re.sub(r"[^\w\s]", "", title.lower()).split() if len(w) >= 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity coefficient between two token sets."""
    if not a and not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


def _normalize_title(title: str) -> str:
    """Normalize a finding title for fuzzy deduplication.

    Strips line numbers, file-specific details, and normalizes casing
    so that 'SQL Injection in login handler' and 'SQL Injection in auth handler'
    map to the same deduplicated concept.
    """
    t = title.strip().lower()
    # Remove line number references like "at line 42", "line 15" (anywhere in string)
    t = re.sub(r"\s*(at\s+)?line\s+\d+", "", t)
    # Remove "in <identifier>" phrases anywhere (not just at end)
    t = re.sub(r"\s+in\s+\S+(\s+\S+)?", " ", t)
    # Collapse whitespace
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _dedup_key(m: dict[str, Any]) -> str:
    """Create a deduplication key from normalized title and first file path."""
    title = _normalize_title(m.get("title", ""))
    paths = m.get("file_paths", [])
    first_path = paths[0].strip().lower() if paths else ""
    return f"{title}|{first_path}"


def _process_memory_edges(
    mid: str, mem_ids: set[str], union_fn: Callable[[str, str], None],
) -> None:
    """Fetch edges for a memory and union strongly-connected same_issue pairs."""
    edges = memory_get_edges(mid)
    for edge in edges:
        target = edge.get("target_id", "")
        source = edge.get("source_id", "")
        other = target if source == mid else source
        if other in mem_ids and edge.get("strength", 0.0) >= 0.75 and edge.get("relation_type", "") == "same_issue":
            union_fn(mid, other)


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

    parent: dict[str, str] = {mid: mid for mid in mem_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            if ra > rb:
                ra, rb = rb, ra
            parent[rb] = ra

    # Batch edge fetches concurrently (was serial, now parallel)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    ids_to_fetch = [m.get("id", "") for m in memories if m.get("id")][:max_fetch]
    with ThreadPoolExecutor(max_workers=min(len(ids_to_fetch), 4)) as pool:
        futures = {pool.submit(memory_get_edges, mid): mid for mid in ids_to_fetch}
        for future in as_completed(futures):
            mid = futures[future]
            try:
                edges = future.result()
                for edge in edges:
                    target = edge.get("target_id", "")
                    source = edge.get("source_id", "")
                    other = target if source == mid else source
                    if other in mem_ids and edge.get("strength", 0.0) >= 0.75 and edge.get("relation_type", "") == "same_issue":
                        union(mid, other)
            except Exception:
                continue

    return {mid: find(mid) for mid in mem_ids}


def _text_dedup(memories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter resolved findings and deduplicate by normalized title+file_path."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for m in memories:
        if m.get("remediation_status", "open") in _SKIP_STATUSES:
            continue
        key = _dedup_key(m)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique


def _edge_dedup(unique: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cluster semantically similar findings via embedding edges and deduplicate."""
    clusters = _fetch_edge_clusters(unique)
    if not clusters:
        return unique
    seen_clusters: set[str] = set()
    result: list[dict[str, Any]] = []
    for m in unique:
        mid = m.get("id", "")
        cluster_id = clusters.get(mid, mid) if mid else ""
        if cluster_id and cluster_id in seen_clusters:
            continue
        if cluster_id:
            seen_clusters.add(cluster_id)
        result.append(m)
    return result


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
    unique = _text_dedup(memories)

    if use_edges and len(unique) > 1:
        unique = _edge_dedup(unique)

    unique = [m for m in unique if _confidence_weight(m) >= _MIN_CONFIDENCE]

    unique.sort(key=lambda m: (
        _SEVERITY_RANK.get(m.get("severity", "info"), 4),
        -_staleness_weight(m) * _confidence_weight(m),
    ))

    return _mmr_select(unique[:max_count * 4], max_count)


def _resolve_context_limits(max_findings: int, max_chars: int) -> tuple[int, int]:
    """Auto-detect context limits from model when values are 0.

    Prior context budget scales logarithmically: 15% of context window
    up to 128K tokens, then diminishing returns via log2 for larger
    windows.  This prevents Gemini-pro (1M tokens) from getting an
    absurd 600K char allocation.

    Example values by model context window:
    - 32K tokens  → ~19,200 chars (15% × 4 chars/token)
    - 128K tokens → ~76,800 chars (15% × 4 chars/token)
    - 200K tokens → ~101,600 chars (76,800 base + log2 growth)
    - 1M tokens   → ~153,400 chars (76,800 base + log2(8) × 25,600)
    """
    if max_findings <= 0:
        from shared.llm.provider import get_max_findings
        max_findings = get_max_findings()
    if max_chars <= 0:
        from shared.llm.provider import get_context_window
        ctx = get_context_window()
        base = 128_000
        if ctx <= base:
            max_chars = int(ctx * 0.15 * 4)
        else:
            # Log-scale: base allocation + logarithmic growth beyond 128K
            base_chars = int(base * 0.15 * 4)  # ~76,800
            extra = int(math.log2(ctx / base) * base * 0.05 * 4)
            max_chars = base_chars + extra
    return max_findings, max_chars


def _format_finding_line(m: dict[str, Any]) -> str:
    """Format a single finding as a compact context line."""
    sev = m.get("severity", "info")[0].upper()
    title = m.get("title", "?")
    paths = m.get("file_paths", [])
    loc = paths[0].rsplit("/", 1)[-1] if paths else ""
    cat = m.get("category", "")
    cat_tag = f"[{cat}] " if cat else ""
    conf = _confidence_weight(m)
    conf_tag = f" c={conf:.1f}" if conf != 0.5 else ""
    prove = m.get("prove_status", "")
    prove_tag = f" [{prove}]" if prove else ""
    return (
        f" {sev}:{cat_tag}{title}"
        + (f" @{loc}" if loc else "")
        + conf_tag
        + prove_tag
    )


def build_prior_context(
    codebase_path: str,
    agent_type: str,
    preloaded: list[dict[str, Any]] | None = None,
    max_findings: int = 0,
    max_chars: int = 0,
) -> str:
    """Build a compact, deduplicated summary of prior findings for agent context.

    When ``preloaded`` is provided (from Go backend), uses those directly
    instead of re-fetching from the memory API — avoiding a redundant HTTP
    round-trip and saving latency.

    Args:
        codebase_path: Path to the codebase being audited.
        agent_type: Agent type to filter by.
        preloaded: Optional pre-loaded findings from Go backend (avoids re-fetch).
        max_findings: Max findings to include. 0 = auto-detect from model context.
        max_chars: Max chars for output. 0 = auto-detect from model context.

    Returns:
        Formatted text summary of prior findings, or empty string.
    """
    max_findings, max_chars = _resolve_context_limits(max_findings, max_chars)
    if preloaded:
        raw = _adapt_prior_findings(preloaded)
    else:
        raw = memory_get_context(codebase_path, agent_type, limit=30)
    if not raw:
        return ""

    use_edges = not bool(preloaded)
    findings = _filter_and_dedup(raw, max_count=max_findings, use_edges=use_edges)
    if not findings:
        return ""

    lines = [f"Known issues ({len(findings)}):"]
    for m in findings:
        lines.append(_format_finding_line(m))

    lines.append("Skip known issues. Report NEW findings only.")
    has_prove = any(m.get("prove_status") for m in findings)
    if has_prove:
        lines.append("LEARN: Boost confidence for patterns similar to [verified] findings.")
        lines.append("LEARN: Demote confidence for patterns similar to [not_reproduced] findings.")

    deduped_count = len(raw) - len(findings)
    if deduped_count > 0:
        lines.append(f"({deduped_count} duplicates/resolved excluded)")

    output = "\n".join(lines)
    if len(output) > max_chars:
        output = _truncate_prior_context(lines, findings, max_chars)

    return output


def _truncate_prior_context(
    lines: list[str], findings: list[dict[str, Any]], max_chars: int,
) -> str:
    """Truncate prior context lines to fit within char budget."""
    truncated = [lines[0]]
    total_len = len(lines[0])
    included = 0
    for line in lines[1:]:
        if total_len + len(line) + 1 > max_chars - 80:
            break
        total_len += len(line) + 1
        truncated.append(line)
        if line.startswith(" ") and ":" in line:
            included += 1
    remaining = len(findings) - included
    if remaining > 0:
        truncated.append(f"...and {remaining} more")
    truncated.append("Skip known issues. Report NEW findings only.")
    return "\n".join(truncated)


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
            "confidence_score": float(pf.get("confidence_score", 0.5)),
            "created_at": pf.get("created_at", ""),
            "prove_status": pf.get("prove_status", ""),
        })
    return adapted
