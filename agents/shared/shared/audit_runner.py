"""Shared audit runner with concurrent skill execution and file caching."""

import asyncio
import logging
import os
import re
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from shared.llm.errors import retry_skill
from shared.tools.file_scanner import scan_code_files, read_file_safe, is_entry_or_config, clear_caches
from pydantic import BaseModel

from shared.tools.memory_client import estimate_tokens, safe_estimate_tokens, _normalize_title
from shared.transport.event_emitter import AgUiEventEmitter

logger = logging.getLogger(__name__)


def _safe_int_env(name: str, default: int) -> int:
    """Read an integer from an env var, returning *default* on empty/missing/invalid."""
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        logger.warning("invalid_env_int var=%s value=%r using_default=%d", name, val, default)
        return default


# Max concurrent skill workers. Override via VULTURE_SKILL_WORKERS env var.
# Default caps at 8: skills are I/O-bound (regex on files), so 8 workers
# saturate disk I/O without excessive thread overhead.  For CPU-bound
# workloads or high-core machines, tune via VULTURE_SKILL_WORKERS.
_SKILL_WORKERS = _safe_int_env("VULTURE_SKILL_WORKERS", min(os.cpu_count() or 4, 8))

# Pre-compiled patterns for _parse_llm_findings (avoid per-call re.compile)
_LLM_JSON_FENCED_RE = re.compile(r"```json\s*(\[.*?\])\s*```", re.DOTALL)
_LLM_JSON_BARE_RE = re.compile(r"(\[\s*\{.*?\}\s*\])", re.DOTALL)
_LLM_JSON_PATTERNS = [_LLM_JSON_FENCED_RE, _LLM_JSON_BARE_RE]


class AuditFinding(BaseModel):
    severity: str = "info"
    category: str = "unknown"
    title: str = "Untitled finding"
    description: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    recommendation: str = ""
    check_id: str = ""


class AuditOutput(BaseModel):
    findings: list[AuditFinding]


SkillFn = Callable[[str], dict]

USE_LLM = os.environ.get("VULTURE_USE_LLM", "false").lower() == "true"

# Severity weights for score computation (shared across all agents).
_SEVERITY_WEIGHTS = {"critical": 10.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}

# Map LLM abbreviations/variants to canonical severity names.
_SEVERITY_ALIASES: dict[str, str] = {
    "c": "critical", "crit": "critical", "critical": "critical",
    "h": "high", "high": "high",
    "m": "medium", "med": "medium", "medium": "medium",
    "l": "low", "low": "low",
    "i": "info", "info": "info", "informational": "info",
}


def normalize_severity(raw: str) -> str:
    """Normalize severity string from LLM output to canonical lowercase form."""
    return _SEVERITY_ALIASES.get(raw.lower().strip(), "info")


def _emit_token_savings(
    emitter: AgUiEventEmitter,
    context: str,
    findings_total: int = 0,
    findings_skipped: int = 0,
    actual_input_tokens: int = 0,
    actual_output_tokens: int = 0,
    model: str | None = None,
    prior_lines: list[str] | None = None,
) -> str | None:
    """Build a token savings SSE event based on real deduplication metrics.

    Args:
        emitter: Event emitter instance.
        context: Prior context string.
        findings_total: Total findings (new + known).
        findings_skipped: Findings skipped because they matched prior context.
        actual_input_tokens: Real input tokens from LLM API response.
        actual_output_tokens: Real output tokens from LLM API response.
        model: Model key for cost estimation.
        prior_lines: Pre-split context lines. Avoids redundant split when
            the caller has already split the string.

    Returns:
        SSE event string, or None if no context.
    """
    if not context:
        return None
    ctx_tokens = estimate_tokens(context)
    ctx_lines = prior_lines if prior_lines is not None else context.split("\n")
    used = sum(1 for ln in ctx_lines if ln.startswith(" ") and ":" in ln)
    dupes = _extract_dupe_count(ctx_lines)

    # Estimate raw tokens: what we'd have used without memory context
    # Each skipped finding would have been ~65 tokens of LLM output + analysis
    if findings_skipped > 0:
        skipped_output_tokens = findings_skipped * 65
        raw_tokens = ctx_tokens + skipped_output_tokens
    else:
        # No findings were skipped — context was informational only, no savings
        raw_tokens = ctx_tokens

    # Compute cost if actual usage is available
    cost_usd = 0.0
    if actual_input_tokens > 0 or actual_output_tokens > 0:
        from shared.llm.provider import estimate_cost
        cost_usd = estimate_cost(actual_input_tokens, actual_output_tokens, model)

    return emitter.token_savings_event(
        ctx_tokens, raw_tokens, used, dupes,
        actual_input_tokens=actual_input_tokens,
        actual_output_tokens=actual_output_tokens,
        cost_usd=cost_usd,
    )


def _parse_known_titles(
    prior_context: str,
    prior_lines: list[str] | None = None,
) -> set[str]:
    """Extract normalized known issue titles from prior context string.

    Parses lines like ' C:[injection] SQL Injection @db.py' to extract 'sql injection'.

    Args:
        prior_context: Raw prior context string.
        prior_lines: Pre-split lines. Avoids redundant split when
            the caller has already split the string.
    """
    titles: set[str] = set()
    if not prior_context:
        return titles
    for line in (prior_lines if prior_lines is not None else prior_context.split("\n")):
        line = line.strip()
        if not line or line.startswith("Known") or line.startswith("Skip") or line.startswith("("):
            continue
        # Format: "C:[category] Title @file" or "C:Title @file"
        if ":" in line:
            after_sev = line.split(":", 1)[1]
            # Remove @file suffix
            if " @" in after_sev:
                after_sev = after_sev.rsplit(" @", 1)[0]
            # Remove [category] prefix if present
            if after_sev.startswith("["):
                bracket_end = after_sev.find("] ")
                if bracket_end >= 0:
                    after_sev = after_sev[bracket_end + 2:]
            titles.add(_normalize_title(after_sev))
    return titles


def _extract_dupe_count(lines: list[str]) -> int:
    """Extract duplicate count from prior context lines."""
    for ln in lines:
        if "duplicates" in ln and "excluded" in ln:
            m = re.search(r"\((\d+)", ln)
            if m:
                return int(m.group(1))
    return 0


def _check_context_budget(prompt_text: str, model: str | None = None) -> tuple[str | None, int]:
    """Check if prompt fits within model's context window.

    Returns ``(warning_or_none, estimated_tokens)`` so callers can reuse
    the token count instead of re-estimating.  The 80% threshold matches
    the truncation target in ``_truncate_prompt_to_budget``.
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window(model)
    estimated_tokens = safe_estimate_tokens(prompt_text)
    budget_pct = estimated_tokens / ctx_tokens if ctx_tokens > 0 else 1.0
    if budget_pct > 0.8:
        logger.warning(
            "context_budget_exceeded estimated=%d ctx_window=%d pct=%.0f%%",
            estimated_tokens, ctx_tokens, budget_pct * 100,
        )
        warning = (
            f"Prompt ({estimated_tokens} est. tokens) exceeds 80% of "
            f"context window ({ctx_tokens} tokens). Truncating to fit."
        )
        return warning, estimated_tokens
    return None, estimated_tokens


def _truncate_prompt_to_budget(
    prompt_text: str,
    model: str | None = None,
    estimated_tokens: int | None = None,
) -> str:
    """Truncate prompt by removing whole low-priority file blocks.

    Instead of slicing at an arbitrary character position (which could
    cut mid-function), this removes file blocks from the end (lowest
    priority) until the prompt fits within 80% of the context window.

    Args:
        prompt_text: The full prompt string.
        model: Optional model key for context window sizing.
        estimated_tokens: Pre-computed token count from ``_check_context_budget``.
            When provided, skips a redundant whole-prompt encode.
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window(model)
    target_tokens = int(ctx_tokens * 0.8)

    # Cheap pre-check: if caller already estimated and the prompt fits,
    # we're done before any encoding work.
    if estimated_tokens is not None and estimated_tokens <= target_tokens:
        return prompt_text

    # Split on file boundaries ("--- path ---") so we can remove whole files.
    file_marker = "\n\n--- "
    parts = prompt_text.split(file_marker)
    if len(parts) <= 1:
        # No file blocks — fall back to char truncation. Encode here only
        # if the caller didn't already.
        estimated = estimated_tokens if estimated_tokens is not None else safe_estimate_tokens(prompt_text)
        if estimated <= target_tokens:
            return prompt_text
        ratio = len(prompt_text) / max(estimated, 1)
        target_chars = int(target_tokens * ratio)
        return prompt_text[:target_chars] + "\n\n[... truncated to fit context window ...]"

    # parts[0] is everything before the first file; parts[1:] are file blocks.
    preamble = parts[0]
    file_blocks = [file_marker.lstrip("\n") + p for p in parts[1:]]

    # Per-block token counts — these dominate the encode work, but each
    # block is encoded exactly once (no O(N²) re-encoding inside the loop).
    preamble_tokens = safe_estimate_tokens(preamble)
    block_tokens = [safe_estimate_tokens(b) for b in file_blocks]
    separator_tokens = safe_estimate_tokens("\n\n")
    running_total = preamble_tokens + sum(block_tokens) + separator_tokens * len(block_tokens)

    # Reuse the per-block sum as our total estimate (avoid encoding the
    # whole prompt a second time just to log it). Only meaningful when
    # the caller didn't already provide estimated_tokens.
    if estimated_tokens is None:
        estimated_tokens = running_total

    # If the prompt was within budget after all (caller's pre-estimate
    # was conservative) we can return unchanged.
    if running_total <= target_tokens:
        return prompt_text

    # If preamble alone exceeds budget, truncate it directly.
    if preamble_tokens > target_tokens:
        ratio = len(preamble) / max(preamble_tokens, 1)
        target_chars = int(target_tokens * ratio)
        return preamble[:target_chars] + "\n\n[... truncated to fit context window ...]"

    # Remove file blocks from the end (lowest priority) until budget met.
    while file_blocks and running_total > target_tokens:
        running_total -= block_tokens.pop() + separator_tokens
        removed = file_blocks.pop()
        logger.debug("truncation_removed_file block_len=%d", len(removed))

    if not file_blocks:
        logger.warning(
            "prompt_truncation_stripped_all_files preamble_tokens=%d target=%d",
            preamble_tokens, target_tokens,
        )
    result = preamble + ("\n\n" + "\n\n".join(file_blocks) if file_blocks else "")
    removed_count = len(parts) - 1 - len(file_blocks)
    if removed_count > 0:
        result += f"\n\n[... {removed_count} file(s) removed to fit context window ...]"
    logger.info("prompt_truncated original=%d target=%d files_removed=%d", estimated_tokens, target_tokens, removed_count)
    return result


_MAX_SOURCE_CHARS = _safe_int_env("VULTURE_MAX_SOURCE_CHARS", 400000)


def _get_max_source_chars(model: str | None = None) -> int:
    """Compute max source chars from the active model's context window.

    Uses ``get_context_window()`` (env override > model lookup > 32K default).
    The OpenAI Agents SDK adds significant overhead (tool schemas, structured
    output schema, system instructions) — typically 3-5K tokens.  We reserve
    50% of context for source code at ~3 chars per token (code is token-dense).

    The result is capped at ``_MAX_SOURCE_CHARS`` (default 400K, configurable
    via ``VULTURE_MAX_SOURCE_CHARS``) to prevent unbounded memory usage with
    large-context models like Gemini (1M+ tokens).

    Args:
        model: Optional model key. Defaults to VULTURE_LLM_MODEL env.
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window(model)
    # Scale source allocation: small models need more headroom for output + SDK overhead.
    source_fraction = 0.35 if ctx_tokens <= 32_000 else 0.5
    # ~3 chars per token for code. Safety margin applied later by safe_estimate_tokens().
    return min(max(2000, int(ctx_tokens * source_fraction * 3)), _MAX_SOURCE_CHARS)


def _safe_stat_size(p: Path) -> int:
    """Get file size with a single syscall; return 0 on any OS error."""
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _safe_rel(fpath: Path, source_path: str) -> str:
    """Compute relative path safely, falling back to str(fpath)."""
    try:
        return str(fpath.relative_to(source_path))
    except ValueError:
        return str(fpath)


def _prioritize_files(
    files: list,
    source_path: str,
    skill_findings: list[dict] | None = None,
) -> list:
    """Sort files into priority tiers for LLM context packing.

    Tier 1: Files that appear in skill_findings (highest signal).
    Tier 2: Entry points and config files (structural importance).
    Tier 3: Remaining files, sorted by size ascending (smaller = more likely focused).

    Args:
        files: List of Path objects from scan_code_files.
        source_path: Root directory (used for relative path matching).
        skill_findings: Optional skill findings to prioritize by.

    Returns:
        Reordered list of Path objects.
    """
    finding_paths: set[str] = set()
    if skill_findings:
        for f in skill_findings:
            fp = f.get("file_path", "")
            if fp:
                finding_paths.add(fp)
                # Also store relative form for matching
                if fp.startswith(source_path):
                    rel = fp[len(source_path):].lstrip("/")
                    finding_paths.add(rel)

    tier1: list = []
    tier2: list = []
    tier3: list = []

    for fpath in files:
        fstr = str(fpath)
        rel = _safe_rel(fpath, source_path)
        if fstr in finding_paths or rel in finding_paths:
            tier1.append(fpath)
        elif is_entry_or_config(Path(fpath) if not isinstance(fpath, Path) else fpath):
            tier2.append(fpath)
        else:
            tier3.append(fpath)

    # Sort tier3 by file size ascending (smaller files first)
    # Pre-compute stat results to avoid repeated syscalls during sort comparisons
    size_map = {p: _safe_stat_size(p) for p in tier3}
    tier3.sort(key=lambda p: size_map[p])

    return tier1 + tier2 + tier3


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping (start, end) ranges into non-overlapping spans."""
    if not ranges:
        return []
    ranges.sort()
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _extract_file_snippet(
    content: str,
    findings: list[dict],
    rel_path: str,
    context_lines: int = 10,
) -> str:
    """Extract relevant code snippets from a file based on finding line ranges.

    Args:
        content: Full file content.
        findings: Findings that reference this file.
        rel_path: Relative path for matching.
        context_lines: Lines of context around each finding.

    Returns:
        Snippet text covering all finding ranges, or full content if no lines.
    """
    lines = content.split("\n")
    ranges: list[tuple[int, int]] = []
    for f in findings:
        fp = f.get("file_path", "")
        if not fp.endswith(rel_path) and rel_path not in fp:
            continue
        ls = f.get("line_start", 0)
        le = f.get("line_end", 0) or ls
        if ls > 0:
            ranges.append((max(0, ls - 1 - context_lines), min(len(lines), le + context_lines)))
    if not ranges:
        return content  # no line info — include full file
    # When all findings point at line 1 (or 0), include first 30 lines
    # for better LLM context instead of just ±10 around line 1.
    all_near_top = all(s == 0 for s, _e in ranges)
    if all_near_top:
        top_lines = min(30, len(lines))
        numbered = "\n".join(f"{i + 1}: {lines[i]}" for i in range(top_lines))
        return numbered
    parts: list[str] = []
    for start, end in _merge_ranges(ranges):
        numbered = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, min(end, len(lines))))
        parts.append(numbered)
    return "\n...\n".join(parts)


def _pack_files(
    ordered_files: list,
    source_path: str,
    max_chars: int,
    skill_findings: list[dict] | None = None,
) -> tuple[str, list[str]]:
    """Pack files into a formatted string within the character budget.

    Uses snippet extraction for files with findings (sends only relevant
    code + context lines). Includes full content for entry points/configs.

    Args:
        ordered_files: Priority-ordered list of Path objects.
        source_path: Root directory for relative path computation.
        max_chars: Maximum total characters to include.
        skill_findings: Optional findings for snippet extraction.

    Returns:
        Tuple of (formatted string, list of relative paths included).
    """
    parts: list[str] = []
    included_paths: list[str] = []
    total = 0
    # Pre-group findings by normalized path suffix to avoid O(files×findings)
    findings_by_path: dict[str, list[dict]] = {}
    if skill_findings:
        for f in skill_findings:
            fp = f.get("file_path", "")
            if fp:
                findings_by_path.setdefault(fp, []).append(f)
    for fpath in ordered_files:
        content = read_file_safe(fpath)
        if content is None or not content.strip():
            continue
        rel = _safe_rel(fpath, source_path)
        # Use snippets for files with findings to save tokens
        if findings_by_path:
            file_findings = findings_by_path.get(rel, [])
            if not file_findings:
                # Fallback: check if any key ends with this rel path
                file_findings = [
                    f for fp_key, flist in findings_by_path.items()
                    for f in flist
                    if fp_key.endswith(rel)
                ]
            if file_findings:
                content = _extract_file_snippet(content, file_findings, rel)
        header = f"--- {rel} ---"
        entry_len = len(header) + 1 + len(content) + 2
        if total + entry_len > max_chars:
            continue
        parts.append(f"{header}\n{content}")
        included_paths.append(rel)
        total += entry_len

    if not parts:
        return "", []
    return "\n\n".join(parts), included_paths


def _build_source_context(
    source_path: str,
    max_chars: int = 0,
    skill_findings: list[dict] | None = None,
    model: str | None = None,
) -> str:
    """Pre-read source files and format them for inline LLM prompt inclusion.

    Local models (Ollama, LM Studio) often lack function-calling support,
    so they cannot use tools to read files.  This function scans the source
    tree and embeds file contents directly in the prompt so the LLM can
    analyze the code without tool use.

    Files are prioritized: skill-finding files first, then entry points/config,
    then remaining files sorted by size ascending.  Files with skill findings
    use snippet extraction (finding lines + context) instead of full content.

    Args:
        source_path: Root directory of the source code.
        max_chars: Maximum total characters of source code to include.
        skill_findings: Optional skill findings for file prioritization and snippets.
        model: Optional model key for context window sizing.

    Returns:
        Formatted string with file contents, or empty string if no files found.
    """
    if max_chars <= 0:
        max_chars = _get_max_source_chars(model)
    files = scan_code_files(source_path)
    if not files:
        return ""

    ordered = _prioritize_files(files, source_path, skill_findings)
    text, _paths = _pack_files(ordered, source_path, max_chars, skill_findings)
    return text


def _dedup_key(f: dict) -> tuple[str, str]:
    """Build dedup key preferring check_id over normalized title."""
    cid = f.get("check_id", "")
    fp = f.get("file_path", "")
    if cid:
        return (cid, fp)
    return (_normalize_title(f.get("title", "")), fp)


def _deduplicate_findings(base: list[dict], new: list[dict]) -> list[dict]:
    """Return findings from ``new`` not already in ``base``.

    Uses ``check_id`` + ``file_path`` when check_id is present (stable,
    hierarchical). Falls back to normalized title + file_path otherwise.

    Args:
        base: Existing findings (e.g. from skill scan).
        new: New findings (e.g. from LLM pass) to filter.

    Returns:
        Subset of ``new`` that don't duplicate any entry in ``base``.
    """
    seen: set[tuple[str, str]] = set()
    for f in base:
        seen.add(_dedup_key(f))

    unique: list[dict] = []
    for f in new:
        key = _dedup_key(f)
        if key not in seen:
            unique.append(f)
            seen.add(key)
    return unique


def _assign_finding_id(finding: dict[str, Any], audit_id: str, index: int) -> None:
    """Assign a deterministic finding ID matching the backend's
    `generateFindingID(auditID, title, file_path, index)` hash.

    Mutates `finding` in place. Idempotent: if `finding["id"]` is
    already set, leaves it untouched. Feature 0046 (issue #1).
    """
    if finding.get("id"):
        return
    import hashlib
    raw = f"{audit_id}:{finding.get('title', '')}:{finding.get('file_path', '')}:{index}"
    finding["id"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def run_combined_audit(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_map: dict[str, SkillFn],
    domain_label: str = "categories",
    prior_context: str = "",
    skill_tools: list[Any] | None = None,
    instructions: str | None = None,
    model: str | None = None,
    use_llm: bool | None = None,
    validate_use_llm: bool | None = None,
) -> Generator[str, None, None]:
    """Run skills first (full coverage), then optionally LLM (deeper analysis).

    Always runs pattern-matching skills across all files. When LLM mode
    is enabled and ``skill_tools``/``instructions`` are provided, performs a
    second LLM pass on the subset of files that fits in the context window.
    LLM findings are deduplicated against skill findings so only genuinely
    new issues are added.

    Args:
        run_id: Unique run identifier.
        source_path: Path to source code root.
        categories: Ordered list of skill/category keys to run.
        skill_map: Mapping from category key to skill function.
        domain_label: Label for summary text.
        prior_context: Optional prior findings context from memory bank.
        skill_tools: LLM agent tools (required for LLM pass).
        instructions: LLM agent system prompt (required for LLM pass).
        model: Optional model preference for LLM pass.
        use_llm: Per-request LLM toggle. ``None`` falls back to the
            ``VULTURE_USE_LLM`` env var (module-level ``USE_LLM``).

    Yields:
        SSE-formatted event strings.
    """
    effective_use_llm = use_llm if use_llm is not None else USE_LLM

    clear_caches()  # Ensure stale file contents don't leak across audit runs
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()
    logger.info("audit_start run_id=%s source=%s categories=%s use_llm=%s",
                run_id, source_path, categories, effective_use_llm)

    # Emit prior findings context if available
    if prior_context:
        yield emitter.text_message(prior_context)

    # --- Phase 1: Skill-based pattern matching (always runs) ---
    scan_code_files(source_path)  # warm file cache

    skill_findings: list[dict] = []
    total = len(categories)
    completed = 0

    pool_workers = min(total, _SKILL_WORKERS)
    # Manual pool management (no `with` / no CM-driven shutdown-with-wait)
    # so that generator GC — which can fire from a worker thread when an
    # SSE consumer disconnects mid-stream — doesn't trigger
    # `RuntimeError: cannot join current thread` via Executor.__exit__.
    pool = ThreadPoolExecutor(max_workers=pool_workers)
    try:
        futures = {}
        for cat in categories:
            fn = skill_map.get(cat)
            if fn is None:
                continue
            futures[pool.submit(retry_skill, fn, source_path)] = cat

        for future in as_completed(futures):
            cat = futures[future]
            yield emitter.text_message(f"Analyzing {cat} patterns...")

            try:
                result = future.result()
            except Exception as exc:
                yield emitter.text_message(f"Skill {cat} failed: {str(exc)[:200]}")
                completed += 1
                yield emitter.progress_event(
                    files_analyzed=completed,
                    total_files=total,
                    findings_count=len(skill_findings),
                )
                continue

            findings = result.get("findings", [])
            # Feature 0046 issue #1: assign deterministic IDs at emission
            # time so L5 streaming `validation_update` events can later
            # reference the same finding via id. The backend's
            # `extractDeltaFindings` only auto-generates IDs when the
            # incoming finding has an empty id field — non-empty IDs are
            # preserved verbatim. Hash matches backend's
            # `generateFindingID(auditID, title, file_path, index)`.
            for finding in findings:
                _assign_finding_id(finding, run_id, len(skill_findings))
                skill_findings.append(finding)
                yield emitter.finding_event(**finding)

            completed += 1
            yield emitter.progress_event(
                files_analyzed=completed,
                total_files=total,
                findings_count=len(skill_findings),
            )
    finally:
        # If we're being GC'd from inside a worker thread (the typical
        # disconnect path), wait=True would join that very thread.
        # Use wait=False to skip the join; Python's thread teardown
        # still cleans up daemon pool threads on process exit.
        try:
            pool.shutdown(wait=True)
        except RuntimeError:
            pool.shutdown(wait=False)

    logger.info("skill_phase_done run_id=%s findings=%d", run_id, len(skill_findings))

    # --- Phase 2: LLM enhancement (optional) ---
    llm_new_findings: list[dict] = []
    actual_input_tokens = 0
    actual_output_tokens = 0
    if effective_use_llm and skill_tools and instructions:
        yield emitter.text_message("Enhancing with LLM analysis...")
        logger.info("llm_phase_start run_id=%s", run_id)

        # Mechanism 6: Build source context once, pass through to LLM collector
        source_context = _build_source_context(source_path, skill_findings=skill_findings, model=model)
        file_count = source_context.count("\n--- ") + (
            1 if source_context.startswith("--- ") else 0
        )
        if source_context:
            yield emitter.text_message(
                f"Loaded {file_count} file(s) into LLM context."
            )

        llm_findings, llm_error, actual_input_tokens, actual_output_tokens = _collect_llm_findings(
            run_id=run_id,
            source_path=source_path,
            categories=categories,
            skill_tools=skill_tools,
            instructions=instructions,
            domain_label=domain_label,
            prior_context=prior_context,
            model=model,
            skill_findings=skill_findings,
            source_context=source_context,
        )
        if llm_error:
            yield emitter.text_message(llm_error)
        llm_new_findings = _deduplicate_findings(skill_findings, llm_findings)

        if llm_new_findings:
            yield emitter.text_message(
                f"LLM discovered {len(llm_new_findings)} additional finding(s)."
            )
            # Continue indexing from the end of skill_findings so IDs
            # remain unique across phases. (Feature 0046 issue #1.)
            base_idx = len(skill_findings)
            for offset, finding in enumerate(llm_new_findings):
                _assign_finding_id(finding, run_id, base_idx + offset)
                yield emitter.finding_event(**finding)
        elif not llm_error:
            yield emitter.text_message("LLM analysis complete — no additional findings.")

    # --- Combine & emit final result ---
    all_findings = skill_findings + llm_new_findings

    # --- Validate stage (feature 0045) ---------------------------
    # Annotates each finding with validation_status + validation_confidence
    # + per-layer check trail. V6: never deletes findings (length-preserving).
    # Disabled via VULTURE_DISABLE_VALIDATE=true env var.
    _validate_enabled = (
        os.environ.get("VULTURE_DISABLE_VALIDATE", "").lower() != "true"
    )
    if _validate_enabled:
        try:
            import queue as _queue
            import threading as _threading
            from shared.validate import validate as _validate
            from shared.validate import ValidateConfig as _ValidateConfig

            # L5 streaming (feature 0046 D6): use a thread-safe queue
            # to bridge from validate's callback-style emit_batch into
            # the generator's yield-based SSE flow.
            _stream_q: "_queue.Queue[list[dict] | None]" = _queue.Queue()

            def _on_validation_update(batch: list[dict]) -> None:
                # Strip non-serialisable / large keys before queuing.
                light = [
                    {
                        "id": f.get("id", ""),
                        "validation_status": f.get("validation_status", ""),
                        "validation_confidence": f.get("validation_confidence", 0.0),
                        "validation": f.get("validation", {}),
                    }
                    for f in batch
                ]
                _stream_q.put(light)

            # Per-request override wins; falls back to env (D4 config surface).
            if validate_use_llm is not None:
                _l5_enabled = bool(validate_use_llm)
            else:
                _l5_enabled = (
                    os.environ.get("VULTURE_USE_VALIDATE_LLM", "").lower() == "true"
                )
            _vcfg = _ValidateConfig(
                compliance_mode=(
                    os.environ.get("VULTURE_COMPLIANCE_MODE", "").lower() == "true"
                ),
                enable_l1=True,
                enable_l2=True,
                enable_l5=_l5_enabled,
            )

            _v_result_box: list = [None]
            _v_exc_box: list = [None]

            def _run_validate_in_thread() -> None:
                try:
                    _v_result_box[0] = _validate(
                        all_findings, source_path=source_path,
                        audit_id=run_id,
                        config=_vcfg,
                        emit_validation_update=_on_validation_update if _l5_enabled else None,
                    )
                except Exception as e:        # noqa: BLE001 — handled by outer try
                    _v_exc_box[0] = e
                finally:
                    _stream_q.put(None)        # sentinel

            _vthread = _threading.Thread(target=_run_validate_in_thread, daemon=True)
            _vthread.start()

            # Drain the queue: emit one validation_update SSE event per
            # batch as L5 produces them. The sentinel `None` means
            # validate finished.
            while True:
                batch = _stream_q.get()
                if batch is None:
                    break
                yield emitter.validation_update_event(batch)
            _vthread.join()
            if _v_exc_box[0] is not None:
                raise _v_exc_box[0]
            v_result = _v_result_box[0]

            for ev_text in v_result.event_texts:
                yield emitter.text_message(ev_text)
            all_findings = v_result.findings
            for parent in v_result.rollups:
                yield emitter.finding_event(**parent)
            all_findings = all_findings + v_result.rollups
        except Exception as ve:
            logger.warning("validate stage raised %s; continuing without validation", ve)
            yield emitter.text_message(
                f"[validate] stage failed: {type(ve).__name__}; "
                f"findings emitted without validation_status"
            )
    # --- End validate stage --------------------------------------

    # Split prior_context once and pass to all consumers to avoid redundant splits
    prior_lines = prior_context.split("\n") if prior_context else []

    # Dedup stats against prior context (informational only)
    known_titles = _parse_known_titles(prior_context, prior_lines=prior_lines)
    if known_titles:
        skipped = sum(
            1 for f in all_findings
            if _normalize_title(f.get("title", "")) in known_titles
        )
    else:
        skipped = 0

    if prior_lines:
        used_count = sum(1 for ln in prior_lines if ln.startswith(" ") and ":" in ln)
        dupe_count = _extract_dupe_count(prior_lines)
        yield emitter.dedup_stats_event(
            findings_deduped=skipped,
            prior_findings_used=used_count,
            duplicates_removed=dupe_count,
        )

    # Mechanism 7: Emit token savings whenever prior context exists
    # (even with 0 actual tokens in skill-only mode — the event handles it gracefully)
    if prior_lines:
        savings_event = _emit_token_savings(
            emitter, prior_context,
            findings_total=len(all_findings),
            findings_skipped=skipped,
            actual_input_tokens=actual_input_tokens,
            actual_output_tokens=actual_output_tokens,
            model=model,
            prior_lines=prior_lines,
        )
        if savings_event:
            yield savings_event

    score = compute_score(all_findings, total)
    summary = build_summary(all_findings, categories, domain_label)
    logger.info("audit_done run_id=%s total_findings=%d score=%.1f", run_id, len(all_findings), score)
    yield emitter.result_event(findings=all_findings, summary=summary, score=score)
    yield emitter.run_finished()


def _collect_llm_findings(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    source_context: str = "",
) -> tuple[list[dict], str | None, int, int]:
    """Run the LLM audit and collect findings (without SSE wrapping).

    Returns (findings, error_message, actual_input_tokens, actual_output_tokens).
    error_message is None on success.
    """
    return asyncio.run(
        _collect_llm_findings_async(
            run_id, source_path, categories, skill_tools,
            instructions, domain_label, prior_context, model,
            skill_findings=skill_findings,
            source_context=source_context,
        )
    )


def _build_llm_prompt(
    source_path: str,
    categories: list[str],
    domain_label: str,
    source_context: str,
    prior_context: str,
    source_in_system: bool = False,
) -> str:
    """Assemble the LLM audit prompt from source context and prior findings.

    Args:
        source_in_system: If True, source code is embedded in the agent's
            instructions (system message) for Anthropic prompt caching.
            The user prompt then omits the source code to avoid duplication.
    """
    parts = [
        f"Audit the source code at: {source_path}",
        f"Focus on these {domain_label}: {', '.join(categories)}",
        "For each issue found, provide severity, category, title, description,",
        "file_path, line_start, line_end, and recommendation.",
    ]
    # Place prior context before source code so the LLM sees known issues
    # early and primes LLM attention.
    if prior_context:
        parts.append(f"\nContext from prior audits:\n{prior_context}")
    if source_in_system:
        parts.append("\nAnalyze the source code provided in the system instructions.")
    elif source_context:
        parts.append(
            "\nThe source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n"
        )
        parts.append(source_context)
    else:
        parts.append("Use the available tools to analyze the code thoroughly.")
    return "\n".join(parts)


def _extract_token_usage(result: Any, model: str | None = None) -> tuple[int, int]:
    """Extract (input_tokens, output_tokens) from an Agent SDK result.

    Warns when token usage is (0,0) — common with Ollama/local models that
    don't populate the usage fields. This makes silent data loss visible.
    """
    actual_input = 0
    actual_output = 0
    try:
        if hasattr(result, "raw_responses"):
            for resp in result.raw_responses:
                usage = getattr(resp, "usage", None)
                if not usage:
                    continue
                # Use whichever field set is populated (mutually exclusive)
                pt = getattr(usage, "prompt_tokens", 0) or 0
                ct = getattr(usage, "completion_tokens", 0) or 0
                it = getattr(usage, "input_tokens", 0) or 0
                ot = getattr(usage, "output_tokens", 0) or 0
                if pt or ct:
                    actual_input += pt
                    actual_output += ct
                elif it or ot:
                    actual_input += it
                    actual_output += ot
    except Exception:
        logger.debug("token_usage_extraction_failed", exc_info=True)
    if actual_input == 0 and actual_output == 0:
        from shared.llm.provider import is_ollama_model
        model_key = model or os.environ.get("VULTURE_LLM_MODEL", "")
        if is_ollama_model(model_key) or _CUSTOM_BASE_URL:
            logger.warning(
                "token_usage_zero model=%s hint=local_models_may_not_report_usage",
                model_key,
            )
    return actual_input, actual_output


# Check for custom base URL (LM Studio, vLLM, etc.)
_CUSTOM_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")


def _parse_llm_result(result: Any) -> list[dict]:
    """Parse findings from an Agent SDK result, handling structured and raw output."""
    final_output = getattr(result, "final_output", None)
    if isinstance(final_output, AuditOutput):
        findings = [f.model_dump() for f in final_output.findings]
        for f in findings:
            f["severity"] = normalize_severity(f.get("severity", "info"))
        return findings
    return _parse_llm_findings(str(final_output) if final_output is not None else "")


async def _collect_llm_findings_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    source_context: str = "",
) -> tuple[list[dict], str | None, int, int]:
    """Async helper: run LLM agent and return (findings, error, input_tokens, output_tokens)."""
    from agents import Agent, ModelSettings, Runner
    from shared.llm.provider import get_model_with_fallback, get_model_settings, uses_custom_endpoint
    from shared.tools.file_reader import read_file_tool
    from shared.tools.file_lister import list_files_tool
    from shared.tools.pattern_matcher import search_pattern_tool

    resolved_model = get_model_with_fallback(model)

    if not source_context:
        source_context = _build_source_context(source_path, skill_findings=skill_findings, model=model)
    # Only register file tools when source is NOT embedded inline — avoids
    # redundant tool-call round trips that waste tokens re-reading files.
    if source_context:
        all_tools = list(skill_tools)
    else:
        all_tools = list(skill_tools) + [read_file_tool, list_files_tool, search_pattern_tool]

    source_in_system = "anthropic" in resolved_model and bool(source_context)
    prompt_text = _build_llm_prompt(
        source_path, categories, domain_label, source_context, prior_context,
        source_in_system=source_in_system,
    )

    # Truncate BEFORE computing max_output so the token budget is based on
    # the final prompt size, not the pre-truncation size.
    budget_warn, precomputed_tokens = _check_context_budget(prompt_text, model)
    if budget_warn:
        logger.warning("context_guard run_id=%s: %s", run_id, budget_warn)
        prompt_text = _truncate_prompt_to_budget(prompt_text, model, estimated_tokens=precomputed_tokens)

    from shared.llm.provider import get_context_window
    env_max_output = _safe_int_env("VULTURE_LLM_MAX_OUTPUT_TOKENS", 16384)
    ctx_window = get_context_window(model)
    prompt_tokens = safe_estimate_tokens(prompt_text)
    # SDK overhead: tool definitions (~150 tokens each) + AuditOutput schema (~600 tokens).
    sdk_overhead = max(512, 150 * len(all_tools) + 600)
    max_output = min(env_max_output, max(2048, ctx_window - prompt_tokens - sdk_overhead))
    model_settings_dict = get_model_settings(model)
    model_settings_dict["max_tokens"] = max_output

    # For Anthropic models, embed source code in the system message (instructions)
    # so it benefits from prompt caching across repeated audits of the same codebase.
    # LiteLLM auto-injects cache_control breakpoints on system messages when the
    # anthropic-beta header is present (see get_model_settings).
    if "anthropic" in resolved_model and source_context:
        augmented_instructions = (
            f"{instructions}\n\n"
            "The source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n\n"
            f"{source_context}"
        )
    else:
        augmented_instructions = instructions

    # Custom OpenAI-compatible endpoints (vLLM, LM Studio, etc.) may not
    # support structured output (response_format with JSON schema).  Skip
    # output_type and rely on prompt-based JSON + _parse_llm_findings fallback.
    use_structured = not uses_custom_endpoint()
    if not use_structured:
        augmented_instructions += (
            "\n\nIMPORTANT: Return findings as a JSON array. Each object must have: "
            "severity, category, title, description, file_path, line_start, line_end, recommendation. "
            "Wrap the array in ```json ... ``` fences."
        )

    agent_kwargs: dict[str, Any] = {
        "name": "auditor",
        "instructions": augmented_instructions,
        "tools": all_tools,
        "model": resolved_model,
        "model_settings": ModelSettings(**model_settings_dict),
    }
    if use_structured:
        agent_kwargs["output_type"] = AuditOutput

    agent = Agent(**agent_kwargs)

    from shared.llm.errors import classify_llm_error, retry_llm_call
    from shared.llm.loop_guard import LoopDetectedError, create_loop_guard_hooks

    hooks, _detector = create_loop_guard_hooks()

    async def _run_agent():
        kwargs: dict[str, Any] = {}
        if hooks is not None:
            try:
                from agents import RunConfig  # type: ignore[import-untyped]
                kwargs["run_config"] = RunConfig(hooks=hooks)  # type: ignore[call-arg]
            except (ImportError, TypeError):
                logger.warning("loop_guard_hooks_disabled: SDK version does not support RunConfig(hooks=)")
        return await Runner.run(agent, input=prompt_text, **kwargs)

    from shared.llm.cooldown import cooldown_manager

    try:
        result = await retry_llm_call(_run_agent, max_attempts=3)
        actual_input, actual_output = _extract_token_usage(result, model=model)
        findings = _parse_llm_result(result)
        cooldown_manager.record_success(resolved_model)
    except LoopDetectedError as exc:
        # Loop is an agent reasoning failure, not a model failure — don't cool down the model.
        logger.info("loop_detected run_id=%s: %s (not recording model cooldown)", run_id, exc)
        return [], f"LLM agent aborted: {exc}", 0, 0
    except Exception as exc:
        kind = classify_llm_error(exc)
        cooldown_manager.record_failure(resolved_model, error_kind=kind.value)
        logger.warning("llm_failed kind=%s error=%s", kind.value, str(exc)[:200])
        return [], f"LLM analysis failed ({kind.value}): {str(exc)[:200]}", 0, 0

    return findings, None, actual_input, actual_output


def compute_score(findings: list[dict], total_items: int) -> float:
    """Compute compliance score based on findings.

    Uses a logarithmic decay curve so scores degrade gradually:
    - 0 findings = 100%
    - A few low/medium findings = 70-90%
    - Multiple high findings = 40-60%
    - Many critical findings = 10-30%
    """
    if not findings:
        return 100.0
    penalty = sum(_SEVERITY_WEIGHTS.get(normalize_severity(f.get("severity", "info")), 0.0) for f in findings)
    scale = max(30.0, total_items * 10.0)
    return round(max(5.0, 100.0 / (1.0 + penalty / scale)), 1)


def build_summary(findings: list[dict], categories: list[str], domain_label: str) -> str:
    """Build a human-readable summary."""
    count = len(categories)
    if not findings:
        return f"No issues found across {count} {domain_label}."
    return f"Found {len(findings)} issue(s) across {count} {domain_label}."



def _parse_llm_findings(output: str) -> list[dict]:
    """Extract structured findings from LLM text output.

    Attempts to parse JSON arrays from the response. Falls back to
    empty list if parsing fails.
    """
    import json

    for pattern in _LLM_JSON_PATTERNS:
        match = pattern.search(output)
        if match:
            try:
                findings = json.loads(match.group(1))
                if isinstance(findings, list):
                    return [_normalize_finding(f) for f in findings if isinstance(f, dict)]
            except json.JSONDecodeError:
                continue
    return []


def _normalize_finding(raw: dict) -> dict:
    """Normalize a finding dict to expected schema."""
    return {
        "severity": normalize_severity(raw.get("severity", "info")),
        "category": raw.get("category", "unknown"),
        "title": raw.get("title", "Untitled finding"),
        "description": raw.get("description", ""),
        "file_path": raw.get("file_path", ""),
        "line_start": raw.get("line_start", 0),
        "line_end": raw.get("line_end", 0),
        "recommendation": raw.get("recommendation", ""),
    }
