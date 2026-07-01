"""Shared audit runner with concurrent skill execution and file caching."""

import asyncio
import contextvars
import logging
import os
import re
import time
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from shared.cancellation import (
    current_audit_deadline,
    current_cancel_token,
    set_audit_deadline,
)

from shared.llm.errors import retry_skill
from shared.tools.file_scanner import scan_code_files, read_file_safe, is_entry_or_config, clear_caches
from shared.tools.snippet import extract_snippet
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
    # Feature 0057 P0.1: code window read from the source, used to ground the
    # L5 judge (R4) so it never judges blind. Populated centrally by
    # _attach_code_snippet() just before validation, then egresses into the SSE
    # ``result`` event and the pre-existing DB ``code_snippet`` column (R7). For
    # secret-bearing CWEs (CWE-798/CWE-319 etc.) the secret VALUE is redacted at
    # that same choke point so neither the SSE payload nor the DB row carries it.
    code_snippet: str = ""


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
    # Cap: read VULTURE_MAX_SOURCE_CHARS dynamically (feature 0057 P1f — tests
    # and operators tune the per-batch budget at runtime) so the batch loop's
    # window size honours the env without an import-time freeze. Falls back to
    # the module default when unset.
    cap = _safe_int_env("VULTURE_MAX_SOURCE_CHARS", _MAX_SOURCE_CHARS)
    # ~3 chars per token for code. Safety margin applied later by safe_estimate_tokens().
    return min(max(2000, int(ctx_tokens * source_fraction * 3)), cap)


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
    include_tier3: bool = True,
) -> list:
    """Sort files into priority tiers for LLM context packing.

    Tier 1: Files that appear in skill_findings (highest signal).
    Tier 2: Entry points and config files (structural importance).
    Tier 3: Remaining files, sorted by size ascending (smaller = more likely focused).

    Feature 0059: when ``include_tier3`` is False, Tier 3 is dropped entirely
    (the LLM sees only flagged + entry/config files) — the cost guard. The
    deterministic phase is upstream and unaffected: skills/signatures still
    scan every file regardless.

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

    if not include_tier3:
        return tier1 + tier2

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


# Feature 0057 P1f: per-batch file cap so a single batch can't pack the whole
# tree when files are tiny (keeps batches bounded by file count too, not only
# by char budget). The USD budget + context window remain the real throttles.
_LLM_FILES_PER_BATCH = _safe_int_env("VULTURE_LLM_FILES_PER_BATCH", 40)


def _format_file_block(
    fpath: Any,
    source_path: str,
    findings_by_path: dict[str, list[dict]],
) -> tuple[str, str] | None:
    """Format one file into a ``(rel_path, "--- rel ---\\ncontent")`` block,
    using snippet extraction for files that carry skill findings. Returns None
    when the file is empty / unreadable."""
    content = read_file_safe(fpath)
    if content is None or not content.strip():
        return None
    rel = _safe_rel(fpath, source_path)
    if findings_by_path:
        file_findings = findings_by_path.get(rel, [])
        if not file_findings:
            file_findings = [
                f for fp_key, flist in findings_by_path.items()
                for f in flist
                if fp_key.endswith(rel)
            ]
        if file_findings:
            content = _extract_file_snippet(content, file_findings, rel)
    return rel, f"--- {rel} ---\n{content}"


def _build_source_batches(
    ordered_files: list,
    source_path: str,
    max_chars: int,
    skill_findings: list[dict] | None = None,
    files_per_batch: int = _LLM_FILES_PER_BATCH,
) -> list[tuple[str, list[str]]]:
    """Partition the ordered file list into context-window-sized batches.

    Feature 0057 P1f: the LLM phase sweeps the WHOLE tree by iterating over
    these batches, instead of a single context window that silently tail-drops
    the rest. Each batch's packed text is ≤ ``max_chars`` and holds ≤
    ``files_per_batch`` files. A single file larger than the whole budget still
    gets its own (over-budget) batch so it is never dropped — truncation to the
    real context window happens later per call.

    Returns a list of ``(batch_text, included_relpaths)``; empty if no files.
    """
    findings_by_path: dict[str, list[dict]] = {}
    if skill_findings:
        for f in skill_findings:
            fp = f.get("file_path", "")
            if fp:
                findings_by_path.setdefault(fp, []).append(f)

    batches: list[tuple[str, list[str]]] = []
    cur_parts: list[str] = []
    cur_paths: list[str] = []
    cur_total = 0

    def _flush() -> None:
        nonlocal cur_parts, cur_paths, cur_total
        if cur_parts:
            batches.append(("\n\n".join(cur_parts), cur_paths))
            cur_parts, cur_paths, cur_total = [], [], 0

    for fpath in ordered_files:
        block = _format_file_block(fpath, source_path, findings_by_path)
        if block is None:
            continue
        rel, text = block
        entry_len = len(text) + 2
        # Start a new batch when the current one is full (by chars or count)
        # — but never emit an empty batch just because one file is huge.
        if cur_parts and (
            cur_total + entry_len > max_chars
            or len(cur_paths) >= files_per_batch
        ):
            _flush()
        cur_parts.append(text)
        cur_paths.append(rel)
        cur_total += entry_len
    _flush()
    return batches


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


def _normalize_dedup_path(fp: str, source_path: str = "") -> str:
    """Normalize a finding path to a canonical *source-root-relative* token so
    absolute and source-relative forms of the SAME file collapse to one dedup
    key — WITHOUT collapsing two genuinely different files that merely share a
    basename.

    Feature 0057 P1f: the LLM phase reports repo-RELATIVE paths (``src/app.py``)
    while skills report ABSOLUTE paths (``/repo/src/app.py``) for the same file.
    Earlier this used a basename fallback, which was wrong in two ways:
      * over-dedup (data loss): ``a/util.py`` and ``b/util.py`` both collapsed
        to ``util.py`` → a real net-new finding in a different directory was
        dropped as a duplicate;
      * under-dedup (double-report): an LLM dupe at ``src/app.py`` (→ basename
        ``app.py``) did not match the skill's root-stripped ``src/app.py``, so
        the same vuln surfaced twice.

    Fix: normalise BOTH forms to a source-root-relative path. Absolute paths
    under the root are made relative; already-relative paths are normalised
    in place (and only resolved against the root when that actually locates
    the file, so we never invent a wrong directory). The directory structure
    is preserved, so distinct directories stay distinct.
    """
    if not fp:
        return ""
    # Backward-compat: when no source root is known (direct unit-test calls),
    # preserve the exact path so the historical (check_id, file_path) key is
    # unchanged. Normalization only kicks in for the real audit pipeline,
    # which always passes source_path.
    if not source_path:
        return fp

    root = source_path.rstrip("/")
    # Absolute path under the root → strip the root, keep the full subpath.
    if fp.startswith(root):
        rel = fp[len(root):].lstrip("/")
        return os.path.normpath(rel) if rel else ""
    # Already source-relative (the LLM's normal output): normalise in place,
    # stripping any leading "./". Keep the FULL relative path (not the
    # basename) so same-basename files in different directories stay distinct.
    cleaned = fp.lstrip("/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return os.path.normpath(cleaned) if cleaned else ""


def _dedup_key(f: dict, source_path: str = "") -> tuple[str, str]:
    """Build dedup key preferring check_id over normalized title.

    The path component is normalized (P1f) so absolute vs relative forms of
    the same file do not defeat cross-phase dedup.
    """
    cid = f.get("check_id", "")
    fp = _normalize_dedup_path(f.get("file_path", ""), source_path)
    if cid:
        return (cid, fp)
    return (_normalize_title(f.get("title", "")), fp)


def _deduplicate_findings(
    base: list[dict], new: list[dict], source_path: str = "",
) -> list[dict]:
    """Return findings from ``new`` not already in ``base``.

    Uses ``check_id`` + normalized ``file_path`` when check_id is present
    (stable, hierarchical). Falls back to normalized title + file_path
    otherwise. Path normalization (P1f) makes the match robust to
    absolute-vs-relative path forms of the same file.

    Args:
        base: Existing findings (e.g. from skill scan).
        new: New findings (e.g. from LLM pass) to filter.
        source_path: Audit source root, used to normalize paths.

    Returns:
        Subset of ``new`` that don't duplicate any entry in ``base``.
    """
    seen: set[tuple[str, str]] = set()
    for f in base:
        seen.add(_dedup_key(f, source_path))

    unique: list[dict] = []
    for f in new:
        key = _dedup_key(f, source_path)
        if key not in seen:
            unique.append(f)
            seen.add(key)
    return unique


def _is_within_root(candidate: Path, root: Path) -> bool:
    """True iff ``candidate`` (already resolved) is inside ``root`` (resolved).

    Uses ``Path.resolve()`` on both so symlink escapes (a finding path that
    points at a symlink inside the tree resolving to ``/etc/...``) are caught.
    Falls back to a string-prefix check on Python versions / paths where
    ``is_relative_to`` is unavailable.
    """
    try:
        return candidate.resolve().is_relative_to(root)
    except AttributeError:  # pragma: no cover — py<3.9
        try:
            candidate.resolve().relative_to(root)
            return True
        except ValueError:
            return False
    except OSError:
        return False


def _resolve_finding_path(file_path: str, source_path: str) -> Path | None:
    """Resolve a finding's file_path to an existing file on disk, CONFINED to
    the audit source root.

    Findings report paths in several forms: absolute, source-root-relative,
    or a bare basename. The LLM-phase ``file_path`` is fully model-controlled
    (parsed raw from model output), so a prompt-injected / hallucinating model
    could emit ``/etc/passwd`` or ``~/.aws/credentials`` and have its content
    read into ``code_snippet`` — which then leaks into the SSE result event.
    To prevent that arbitrary-file-read → exfiltration channel, we reject any
    resolved path that is not under ``source_path`` (symlink-escape safe via
    ``Path.resolve()``).

    When no source root is known (direct unit-test calls), the confinement is
    skipped and the historical absolute/relative resolution applies.
    """
    if not file_path:
        return None
    if not source_path:
        # No root to confine against (e.g. unit tests calling validate with
        # source_path=""). Preserve the historical resolution behaviour.
        p = Path(file_path)
        return p if p.is_file() else None

    root = Path(source_path).resolve()
    p = Path(file_path)
    # Absolute paths are taken verbatim; relative paths are resolved against
    # the source root. Either way the result must be IN-TREE (root-confined).
    candidate = p if p.is_absolute() else (Path(source_path) / file_path)
    if candidate.is_file() and _is_within_root(candidate, root):
        return candidate
    return None


# Feature 0057 P2a: CWEs whose findings embed an actual secret VALUE in the
# offending source line (credential, key, password, cleartext URL). For these,
# the secret must be masked out of ``code_snippet`` before it reaches the SSE
# ``result`` event or the DB column. Non-secret CWEs are left verbatim.
_SECRET_BEARING_CWES: frozenset[str] = frozenset({
    "CWE-798",  # use of hard-coded credentials
    "CWE-319",  # cleartext transmission of sensitive information
    "CWE-312",  # cleartext storage of sensitive information
    "CWE-256",  # plaintext storage of a password
    "CWE-259",  # use of a hard-coded password
    "CWE-321",  # use of a hard-coded cryptographic key (crypto_check embeds key)
    "CWE-522",  # insufficiently protected credentials
})

_REDACTION_PLACEHOLDER = "***REDACTED***"

# A quoted string literal: capture the opening quote so we can re-emit it while
# masking the body. Handles both single- and double-quoted literals.
_QUOTED_LITERAL_RE = re.compile(r"""(['"])(?:\\.|(?!\1)[^\\])*\1""")

# An assignment / key-value right-hand side whose value is NOT a fully quoted
# literal (e.g. ``token = abcd1234``, ``password: hunter2``, ``export KEY=v``,
# or a truncated ``api_key = "AKIA`` whose closing quote was cut). Captures any
# leading indentation plus the variable/key and operator so structure is
# preserved; masks the value. ``^\s*`` lets the branch fire on INDENTED source
# lines; an optional ``export``/``set`` shell prefix is tolerated.
_ASSIGN_RHS_RE = re.compile(
    r"""^(?P<indent>\s*(?:export\s+|set\s+)?)"""
    r"""(?P<lhs>[A-Za-z_][\w.\[\]'"-]*\s*[:=]\s*)"""
    r"""(?P<val>\S.*?)(?P<tail>\s*(?:#.*)?)$"""
)

# A trailing comment body (``# ...`` / ``// ...``). For secret-bearing findings
# a secret can hide in a comment; mask the comment body while keeping the marker.
_COMMENT_BODY_RE = re.compile(r"""(?P<marker>#|//)(?P<body>\s*\S.*)$""")


def _has_unterminated_quote(text: str) -> int:
    """Return the index of a dangling opening quote (a quote char with no
    matching close before end-of-line), or -1 if every quote is balanced.

    Handles the 200-char-truncation leak: when ``extract_snippet`` cuts a long
    secret line, the closing quote (and the secret tail) fall past the cut, so
    the value after the LAST opening quote was never masked by the
    complete-literal pass and would leak its PREFIX.
    """
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            close = text.find(c, i + 1)
            if close == -1:
                return i  # opening quote never closed → dangling
            i = close + 1
        else:
            i += 1
    return -1


def _redact_secret_line(line: str) -> str:
    """Mask secret VALUES in a single source line while preserving structure.

    The numbered-snippet line prefix (``"3: "``) is left untouched by callers;
    this operates on the code portion only. Masks:
      * the BODY of every quoted string VALUE (keeps the quotes; a quoted
        literal in dict-KEY position — immediately followed by ``:`` — is
        preserved so keys survive),
      * an unquoted assignment / key-value RHS (keeps the lhs + operator),
        including INDENTED and ``export``-prefixed lines, and
      * an unterminated opening quote (truncated long-secret lines), and
      * a trailing comment body (a secret hidden in a comment).
    Variable names, keys, quotes and line shape survive so the finding stays
    useful for triage.
    """
    trailing_nl = "\n" if line.endswith("\n") else ""
    body = line.rstrip("\n")

    if _QUOTED_LITERAL_RE.search(body):
        # At least one COMPLETE quoted literal: mask each literal's body, keep
        # quotes. Preserve quoted literals sitting in dict-KEY position (the
        # literal is immediately followed by ``:``) so keys stay readable.
        def _mask(m: re.Match[str]) -> str:
            q = m.group(1)
            after = body[m.end():]
            if after.lstrip().startswith(":"):
                return m.group(0)  # dict key — preserve verbatim
            return f"{q}{_REDACTION_PLACEHOLDER}{q}"

        masked = _QUOTED_LITERAL_RE.sub(_mask, body)
        # After masking complete literals, a dangling opening quote means the
        # closing quote was truncated away — mask its leaked tail to EOL.
        dangling = _has_unterminated_quote(masked)
        if dangling != -1:
            masked = masked[: dangling + 1] + _REDACTION_PLACEHOLDER
        return masked + trailing_nl

    # No complete quoted literal. If there's a lone (truncated) opening quote,
    # mask from it to EOL so the secret prefix is removed.
    dangling = _has_unterminated_quote(body)
    if dangling != -1:
        return body[: dangling + 1] + _REDACTION_PLACEHOLDER + trailing_nl

    # Try to mask an unquoted assignment RHS (indent / export aware).
    m = _ASSIGN_RHS_RE.match(body)
    if m:
        return (
            f"{m.group('indent')}{m.group('lhs')}{_REDACTION_PLACEHOLDER}"
            f"{m.group('tail')}{trailing_nl}"
        )

    # No assignment either — mask a trailing comment body (secret-in-comment).
    cm = _COMMENT_BODY_RE.search(body)
    if cm:
        prefix = body[: cm.start()]
        return f"{prefix}{cm.group('marker')} {_REDACTION_PLACEHOLDER}{trailing_nl}"
    return line


def _redact_snippet(snippet: str) -> str:
    """Redact secret values in a numbered code-window snippet (P2a).

    Each line is of the form ``"<n>: <code>"`` (see ``extract_snippet``). The
    ``"<n>: "`` prefix — carrying the line number and shape — is preserved and
    only the code portion is run through :func:`_redact_secret_line`.
    """
    if not snippet:
        return snippet
    out_lines: list[str] = []
    for raw in snippet.split("\n"):
        # Split off the "<n>: " numbered prefix produced by extract_snippet so
        # the line number is preserved exactly.
        m = re.match(r"^(\s*\d+:\s?)(.*)$", raw)
        if m:
            out_lines.append(f"{m.group(1)}{_redact_secret_line(m.group(2))}")
        else:
            out_lines.append(_redact_secret_line(raw))
    return "\n".join(out_lines)


def _redact_finding_inplace(finding: dict[str, Any]) -> None:
    """Mask the secret VALUE in a single finding's ``code_snippet`` when the
    finding is secret-bearing (P2a). Idempotent and DRY: this is the single
    redaction primitive invoked from EVERY snippet egress point —

      * the per-finding ``finding`` SSE event (skill + LLM phases), and
      * the ``_attach_code_snippet`` finalisation choke point (SSE ``result``
        + DB row),

    so a secret never reaches the frontend live view, the result snapshot, or
    the persisted ``code_snippet`` column. No-op for non-secret CWEs and for
    findings without a snippet. Re-redacting an already-masked snippet is safe
    (the placeholder carries no secret).
    """
    if str(finding.get("category", "")).strip().upper() not in _SECRET_BEARING_CWES:
        return
    existing = finding.get("code_snippet")
    if existing:
        finding["code_snippet"] = _redact_snippet(existing)


# --- Feature 0057 P6b: provenance vocabulary -----------------------------
# Exactly ONE of these tags is stamped on every finding. The deterministic
# tiers are set centrally at the finalisation choke point (``_set_provenance``,
# applied in ``_attach_code_snippet`` BEFORE validate); the ``llm`` tag is set
# at LLM-finding emission time (run_combined_audit) and PRESERVED here via
# ``setdefault`` semantics; ``llm_l5_verified`` is the L5-survival re-tag set
# at the validate vote choke point (``validate._apply_validation_to_finding``).
#
# The tags are ADDITIVE metadata: they must NOT change the
# ``validate.llm_judge._is_deterministic`` / ``_is_l5_exempt`` determinations,
# which key off ``check_id`` / ``signature_status`` / ``provenance == "llm"``.
PROVENANCE_VALUES: frozenset[str] = frozenset(
    {
        "skill",
        "signature_trusted",
        "signature_candidate",
        "catalog_rollup",
        "llm",
        "llm_l5_verified",
    }
)


def _classify_deterministic_provenance(finding: dict[str, Any]) -> str:
    """Map a DETERMINISTIC-tier finding to its provenance tag.

    Precedence (most specific first):
      * ``signature_status == "trusted"``    → ``signature_trusted``
      * ``signature_status == "candidate"``  → ``signature_candidate``
      * ``check_id`` ending ``.rollup``      → ``catalog_rollup``
        (built by ``catalog_detector._build_rollup_finding`` as
        ``cwe.catalog.cwe_<id>.rollup``)
      * anything else carrying a ``check_id`` → ``skill`` (the dedicated
        skills + keyword catalog hits)
    """
    sig_status = finding.get("signature_status")
    if sig_status == "trusted":
        return "signature_trusted"
    if sig_status == "candidate":
        return "signature_candidate"
    if str(finding.get("check_id", "")).endswith(".rollup"):
        return "catalog_rollup"
    return "skill"


def _set_provenance(finding: dict[str, Any]) -> None:
    """Stamp exactly one ``provenance`` tag on a finding (Feature 0057 P6b).

    ``setdefault`` semantics: a pre-set ``provenance`` (the Phase-1 ``llm`` tag
    on LLM findings) is preserved untouched; only deterministic-tier findings
    that arrive WITHOUT a provenance are classified here. Mutates in place;
    idempotent.
    """
    if finding.get("provenance"):
        return
    finding["provenance"] = _classify_deterministic_provenance(finding)


def _attach_code_snippet(
    findings: list[dict[str, Any]],
    source_path: str,
) -> None:
    """Feature 0057 P0.2: populate a real code window on every finding that
    lacks one, read from the referenced source line.

    Central choke point applied to ``all_findings`` (skill + LLM) just before
    the validate stage so the L5 judge always sees a grounded window (R4).
    Mutates findings in place. Additive / no-op for findings that already
    carry a non-empty ``code_snippet`` (several skills set it directly).

    Feature 0057 P6b: this is also the central provenance set-point —
    ``_set_provenance`` is applied to every finding here (BEFORE validate), so
    the emitted ``result`` carries the full deterministic provenance vocabulary
    while preserving the pre-set ``llm`` tag (setdefault semantics).

    A finding whose path cannot be resolved or whose line is missing/zero is
    left with an empty snippet — the L5 selection layer then SKIPS it (P0.3)
    rather than judging blind.
    """
    from shared.tools.file_scanner import read_file_lines

    # P6b: stamp the deterministic provenance tag on EVERY finding first, in a
    # standalone pass with no I/O. This is decoupled from the best-effort snippet
    # loop below so that a snippet/read failure (which the caller catches and
    # logs) can never strip provenance from the whole batch — provenance is a
    # pure in-memory classification and must always complete. (no-op if `llm`.)
    for f in findings:
        _set_provenance(f)

    for f in findings:
        if not f.get("code_snippet"):
            line_start = f.get("line_start", 0) or 0
            try:
                line_start = int(line_start)
            except (TypeError, ValueError):
                line_start = 0
            if line_start >= 1:
                resolved = _resolve_finding_path(f.get("file_path", ""), source_path)
                if resolved is not None:
                    lines = read_file_lines(resolved)
                    if lines:
                        snippet = extract_snippet(lines, line_start, context=2)
                        if snippet:
                            f["code_snippet"] = snippet

        # P2a: mask secret VALUES for secret-bearing CWEs, whether the snippet
        # was back-filled above OR pre-set by a skill (e.g. auth_check). This
        # runs at the finalisation choke point so both the SSE result and the
        # DB row carry the redacted form. (The per-finding `finding` SSE events
        # are independently redacted at emission time — see run_combined_audit —
        # so the live frontend view never sees the raw secret either.)
        _redact_finding_inplace(f)


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
    llm_tier3: bool | None = None,
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

    # feature 0061: cooperative cancellation. `cancel` is the ambient token the
    # transport flips on client disconnect; `_deadline_val` is the single
    # wall-clock ceiling shared across the skill, generate, and L5 phases so
    # their timeouts cannot stack (F11a). Bound ambiently so the generate
    # (asyncio.run) and L5 (copy_context thread) phases both see it.
    cancel = current_cancel_token()
    _max_audit_s = _safe_int_env("VULTURE_AGENT_MAX_AUDIT_SECONDS", 900)
    _deadline_val: float | None = None
    if _max_audit_s > 0:
        _deadline_val = time.monotonic() + _max_audit_s
        set_audit_deadline(_deadline_val)

    def _cancelled_or_expired() -> bool:
        return (cancel is not None and cancel.cancelled()) or (
            _deadline_val is not None and time.monotonic() > _deadline_val
        )

    # Emit prior findings context if available
    if prior_context:
        yield emitter.text_message(prior_context)

    # --- Phase 1: Skill-based pattern matching (always runs) ---
    scan_code_files(source_path)  # warm file cache

    skill_findings: list[dict] = []
    total = len(categories)
    completed = 0

    _skill_aborted = False  # feature 0061: set on cancel / skill-phase deadline
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

        # feature 0061: bound the skill wait by the shared whole-audit deadline
        # and honor cancel, so a hung skill or a client disconnect cannot pin
        # this phase (F2). `as_completed(timeout=)` caps the total wait.
        _skill_timeout = (
            max(0.1, _deadline_val - time.monotonic())
            if _deadline_val is not None else None
        )
        try:
            for future in as_completed(futures, timeout=_skill_timeout):
                if cancel is not None and cancel.cancelled():
                    _skill_aborted = True
                    break
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
                    # Feature 0057 P2a: redact secret-bearing snippets BEFORE the
                    # per-finding SSE event so the live frontend view (and any
                    # delta-finding DB persistence on a stalled stream) never sees
                    # the raw secret. Mutates the dict that is also kept in
                    # skill_findings, so the finalisation choke point re-sees the
                    # already-masked form (idempotent).
                    _redact_finding_inplace(finding)
                    yield emitter.finding_event(**finding)

                completed += 1
                yield emitter.progress_event(
                    files_analyzed=completed,
                    total_files=total,
                    findings_count=len(skill_findings),
                )
        except TimeoutError:
            _skill_aborted = True
            yield emitter.text_message(
                "[partial results] skill phase wall-clock cap reached; "
                "remaining skills not analyzed."
            )
    finally:
        # feature 0061: on cancel/expiry, cancel pending futures and don't block
        # on in-flight skills. Otherwise wait normally. (If GC'd from a worker
        # thread, wait=True would join that very thread — the RuntimeError
        # fallback drops to wait=False.)
        _drain = _skill_aborted or _cancelled_or_expired()
        try:
            pool.shutdown(wait=not _drain, cancel_futures=_drain)
        except (RuntimeError, TypeError):
            pool.shutdown(wait=False)

    logger.info("skill_phase_done run_id=%s findings=%d", run_id, len(skill_findings))

    # --- Phase 2: LLM enhancement (optional) ---
    llm_new_findings: list[dict] = []
    actual_input_tokens = 0
    actual_output_tokens = 0
    if effective_use_llm and skill_tools and instructions and not _cancelled_or_expired():
        yield emitter.text_message("Enhancing with LLM analysis...")
        logger.info("llm_phase_start run_id=%s", run_id)

        # Feature 0057 P1f: the collector now sweeps the whole tree in
        # context-window-sized batches (no single pre-built context / silent
        # tail-drop). It returns a partial-results notice (P1d) when a cap hit.
        (
            llm_findings, llm_error,
            actual_input_tokens, actual_output_tokens,
            llm_notice,
        ) = _collect_llm_findings(
            run_id=run_id,
            source_path=source_path,
            categories=categories,
            skill_tools=skill_tools,
            instructions=instructions,
            domain_label=domain_label,
            prior_context=prior_context,
            model=model,
            skill_findings=skill_findings,
            llm_tier3=llm_tier3,
        )
        if llm_notice:
            yield emitter.text_message(llm_notice)
        if llm_error:
            yield emitter.text_message(llm_error)
        llm_new_findings = _deduplicate_findings(
            skill_findings, llm_findings, source_path=source_path,
        )

        if llm_new_findings:
            yield emitter.text_message(
                f"LLM discovered {len(llm_new_findings)} additional finding(s)."
            )
            # Continue indexing from the end of skill_findings so IDs
            # remain unique across phases. (Feature 0046 issue #1.)
            base_idx = len(skill_findings)
            for offset, finding in enumerate(llm_new_findings):
                # Feature 0057: tag LLM findings so the validate stage knows
                # they are non-deterministic (L5-demotable), while skill
                # findings stay deterministic/trusted (R2 voter floor).
                finding.setdefault("provenance", "llm")
                _assign_finding_id(finding, run_id, base_idx + offset)
                # Feature 0057 P2a: redact secret-bearing LLM-finding snippets
                # before the per-finding SSE event (LLM is the realistic source
                # of unquoted / env-style / comment-embedded secrets).
                _redact_finding_inplace(finding)
                yield emitter.finding_event(**finding)
        elif not llm_error:
            yield emitter.text_message("LLM analysis complete — no additional findings.")

    # --- Combine & emit final result ---
    all_findings = skill_findings + llm_new_findings

    # --- Feature 0057 P0.2: code-grounding -----------------------
    # Populate a real code window on every finding lacking one (read from
    # source) so the L5 judge is never blind (R4). Additive / no-op when a
    # finding already carries a snippet. Skipped if the source is gone.
    try:
        _attach_code_snippet(all_findings, source_path)
    except Exception as exc:  # noqa: BLE001 — grounding is best-effort
        logger.warning("code_snippet_attach_failed run_id=%s: %s", run_id, exc)

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
            # feature 0061 (F11): skip the L5 *LLM* judge when the audit is
            # already cancelled / past the shared deadline. Deterministic L1/L2
            # still annotate the partial findings cheaply.
            if _cancelled_or_expired():
                _l5_enabled = False
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

            # feature 0061 (F11c): a raw threading.Thread does NOT inherit
            # contextvars, so copy the current context (carrying the cancel
            # token + shared whole-audit deadline) into the L5 thread. run_l5
            # reads them to cap its deadline and stop early on cancel.
            _vctx = contextvars.copy_context()
            _vthread = _threading.Thread(
                target=lambda: _vctx.run(_run_validate_in_thread), daemon=True,
            )
            _vthread.start()

            # Drain the queue: emit one validation_update SSE event per
            # batch as L5 produces them. The sentinel `None` means
            # validate finished.
            while True:
                batch = _stream_q.get()
                if batch is None:
                    break
                yield emitter.validation_update_event(batch)
            # feature 0061: bounded join — L5 self-terminates by the shared
            # deadline (it caps its own on `current_audit_deadline`), so never
            # pin the generator/producer indefinitely.
            _join_timeout = (
                max(1.0, _deadline_val - time.monotonic()) + 5.0
                if _deadline_val is not None else None
            )
            _vthread.join(timeout=_join_timeout)
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
    llm_tier3: bool | None = None,
) -> tuple[list[dict], str | None, int, int, str | None]:
    """Run the LLM audit (batch-looped) and collect findings (no SSE wrapping).

    Returns ``(findings, error_message, input_tokens, output_tokens, notice)``.
    ``error_message`` is None on success; ``notice`` carries a partial-results
    message when the sweep stopped early on the budget / work cap (P1d), or
    when Tier-3 was skipped (0059 cost guard). Uses ``asyncio.run`` per issue #19.
    """
    return asyncio.run(
        _collect_llm_findings_batched_async(
            run_id, source_path, categories, skill_tools,
            instructions, domain_label, prior_context, model,
            skill_findings=skill_findings,
            llm_tier3=llm_tier3,
        )
    )


def _resolve_llm_budget_usd() -> float:
    """Parse VULTURE_LLM_BUDGET_USD; <= 0 / unset / invalid ⇒ no USD cap."""
    raw = os.environ.get("VULTURE_LLM_BUDGET_USD", "").strip()
    if not raw:
        return 0.0
    try:
        val = float(raw)
    except (ValueError, TypeError):
        logger.warning("invalid_budget_usd value=%r ignoring", raw)
        return 0.0
    return val if val > 0 else 0.0


def _llm_tier3_enabled(config_value: bool | None = None) -> bool:
    """Feature 0059: should the LLM generate phase analyze Tier-3 files
    (no deterministic findings, not entry/config)?

    Precedence: explicit per-request ``config_value`` > ``VULTURE_LLM_TIER3``
    env (on/true/1/yes) > built-in default **OFF** (the cost guard). OFF scopes
    the LLM sweep to Tier 1 (flagged) + Tier 2 (entry/config); deterministic
    skills/signatures still scan every file regardless.
    """
    if isinstance(config_value, bool):
        return config_value
    return os.environ.get("VULTURE_LLM_TIER3", "").strip().lower() in ("on", "true", "1", "yes")


async def _collect_llm_findings_batched_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    llm_tier3: bool | None = None,
) -> tuple[list[dict], str | None, int, int, str | None]:
    """Feature 0057 P1f + P1d: sweep the WHOLE tree in context-window-sized
    batches instead of a single shot that silently tail-drops files.

    For each batch it runs one agent call (delegating to
    ``_collect_llm_findings_async``), dedups findings across batches, and
    accumulates real token usage. The loop stops when the tree is covered, the
    per-audit file cap (``VULTURE_LLM_MAX_FILES``) is hit, or the estimated USD
    spend crosses ``VULTURE_LLM_BUDGET_USD`` — emitting a partial-results
    notice in the latter two cases.

    Returns ``(findings, error, input_tokens, output_tokens, notice)``.
    """
    max_files = _safe_int_env("VULTURE_LLM_MAX_FILES", 10000)
    budget_usd = _resolve_llm_budget_usd()

    # Feature 0057 P1d: the LLM sweep is bounded by VULTURE_LLM_MAX_FILES, the
    # operative ceiling for the whole-codebase pass. Without passing it here the
    # sweep would silently cap at the smaller global scan limit
    # (VULTURE_MAX_FILES, default 500) and the documented LLM cap could never
    # trip. We take the larger of the two so the LLM phase can sweep beyond the
    # per-skill scan cap up to its own ceiling.
    from shared.tools.file_scanner import MAX_FILES as _SCAN_MAX_FILES
    scan_cap = max(max_files, _SCAN_MAX_FILES)
    # Feature 0059: Tier-3 cost guard (default OFF). When off, the LLM sweep
    # is scoped to flagged + entry/config files; the long tail is skipped (and
    # reported via the notice below). Deterministic skills already scanned all.
    include_tier3 = _llm_tier3_enabled(llm_tier3)
    scanned = scan_code_files(source_path, max_files=scan_cap)
    ordered = _prioritize_files(
        scanned, source_path, skill_findings, include_tier3=include_tier3,
    )
    tier3_skipped = (len(scanned) - len(ordered)) if not include_tier3 else 0
    max_chars = _get_max_source_chars(model)
    # Budget-aware batching: with a USD budget configured the sweep batches
    # cautiously (smaller batches) so cost accrues incrementally and the cap
    # can halt it mid-tree before over-spending; with no budget it packs large
    # batches for efficiency (file count is not the throttle — the context
    # window + budget are; plan §7).
    files_per_batch = (
        _safe_int_env("VULTURE_LLM_FILES_PER_BATCH", 1)
        if budget_usd > 0 else _LLM_FILES_PER_BATCH
    )
    batches = _build_source_batches(
        ordered, source_path, max_chars, skill_findings,
        files_per_batch=files_per_batch,
    )
    # No readable source files → still make ONE tool-enabled call so the LLM
    # can read/list/grep the tree itself (preserves prior single-shot behaviour).
    if not batches:
        batches = [("", [])]

    from shared.llm.provider import estimate_cost

    acc: list[dict] = []
    total_in = 0
    total_out = 0
    files_seen = 0
    notice: str | None = None
    first_error: str | None = None

    # feature 0061: honor cancel + the shared whole-audit deadline BEFORE each
    # call, and bound each call so a hung/slow model cannot starve these checks.
    _cancel = current_cancel_token()
    _deadline = current_audit_deadline()
    _call_timeout = _safe_int_env("VULTURE_LLM_CALL_TIMEOUT_SEC", 120)
    if _call_timeout <= 0:  # 0/negative would make asyncio.wait_for insta-timeout every call
        _call_timeout = 120
    for batch_idx, (batch_text, batch_paths) in enumerate(batches):
        if _cancel is not None and _cancel.cancelled():
            notice = (
                f"[partial results] audit cancelled ({_cancel.reason}); "
                f"stopped after {batch_idx} of {len(batches)} batch(es)."
            )
            logger.warning("audit_cancelled run_id=%s reason=%s batches=%d/%d",
                           run_id, _cancel.reason, batch_idx, len(batches))
            break
        if _deadline is not None and time.monotonic() > _deadline:
            notice = (
                f"[partial results] wall-clock cap reached; "
                f"stopped after {batch_idx} of {len(batches)} batch(es)."
            )
            logger.warning("audit_deadline run_id=%s batches=%d/%d",
                           run_id, batch_idx, len(batches))
            break
        try:
            findings, error, in_tok, out_tok = await asyncio.wait_for(
                _collect_llm_findings_async(
                    run_id, source_path, categories, skill_tools,
                    instructions, domain_label, prior_context, model,
                    skill_findings=skill_findings,
                    source_context=batch_text,
                ),
                timeout=_call_timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            # A hung/slow call is bounded here so the loop regains control to
            # re-check cancel/deadline on the next iteration. The injected
            # CancelledError escapes _collect_llm_findings_async's `except
            # Exception`, so no model cooldown/failure is recorded (F7).
            findings, error, in_tok, out_tok = (
                [], f"llm call timed out after {_call_timeout}s", 0, 0,
            )
        total_in += in_tok
        total_out += out_tok
        files_seen += len(batch_paths)
        if error and first_error is None:
            first_error = error
        if findings:
            # Dedup across batches AND against skill findings so one vuln seen
            # in two overlapping windows isn't double-reported (P1f).
            new = _deduplicate_findings(
                (skill_findings or []) + acc, findings, source_path=source_path,
            )
            acc.extend(new)

        # --- Caps (P1d): evaluate AFTER the batch so its tokens count ---
        if budget_usd > 0:
            spent = estimate_cost(total_in, total_out, model)
            if spent > budget_usd and batch_idx + 1 < len(batches):
                notice = (
                    f"[partial results] LLM budget cap reached "
                    f"(${spent:.4f} > ${budget_usd:.4f}); stopped after "
                    f"{batch_idx + 1} of {len(batches)} file batch(es). "
                    f"Remaining files were not analyzed by the LLM."
                )
                logger.warning("llm_budget_cap run_id=%s %s", run_id, notice)
                break
        if files_seen >= max_files and batch_idx + 1 < len(batches):
            notice = (
                f"[partial results] LLM file cap reached "
                f"({files_seen} >= VULTURE_LLM_MAX_FILES={max_files}); "
                f"stopped after {batch_idx + 1} of {len(batches)} batch(es)."
            )
            logger.warning("llm_file_cap run_id=%s %s", run_id, notice)
            break

    # Surface a per-call error only when the sweep produced nothing useful.
    err = first_error if (first_error and not acc) else None
    # Feature 0059: never silently reduce scope — report the skipped Tier-3 tail.
    if tier3_skipped > 0:
        tier3_notice = (
            f"[llm-scope] Tier-3 skipped: {tier3_skipped} file(s) (no deterministic "
            f"findings, not entry/config) were NOT sent to the LLM — cost guard. "
            f"Set VULTURE_LLM_TIER3=on or scan --llm-tier3 for full-tree LLM coverage."
        )
        notice = f"{tier3_notice}\n{notice}" if notice else tier3_notice
    return acc, err, total_in, total_out, notice


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
    from shared.llm.provider import get_model_with_fallback, get_model_settings, supports_structured_output
    from shared.tools.file_reader import make_read_file_tool
    from shared.tools.file_lister import make_list_files_tool
    from shared.tools.pattern_matcher import make_search_pattern_tool

    resolved_model = get_model_with_fallback(model)

    if not source_context:
        source_context = _build_source_context(source_path, skill_findings=skill_findings, model=model)
    # Feature 0057 P1c: always attach the read-only file + grep tools, even on
    # the inline-source path. The inline context is a budget-bounded subset of
    # the tree; giving the LLM read/list/grep lets it follow cross-file
    # dataflow into files that didn't fit the window (the batch loop covers
    # breadth; the tools cover depth). The model decides whether to call them.
    #
    # Security: the tools are CONFINED to the audit source root (built per
    # audit) so a prompt-injected / hallucinating model cannot read or grep
    # outside the scanned tree (e.g. /etc/passwd, ~/.aws/credentials) and
    # exfiltrate it via a finding. Falls back to the unconfined module tools
    # only when no source root is known (should not happen in the real pipeline).
    if source_path:
        extra_tools = [
            make_read_file_tool(source_path),
            make_list_files_tool(source_path),
            make_search_pattern_tool(source_path),
        ]
    else:
        from shared.tools.file_reader import read_file_tool
        from shared.tools.file_lister import list_files_tool
        from shared.tools.pattern_matcher import search_pattern_tool
        extra_tools = [read_file_tool, list_files_tool, search_pattern_tool]
    all_tools = list(skill_tools) + extra_tools

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

    # Custom OpenAI-compatible endpoints (vLLM, LM Studio, etc.) and Gemini may
    # not support structured output (response_format with JSON schema) alongside
    # the function-calling tools we always attach.  Skip output_type in those
    # cases and rely on prompt-based JSON + _parse_llm_findings fallback.
    use_structured = supports_structured_output(resolved_model)
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
