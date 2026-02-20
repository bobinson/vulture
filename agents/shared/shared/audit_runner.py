"""Shared audit runner with concurrent skill execution and file caching."""

import asyncio
import os
import re
from collections.abc import AsyncGenerator, Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from shared.tools.file_scanner import scan_code_files, read_file_safe
from pydantic import BaseModel

from shared.tools.memory_client import estimate_tokens, _normalize_title
from shared.transport.event_emitter import AgUiEventEmitter


class AuditFinding(BaseModel):
    severity: str = "info"
    category: str = "unknown"
    title: str = "Untitled finding"
    description: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    recommendation: str = ""


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
) -> str | None:
    """Build a token savings SSE event based on real deduplication metrics.

    Args:
        emitter: Event emitter instance.
        context: Prior context string.
        findings_total: Total findings (new + known).
        findings_skipped: Findings skipped because they matched prior context.
        actual_input_tokens: Real input tokens from LLM API response.
        actual_output_tokens: Real output tokens from LLM API response.

    Returns:
        SSE event string, or None if no context.
    """
    if not context:
        return None
    ctx_tokens = estimate_tokens(context)
    lines = context.split("\n")
    used = sum(1 for ln in lines if ln.startswith(" ") and ":" in ln)
    dupes = _extract_dupe_count(lines)

    # Estimate raw tokens: what we'd have used without memory context
    # Each skipped finding would have been ~65 tokens of LLM output + analysis
    if findings_skipped > 0:
        skipped_output_tokens = findings_skipped * 65
        raw_tokens = ctx_tokens + skipped_output_tokens
    else:
        # No findings were skipped — context was informational only, no savings
        raw_tokens = ctx_tokens

    return emitter.token_savings_event(
        ctx_tokens, raw_tokens, used, dupes,
        actual_input_tokens=actual_input_tokens,
        actual_output_tokens=actual_output_tokens,
    )


def _parse_known_titles(prior_context: str) -> set[str]:
    """Extract normalized known issue titles from prior context string.

    Parses lines like ' C:[injection] SQL Injection @db.py' to extract 'sql injection'.
    """
    titles: set[str] = set()
    if not prior_context:
        return titles
    for line in prior_context.split("\n"):
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


def _get_max_source_chars() -> int:
    """Compute max source chars from the active model's context window.

    Uses ``get_context_window()`` (env override > model lookup > 32K default).
    The OpenAI Agents SDK adds significant overhead (tool schemas, structured
    output schema, system instructions) — typically 3-5K tokens.  We reserve
    50% of context for source code at ~3 chars per token (code is token-dense).
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window()
    return max(2000, int(ctx_tokens * 0.5 * 3))


def _build_source_context(
    source_path: str,
    max_chars: int = 0,
) -> str:
    """Pre-read source files and format them for inline LLM prompt inclusion.

    Local models (Ollama, LM Studio) often lack function-calling support,
    so they cannot use tools to read files.  This function scans the source
    tree and embeds file contents directly in the prompt so the LLM can
    analyze the code without tool use.

    Args:
        source_path: Root directory of the source code.
        max_chars: Maximum total characters of source code to include.

    Returns:
        Formatted string with file contents, or empty string if no files found.
    """
    if max_chars <= 0:
        max_chars = _get_max_source_chars()
    files = scan_code_files(source_path)
    if not files:
        return ""

    parts: list[str] = []
    total = 0
    for fpath in files:
        content = read_file_safe(fpath)
        if content is None:
            continue
        # Skip empty files
        if not content.strip():
            continue
        # Check budget before adding
        rel = str(fpath.relative_to(source_path)) if str(fpath).startswith(source_path) else str(fpath)
        header = f"--- {rel} ---"
        entry_len = len(header) + 1 + len(content) + 2  # header + newline + content + double newline
        if total + entry_len > max_chars:
            continue
        parts.append(f"{header}\n{content}")
        total += entry_len

    if not parts:
        return ""
    return "\n\n".join(parts)


def _deduplicate_findings(base: list[dict], new: list[dict]) -> list[dict]:
    """Return findings from ``new`` not already in ``base`` (by normalized title + file).

    Comparison is case-insensitive on the title (after normalization via
    ``_normalize_title``) and exact on ``file_path``.

    Args:
        base: Existing findings (e.g. from skill scan).
        new: New findings (e.g. from LLM pass) to filter.

    Returns:
        Subset of ``new`` that don't duplicate any entry in ``base``.
    """
    seen: set[tuple[str, str]] = set()
    for f in base:
        key = (_normalize_title(f.get("title", "")), f.get("file_path", ""))
        seen.add(key)

    unique: list[dict] = []
    for f in new:
        key = (_normalize_title(f.get("title", "")), f.get("file_path", ""))
        if key not in seen:
            unique.append(f)
            seen.add(key)
    return unique


def run_skill_audit(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_map: dict[str, SkillFn],
    domain_label: str = "categories",
    prior_context: str = "",
) -> Generator[str, None, None]:
    """Execute skills concurrently and yield SSE events.

    Pre-scans the file tree once (warming the read cache), then
    dispatches all skills via a thread pool for parallel execution.

    Args:
        run_id: Unique run identifier.
        source_path: Path to source code root.
        categories: Ordered list of skill/category keys to run.
        skill_map: Mapping from category key to skill function.
        domain_label: Label for summary text (e.g. 'categories', 'OWASP categories').
        prior_context: Optional prior findings context from memory bank.

    Yields:
        SSE-formatted event strings.
    """
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    # Emit prior findings context if available (token savings + context awareness)
    if prior_context:
        yield emitter.text_message(prior_context)
        _emit_context = prior_context
    else:
        _emit_context = ""

    # Pre-scan files once to warm the directory cache for all skills.
    scan_code_files(source_path)

    # Run skills concurrently.
    all_findings: list[dict] = []
    total = len(categories)
    completed = 0

    with ThreadPoolExecutor(max_workers=min(total, 4)) as pool:
        futures = {}
        for cat in categories:
            fn = skill_map.get(cat)
            if fn is None:
                continue
            futures[pool.submit(fn, source_path)] = cat

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
                    findings_count=len(all_findings),
                )
                continue

            findings = result.get("findings", [])
            all_findings.extend(findings)

            for finding in findings:
                yield emitter.finding_event(**finding)

            completed += 1
            yield emitter.progress_event(
                files_analyzed=completed,
                total_files=total,
                findings_count=len(all_findings),
            )

    # Count how many findings match known prior issues (for stats only).
    # All findings are kept — prior context is informational, not a filter.
    known_titles = _parse_known_titles(prior_context)
    if known_titles:
        skipped = sum(
            1 for f in all_findings
            if _normalize_title(f.get("title", "")) in known_titles
        )
    else:
        skipped = 0

    score = compute_score(all_findings, total)
    summary = build_summary(all_findings, categories, domain_label)

    # Emit dedup stats for skill mode (skills don't use LLM tokens)
    if _emit_context:
        ctx_lines = _emit_context.split("\n")
        used_count = sum(1 for ln in ctx_lines if ln.startswith(" ") and ":" in ln)
        dupe_count = _extract_dupe_count(ctx_lines)
        yield emitter.dedup_stats_event(
            findings_deduped=skipped,
            prior_findings_used=used_count,
            duplicates_removed=dupe_count,
        )

    yield emitter.result_event(findings=all_findings, summary=summary, score=score)
    yield emitter.run_finished()


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
) -> Generator[str, None, None]:
    """Run skills first (full coverage), then optionally LLM (deeper analysis).

    Always runs pattern-matching skills across all files. When ``USE_LLM``
    is true and ``skill_tools``/``instructions`` are provided, performs a
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

    Yields:
        SSE-formatted event strings.
    """
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    # Emit prior findings context if available
    if prior_context:
        yield emitter.text_message(prior_context)

    # --- Phase 1: Skill-based pattern matching (always runs) ---
    scan_code_files(source_path)  # warm file cache

    skill_findings: list[dict] = []
    total = len(categories)
    completed = 0

    with ThreadPoolExecutor(max_workers=min(total, 4)) as pool:
        futures = {}
        for cat in categories:
            fn = skill_map.get(cat)
            if fn is None:
                continue
            futures[pool.submit(fn, source_path)] = cat

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
            skill_findings.extend(findings)

            for finding in findings:
                yield emitter.finding_event(**finding)

            completed += 1
            yield emitter.progress_event(
                files_analyzed=completed,
                total_files=total,
                findings_count=len(skill_findings),
            )

    # --- Phase 2: LLM enhancement (optional) ---
    llm_new_findings: list[dict] = []
    if USE_LLM and skill_tools and instructions:
        yield emitter.text_message("Enhancing with LLM analysis...")

        source_context = _build_source_context(source_path)
        file_count = source_context.count("\n--- ") + (
            1 if source_context.startswith("--- ") else 0
        )
        if source_context:
            yield emitter.text_message(
                f"Loaded {file_count} file(s) into LLM context."
            )

        llm_findings, llm_error = _collect_llm_findings(
            run_id=run_id,
            source_path=source_path,
            categories=categories,
            skill_tools=skill_tools,
            instructions=instructions,
            domain_label=domain_label,
            prior_context=prior_context,
            model=model,
        )
        if llm_error:
            yield emitter.text_message(llm_error)
        llm_new_findings = _deduplicate_findings(skill_findings, llm_findings)

        if llm_new_findings:
            yield emitter.text_message(
                f"LLM discovered {len(llm_new_findings)} additional finding(s)."
            )
            for finding in llm_new_findings:
                yield emitter.finding_event(**finding)
        elif not llm_error:
            yield emitter.text_message("LLM analysis complete — no additional findings.")

    # --- Combine & emit final result ---
    all_findings = skill_findings + llm_new_findings

    # Dedup stats against prior context (informational only)
    known_titles = _parse_known_titles(prior_context)
    if known_titles:
        skipped = sum(
            1 for f in all_findings
            if _normalize_title(f.get("title", "")) in known_titles
        )
    else:
        skipped = 0

    if prior_context:
        ctx_lines = prior_context.split("\n")
        used_count = sum(1 for ln in ctx_lines if ln.startswith(" ") and ":" in ln)
        dupe_count = _extract_dupe_count(ctx_lines)
        yield emitter.dedup_stats_event(
            findings_deduped=skipped,
            prior_findings_used=used_count,
            duplicates_removed=dupe_count,
        )

    score = compute_score(all_findings, total)
    summary = build_summary(all_findings, categories, domain_label)
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
) -> tuple[list[dict], str | None]:
    """Run the LLM audit and collect findings (without SSE wrapping).

    Returns (findings, error_message). error_message is None on success.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            _collect_llm_findings_async(
                run_id, source_path, categories, skill_tools,
                instructions, domain_label, prior_context, model,
            )
        )
    finally:
        loop.close()


async def _collect_llm_findings_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
) -> tuple[list[dict], str | None]:
    """Async helper: run LLM agent and return (findings, error_message)."""
    from agents import Agent, ModelSettings, Runner
    from shared.llm.provider import get_model
    from shared.tools.file_reader import read_file_tool
    from shared.tools.file_lister import list_files_tool
    from shared.tools.pattern_matcher import search_pattern_tool

    source_context = _build_source_context(source_path)
    all_tools = list(skill_tools) + [read_file_tool, list_files_tool, search_pattern_tool]

    prompt_parts = [
        f"Audit the source code at: {source_path}",
        f"Focus on these {domain_label}: {', '.join(categories)}",
        "For each issue found, provide severity, category, title, description,",
        "file_path, line_start, line_end, and recommendation.",
    ]
    if source_context:
        prompt_parts.append(
            "\nThe source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n"
        )
        prompt_parts.append(source_context)
    else:
        prompt_parts.append("Use the available tools to analyze the code thoroughly.")
    if prior_context:
        prompt_parts.append(f"\nContext from prior audits:\n{prior_context}")

    agent = Agent(
        name="auditor",
        instructions=instructions,
        tools=all_tools,
        model=get_model(model),
        output_type=AuditOutput,
        model_settings=ModelSettings(temperature=0.1),
    )

    prompt_text = "\n".join(prompt_parts)
    findings: list[dict] = []

    try:
        result = await Runner.run(agent, input=prompt_text)
        if isinstance(result.final_output, AuditOutput):
            findings = [f.model_dump() for f in result.final_output.findings]
            for f in findings:
                f["severity"] = normalize_severity(f.get("severity", "info"))
        else:
            findings = _parse_llm_findings(str(result.final_output))
    except Exception as exc:
        return [], f"LLM analysis failed: {str(exc)[:200]}"

    return findings, None


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


async def _run_llm_audit_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
) -> AsyncGenerator[str, None]:
    """Execute audit via LLM agent with tool use.

    Uses the OpenAI Agents SDK with LiteLLM for vendor-neutral model support.
    The agent reasons about the codebase and invokes skill tools autonomously.

    Args:
        run_id: Unique run identifier.
        source_path: Path to source code root.
        categories: Categories to focus on.
        skill_tools: List of @function_tool decorated tools.
        instructions: System instructions for the agent.
        domain_label: Label for summary text.
        prior_context: Optional prior findings from memory bank.
        model: Optional model preference (defaults to env).

    Yields:
        SSE-formatted event strings.
    """
    from agents import Agent, ModelSettings, Runner
    from shared.llm.provider import get_model
    from shared.tools.file_reader import read_file_tool
    from shared.tools.file_lister import list_files_tool
    from shared.tools.pattern_matcher import search_pattern_tool

    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    # Emit prior context if available
    _llm_context = ""
    if prior_context:
        yield emitter.text_message(prior_context)
        _llm_context = prior_context

    yield emitter.text_message("Initializing LLM agent...")

    # Pre-read source files for inline inclusion (local models may lack tool use).
    yield emitter.text_message("Reading source files...")
    source_context = _build_source_context(source_path)
    file_count = source_context.count("\n--- ") + (1 if source_context.startswith("--- ") else 0)

    # Combine domain-specific skill tools with general-purpose tools
    all_tools = list(skill_tools) + [read_file_tool, list_files_tool, search_pattern_tool]

    # Build the prompt with context
    prompt_parts = [
        f"Audit the source code at: {source_path}",
        f"Focus on these {domain_label}: {', '.join(categories)}",
        "For each issue found, provide severity, category, title, description,",
        "file_path, line_start, line_end, and recommendation.",
    ]
    if source_context:
        yield emitter.text_message(f"Loaded {file_count} source file(s) into context.")
        prompt_parts.append(
            "\nThe source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n"
        )
        prompt_parts.append(source_context)
    else:
        prompt_parts.append("Use the available tools to analyze the code thoroughly.")
    if prior_context:
        prompt_parts.append(f"\nContext from prior audits:\n{prior_context}")

    agent = Agent(
        name="auditor",
        instructions=instructions,
        tools=all_tools,
        model=get_model(model),
        output_type=AuditOutput,
        model_settings=ModelSettings(temperature=0.1),
    )

    yield emitter.text_message("Running LLM-powered analysis...")

    prompt_text = "\n".join(prompt_parts)
    findings: list[dict] = []
    actual_input = 0
    actual_output = 0

    try:
        result = await Runner.run(agent, input=prompt_text)

        # Try to extract actual usage from SDK result
        try:
            if hasattr(result, 'raw_responses'):
                for resp in result.raw_responses:
                    if hasattr(resp, 'usage'):
                        actual_input += getattr(resp.usage, 'input_tokens', 0) or 0
                        actual_output += getattr(resp.usage, 'output_tokens', 0) or 0
        except Exception:
            pass

        # With structured output, result.final_output is already an AuditOutput instance
        if isinstance(result.final_output, AuditOutput):
            findings = [f.model_dump() for f in result.final_output.findings]
            for f in findings:
                f["severity"] = normalize_severity(f.get("severity", "info"))
        else:
            # Fallback to regex parsing for non-structured responses
            findings = _parse_llm_findings(str(result.final_output))
    except Exception as exc:
        err_msg = str(exc)
        if "n_keep" in err_msg and "n_ctx" in err_msg:
            yield emitter.text_message(
                f"Error: source code ({len(prompt_text)} chars) exceeds model context window. "
                "Increase n_ctx in LM Studio or use a model with larger context."
            )
        else:
            yield emitter.text_message(f"LLM error: {err_msg[:200]}")

    yield emitter.text_message(f"Agent found {len(findings)} finding(s).")

    for finding in findings:
        yield emitter.finding_event(**finding)

    # Emit token savings for LLM mode
    # For LLM mode, findings_skipped is harder to measure without a baseline.
    # Use the prior findings count as a proxy: LLM was told to skip those.
    known_count = len(_parse_known_titles(_llm_context))
    savings_event = _emit_token_savings(
        emitter, _llm_context,
        findings_total=len(findings) + known_count,
        findings_skipped=known_count,
        actual_input_tokens=actual_input,
        actual_output_tokens=actual_output,
    )
    if savings_event:
        yield savings_event

    score = compute_score(findings, len(categories))
    summary = build_summary(findings, categories, domain_label)
    yield emitter.result_event(findings=findings, summary=summary, score=score)
    yield emitter.run_finished()


def run_llm_audit(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str = "categories",
    prior_context: str = "",
    model: str | None = None,
) -> Generator[str, None, None]:
    """Synchronous wrapper for LLM-powered audit.

    Collects all events from the async generator and yields them.
    """
    loop = asyncio.new_event_loop()
    try:
        gen = _run_llm_audit_async(
            run_id, source_path, categories, skill_tools,
            instructions, domain_label, prior_context, model,
        )
        while True:
            try:
                event = loop.run_until_complete(gen.__anext__())
                yield event
            except StopAsyncIteration:
                break
    finally:
        loop.close()


def _parse_llm_findings(output: str) -> list[dict]:
    """Extract structured findings from LLM text output.

    Attempts to parse JSON arrays from the response. Falls back to
    empty list if parsing fails.
    """
    import json
    import re

    # Try to extract JSON array from the output
    patterns = [
        re.compile(r"```json\s*(\[.*?\])\s*```", re.DOTALL),
        re.compile(r"(\[\s*\{.*?\}\s*\])", re.DOTALL),
    ]
    for pattern in patterns:
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
