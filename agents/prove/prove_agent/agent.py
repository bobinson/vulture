"""Prove agent orchestration with self-learning, endpoint analysis, and proactive probing.

Pipeline:
  1. Load cached discovery + cross-session learnings
  2. Start verification immediately using cached discovery
  3. Run fresh discovery in background thread (results used for remaining findings)
  4. Proactive API security probing on discovered endpoints
  5. Save learnings for next session
"""

import asyncio
import json
import logging
import os
import threading
from collections.abc import Generator
from typing import Any

import httpx

from shared.llm.mode import is_llm_required, is_skills_only
from shared.transport.event_emitter import AgUiEventEmitter

from shared.discovery.cache import load_cached_discovery
from shared.discovery.sitemap import SiteMap

from prove_agent.api_prober import probe_api_endpoints
from prove_agent.config import ALL_TYPES
from prove_agent.discover_client import call_discover
from prove_agent.discovery import discover_incremental
from prove_agent.endpoint_analyzer import analyze_endpoints, format_endpoint_analysis
from prove_agent.protocols.detection import TargetCapabilities, detect_capabilities
from prove_agent.prove_learnings import (
    ProveSessionLearnings,
    record_successful_probe,
)
from prove_agent.runner import prove_finding_with_timeout, validate_staging_url
from prove_agent.strategies import STRATEGY_MAP

logger = logging.getLogger(__name__)

_BACKEND_URL = os.environ.get("VULTURE_BACKEND_URL", "http://backend:28080")
_CROSS_FINDING_CIRCUIT_BREAKER = 5  # Abort after N consecutive connection failures across findings


def run_prove(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the prove verification pipeline and yield SSE events."""
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()
    yield emitter.text_message("Starting prove agent verification pipeline")

    staging_url = config.get("staging_url", "")
    types = config.get("types", ALL_TYPES)
    _MAX_ITERATIONS_CAP = 10
    raw_iterations = config.get("max_iterations", 3)
    max_iterations = min(raw_iterations, _MAX_ITERATIONS_CAP)
    if raw_iterations > _MAX_ITERATIONS_CAP:
        logger.warning(
            "max_iterations_capped requested=%d cap=%d",
            raw_iterations, _MAX_ITERATIONS_CAP,
        )
    allow_local = config.get("allow_local", False)
    schemas = config.get("schemas", {})

    # Validate staging URL
    url_error = validate_staging_url(staging_url, allow_local=allow_local)
    if url_error:
        yield emitter.text_message(f"ERROR: {url_error}")
        yield emitter.run_finished("failed")
        return

    # Feature 0043: skills-only mode bail-out. The prove agent is
    # currently LLM-mandatory by design (per agents/prove/CLAUDE.md
    # — verification logic uses LLM-assisted proof generation). If
    # the operator opted out of LLM use via VULTURE_USE_LLM=false
    # (or unset) we MUST NOT call any LLM client — doing so produces
    # AuthenticationError + 5-minute litellm cooldown loops that
    # never recover. Exit cleanly with a clear message instead.
    #
    # If the operator simultaneously set VULTURE_REQUIRE_LLM=true,
    # that is a config conflict (require LLM AND opt out of LLM) —
    # fail loudly so they correct it.
    if is_skills_only():
        if is_llm_required():
            yield emitter.text_message(
                "ERROR: VULTURE_REQUIRE_LLM=true but VULTURE_USE_LLM is "
                "not set to 'true'. Configuration conflict — set "
                "VULTURE_USE_LLM=true (and provide an LLM API key) "
                "to satisfy VULTURE_REQUIRE_LLM, or unset "
                "VULTURE_REQUIRE_LLM to allow skills-only operation."
            )
            yield emitter.run_finished("failed")
            return
        yield emitter.text_message(
            "Prove agent skipped: skills-only mode "
            "(VULTURE_USE_LLM != true). Prove requires LLM for "
            "verification logic. To enable, set VULTURE_USE_LLM=true "
            "and provide an LLM API key (OPENAI_API_KEY, "
            "ANTHROPIC_API_KEY, GEMINI_API_KEY, or run Ollama). "
            "See docs/features/0043_universal_skills_llm_contract/ "
            "for the full skills/LLM dual-mode contract."
        )
        yield emitter.run_finished("skipped")
        return

    # Reset token tracking for this session
    from prove_agent.llm_helper import get_token_usage, reset_token_usage
    reset_token_usage()

    # Validate LLM availability; allow config to override model
    try:
        from shared.llm.provider import get_model
        model_preference = config.get("model")
        model = get_model(model_preference)
        yield emitter.text_message(f"Using LLM model: {model}")
    except Exception as exc:
        yield emitter.text_message(
            f"ERROR: Prove agent requires LLM but none configured: {exc}. "
            "Set VULTURE_LLM_MODEL, OPENAI_API_KEY, or ensure Ollama is running."
        )
        yield emitter.run_finished("failed")
        return

    # Pre-flight capability detection — probe HTTP, WS, JSON-RPC support
    caps_loop = asyncio.new_event_loop()
    try:
        capabilities, caps_summary = caps_loop.run_until_complete(
            detect_capabilities(staging_url)
        )
    except Exception as exc:
        yield emitter.text_message(
            f"ERROR: Staging URL unreachable: {exc}. "
            "Verify the server is running and accessible from this machine."
        )
        yield emitter.run_finished("failed")
        return
    finally:
        caps_loop.close()

    any_protocol = (
        capabilities.http or capabilities.websocket
        or capabilities.jsonrpc_http or capabilities.jsonrpc_ws
        or capabilities.grpc or capabilities.sse or capabilities.mqtt_ws
    )
    if not any_protocol:
        yield emitter.text_message(
            f"ERROR: No supported protocols detected on staging URL ({staging_url}). "
            f"Diagnostics: {caps_summary}. "
            "Verify the server is running and accessible from this machine."
        )
        yield emitter.run_finished("failed")
        return
    yield emitter.text_message(caps_summary)

    # Get findings to verify
    findings = _get_findings(config, prior_findings, source_path, types)
    if not findings:
        yield emitter.text_message(
            "No scan findings available — skipping verification, "
            "proceeding with proactive API security probing"
        )
        loop = asyncio.new_event_loop()
        try:
            yield from _run_probe_only(
                loop, emitter, staging_url, source_path,
                schemas=config.get("schemas", {}),
            )
        finally:
            loop.close()
        return

    yield emitter.text_message(
        f"Found {len(findings)} findings to verify against {staging_url}"
    )

    # Create session-scoped learnings (discovery learnings now live in discover agent)
    learnings = ProveSessionLearnings()

    loop = asyncio.new_event_loop()
    try:
        yield from _run_prove_pipeline(
            loop, emitter, findings, staging_url, types, max_iterations,
            learnings, source_path, schemas=schemas,
            capabilities=capabilities,
        )
    finally:
        loop.close()


def _run_prove_pipeline(
    loop: asyncio.AbstractEventLoop,
    emitter: AgUiEventEmitter,
    findings: list[dict],
    staging_url: str,
    types: list[str],
    max_iterations: int,
    learnings: ProveSessionLearnings,
    source_path: str,
    *,
    schemas: dict,
    capabilities: TargetCapabilities,
) -> Generator[str, None, None]:
    """Inner pipeline — separated so the caller can wrap in try/finally for loop cleanup."""

    # Phase 1: Load cached discovery (instant) — use for immediate verification
    cached_site = load_cached_discovery(staging_url)
    if cached_site:
        yield emitter.text_message(
            f"Loaded cached discovery: {len(cached_site.urls)} URLs, "
            f"{len(cached_site.api_endpoints)} API endpoints"
        )
        discovery_summary = cached_site.summary()
    else:
        discovery_summary = ""

    # Phase 2: Call discover agent in background (non-blocking)
    # Verification proceeds immediately using cached data
    bg_discovery = _BackgroundDiscovery(
        staging_url,
        source_path=source_path,
        schemas=schemas,
    )
    bg_discovery.start()
    if cached_site:
        yield emitter.text_message(
            "Fresh discovery running in background — verifying with cached data now"
        )
    else:
        yield emitter.text_message("Running site discovery via discover agent...")

    # Build initial context from cache + learnings from discover
    enriched_context = discovery_summary

    # If no cached discovery, wait for background discovery before proceeding
    if not cached_site:
        bg_discovery.wait()
        if bg_discovery.result:
            discovery_summary = bg_discovery.result.summary()
            enriched_context = discovery_summary
            if bg_discovery.learnings_context:
                enriched_context += "\n\nPRIOR SESSION LEARNINGS:\n" + bg_discovery.learnings_context
            yield emitter.text_message(
                f"Discovery: {len(bg_discovery.result.urls)} URLs, "
                f"{len(bg_discovery.result.api_endpoints)} API endpoints, "
                f"{len(bg_discovery.result.forms)} forms"
            )
        elif bg_discovery.error:
            yield emitter.text_message(
                f"Discovery failed ({bg_discovery.error}), proceeding without site map"
            )

    # Cross-finding learning: insights accumulated across all findings
    cross_learnings: list[str] = list(learnings.insights[-10:])
    learnings_ctx = bg_discovery.learnings_context
    discovered_during_verify: list[str] = []

    # Group findings by agent type and verify
    counts = {"verified": 0, "not_reproduced": 0, "inconclusive": 0, "skipped": 0}
    consecutive_conn_failures = 0  # Cross-finding circuit breaker
    global_abort = False

    for agent_type in types:
        if global_abort:
            break
        type_findings = [f for f in findings if f.get("agent_type") == agent_type]
        if not type_findings:
            continue

        strategy_cls = STRATEGY_MAP.get(agent_type)
        if not strategy_cls:
            yield emitter.text_message(f"No strategy for agent type: {agent_type}")
            continue

        strategy = strategy_cls()
        yield emitter.step_started(f"prove-{agent_type}")
        yield emitter.text_message(
            f"Verifying {len(type_findings)} {agent_type} findings"
        )

        # Verify findings with concurrency (up to 3 in parallel)
        _SEM_SIZE = 3

        async def _verify_batch(batch: list[dict], batch_offset: int) -> list[tuple[list[str], bool] | Exception]:
            """Verify a batch of findings concurrently. Semaphore created inside async context."""
            sem = asyncio.Semaphore(_SEM_SIZE)

            async def _verify_one(finding: dict, idx: int) -> tuple[list[str], bool]:
                async with sem:
                    gen = prove_finding_with_timeout(
                        finding, strategy, staging_url, max_iterations,
                        emitter, site_context=enriched_context,
                        cross_learnings=cross_learnings,
                        capabilities=capabilities,
                    )
                    evts: list[str] = []
                    async for event_str in gen:
                        evts.append(event_str)
                    had_conn = any(
                        "proof_result" in e and ("Target unreachable" in e or "Connection failed" in e)
                        for e in evts
                    )
                    return evts, had_conn

            tasks = [_verify_one(f, batch_offset + j) for j, f in enumerate(batch)]
            return await asyncio.gather(*tasks, return_exceptions=True)

        # Process in batches of _SEM_SIZE to maintain ordering and cross-learning
        batch_size = _SEM_SIZE
        for batch_start in range(0, len(type_findings), batch_size):
            if global_abort:
                counts["skipped"] += len(type_findings) - batch_start
                break

            # Check if background discovery finished — update context
            if bg_discovery.done and not bg_discovery.context_updated:
                bg_discovery.context_updated = True
                learnings_ctx = bg_discovery.learnings_context
                if bg_discovery.result:
                    discovery_summary = bg_discovery.result.summary()
                    enriched_context = discovery_summary
                    if learnings_ctx:
                        enriched_context += "\n\nPRIOR SESSION LEARNINGS:\n" + learnings_ctx
                    yield emitter.text_message(
                        f"Background discovery complete: "
                        f"{len(bg_discovery.result.urls)} URLs, "
                        f"{len(bg_discovery.result.api_endpoints)} API endpoints"
                    )

            # Incremental discovery from URLs found during verification
            if discovered_during_verify and batch_start > 0:
                try:
                    incr = loop.run_until_complete(
                        discover_incremental(staging_url, discovered_during_verify)
                    )
                    if incr.urls:
                        full = load_cached_discovery(staging_url)
                        if full:
                            enriched_context = full.summary()
                            if learnings_ctx:
                                enriched_context += "\n\nPRIOR SESSION LEARNINGS:\n" + learnings_ctx
                            yield emitter.text_message(
                                f"Incremental discovery: {len(incr.urls)} new pages crawled"
                            )
                    discovered_during_verify.clear()
                except Exception as exc:
                    logger.warning("Incremental discovery failed: %s", exc)

            batch = type_findings[batch_start:batch_start + batch_size]
            try:
                batch_results = loop.run_until_complete(_verify_batch(batch, batch_start))

                for bi, br in enumerate(batch_results):
                    if isinstance(br, Exception):
                        logger.warning("Verification failed for finding: %s", br)
                        yield emitter.text_message(f"Verification error: {br}")
                        counts["inconclusive"] += 1
                        continue

                    events, finding_had_conn_error = br
                    for event_str in events:
                        yield event_str
                        if "proof_result" in event_str:
                            _update_counts(event_str, counts)
                            _update_learnings_from_result(event_str, batch[bi], learnings)
                        if "proof_attempt" in event_str:
                            _collect_discovered_urls(event_str, discovered_during_verify)

                    if finding_had_conn_error:
                        consecutive_conn_failures += 1
                    else:
                        consecutive_conn_failures = 0

                    if consecutive_conn_failures >= _CROSS_FINDING_CIRCUIT_BREAKER:
                        remaining = len(type_findings) - (batch_start + bi + 1)
                        yield emitter.text_message(
                            f"Circuit breaker: {consecutive_conn_failures} consecutive "
                            f"connection failures — aborting remaining {max(0, remaining)} findings. "
                            "The staging URL appears unreachable."
                        )
                        counts["skipped"] += max(0, remaining)
                        global_abort = True
                        break
            except Exception as exc:
                logger.warning("Batch verification failed: %s", exc)
                yield emitter.text_message(f"Batch verification error: {exc}")
                counts["inconclusive"] += len(batch)

    # Wait for background discovery if still running
    bg_discovery.wait()

    # Phase 3: Proactive API security probing
    yield emitter.text_message("Probing discovered API endpoints for security issues...")
    full_site = None
    try:
        full_site = load_cached_discovery(staging_url)
        if full_site:
            api_findings = loop.run_until_complete(
                probe_api_endpoints(
                    staging_url, full_site.api_endpoints,
                    full_site.forms, None,
                )
            )
            if api_findings:
                yield emitter.text_message(
                    f"API probing found {len(api_findings)} additional issues"
                )
                for af in api_findings:
                    yield emitter.proof_result_event(
                        af["id"], af["status"], af["evidence"], 1,
                    )
                    counts["verified"] += 1
            else:
                yield emitter.text_message("API probing: no additional issues found")
    except Exception as exc:
        logger.warning("API probing failed: %s", exc)
        yield emitter.text_message(f"API probing skipped: {exc}")

    # Update session learnings (no longer persisted — discover owns persistence)
    learnings.insights = list(set(cross_learnings))
    learnings.total_findings_tested += len(findings)
    learnings.verified_count += counts["verified"]

    # Emit summary
    total = sum(counts.values())
    if cross_learnings:
        yield emitter.text_message(
            f"Cross-finding learnings: {len(cross_learnings)} insights saved for next session"
        )
    yield emitter.proof_summary_event(
        total=total,
        verified=counts["verified"],
        not_reproduced=counts["not_reproduced"],
        inconclusive=counts["inconclusive"],
        skipped=counts["skipped"],
    )

    # Emit token usage for the entire prove session
    from prove_agent.llm_helper import get_token_usage
    usage = get_token_usage()
    if usage.call_count > 0:
        model_key = os.environ.get("VULTURE_LLM_MODEL", "gpt-4o")
        cost = usage.estimate_cost_usd(model_key)
        yield emitter.token_savings_event(
            context_tokens=usage.input_tokens,
            raw_tokens=usage.input_tokens,  # no savings concept for prove
            prior_findings_used=len(findings),
            duplicates_removed=0,
            actual_input_tokens=usage.input_tokens,
            actual_output_tokens=usage.output_tokens,
            cost_usd=cost,
        )
        logger.info(
            "prove_token_usage calls=%d input=%d output=%d total=%d cost=$%.4f errors=%d",
            usage.call_count, usage.input_tokens, usage.output_tokens,
            usage.total_tokens, cost, usage.errors,
        )

    yield emitter.run_finished("completed")


class _BackgroundDiscovery:
    """Run discovery via HTTP call to discover agent in background thread."""

    def __init__(
        self, staging_url: str,
        *,
        source_path: str = "",
        schemas: dict[str, str] | None = None,
    ):
        self.staging_url = staging_url
        self.source_path = source_path
        self.schemas = schemas
        self.result: SiteMap | None = None
        self.learnings_context: str = ""
        self.error: Exception | None = None
        self.context_updated = False
        self._done_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def done(self) -> bool:
        return self._done_event.is_set()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            result, learnings_ctx, _ = call_discover(
                self.staging_url,
                source_path=self.source_path,
                schemas=self.schemas,
            )
            with self._lock:
                self.result = result
                self.learnings_context = learnings_ctx
        except Exception as exc:
            self.error = exc
            logger.warning("Background discovery failed: %s", exc)
        finally:
            self._done_event.set()

    def wait(self):
        if self._thread:
            self._thread.join(timeout=310)  # Slightly above discover HTTP timeout (300s)
            if self._thread.is_alive():
                logger.warning("Background discovery thread still running after wait timeout")


def _probe_discovered_endpoints(
    loop: asyncio.AbstractEventLoop,
    emitter: AgUiEventEmitter,
    staging_url: str,
) -> Generator[str, None, None]:
    """Probe discovered API endpoints for security issues."""
    full_site = load_cached_discovery(staging_url)
    if not full_site or not full_site.api_endpoints:
        yield emitter.text_message("No endpoints discovered for probing")
        return
    yield emitter.text_message(
        f"Probing {len(full_site.api_endpoints)} discovered API endpoints..."
    )
    try:
        api_findings = loop.run_until_complete(
            probe_api_endpoints(
                staging_url, full_site.api_endpoints, full_site.forms, None,
            )
        )
        if api_findings:
            yield emitter.text_message(f"API probing found {len(api_findings)} issues")
            for af in api_findings:
                yield emitter.proof_result_event(af["id"], af["status"], af["evidence"], 1)
        else:
            yield emitter.text_message("API probing: no issues found")
    except Exception as exc:
        logger.warning("API probing failed: %s", exc)
        yield emitter.text_message(f"API probing skipped: {exc}")


def _run_probe_only(
    loop: asyncio.AbstractEventLoop,
    emitter: AgUiEventEmitter,
    staging_url: str,
    source_path: str,
    *,
    schemas: dict,
) -> Generator[str, None, None]:
    """Discovery + API probing when no scan findings to verify."""
    bg = _BackgroundDiscovery(staging_url, source_path=source_path, schemas=schemas)
    bg.start()
    yield emitter.text_message("Running discovery for proactive probing...")
    bg.wait()
    if bg.result:
        yield emitter.text_message(
            f"Discovery: {len(bg.result.urls)} URLs, "
            f"{len(bg.result.api_endpoints)} API endpoints"
        )
    yield from _probe_discovered_endpoints(loop, emitter, staging_url)
    yield emitter.proof_summary_event(
        total=0, verified=0, not_reproduced=0, inconclusive=0, skipped=0,
    )
    yield emitter.run_finished("completed")


def _get_findings(
    config: dict,
    prior_findings: list[dict[str, Any]] | None,
    source_path: str,
    types: list[str],
) -> list[dict]:
    """Get findings from config, prior_findings, or backend cache."""
    config_findings = config.get("findings", [])
    if config_findings:
        return [f for f in config_findings if f.get("agent_type") in types]

    if prior_findings:
        return [f for f in prior_findings if f.get("agent_type") in types]

    try:
        url = f"{_BACKEND_URL}/api/memories/by-path?path={source_path}&limit=100"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            memories = data if isinstance(data, list) else data.get("memories", [])
            return [m for m in memories if m.get("agent_type") in types]
    except Exception as exc:
        logger.warning("Failed to fetch cached findings: %s", exc)

    return []


def _update_counts(event_str: str, counts: dict) -> None:
    """Extract status from a proof_result SSE event and update counts."""
    try:
        for line in event_str.split("\n"):
            if line.startswith("data: "):
                data = json.loads(line[6:])
                status = data.get("status", "")
                if status in counts:
                    counts[status] += 1
                return
    except (json.JSONDecodeError, Exception):
        pass


def _update_learnings_from_result(
    event_str: str, finding: dict, learnings: ProveSessionLearnings,
) -> None:
    """Extract learnings from proof results."""
    try:
        for line in event_str.split("\n"):
            if line.startswith("data: "):
                data = json.loads(line[6:])
                status = data.get("status", "")

                if status == "verified":
                    record_successful_probe(
                        learnings,
                        finding.get("category", ""),
                        "GET",
                        finding.get("file_path", ""),
                    )
                return
    except (json.JSONDecodeError, Exception):
        pass


def _collect_discovered_urls(event_str: str, urls: list[str]) -> None:
    """Extract URL paths from proof_attempt events for incremental discovery."""
    try:
        for line in event_str.split("\n"):
            if line.startswith("data: "):
                data = json.loads(line[6:])
                evidence = data.get("evidence", "")
                for word in evidence.split():
                    if word.startswith("/") and len(word) > 1:
                        if word not in urls:
                            urls.append(word)
                return
    except (json.JSONDecodeError, Exception):
        pass
