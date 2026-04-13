"""SSE event emitter for agent communication."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AgUiEventEmitter:
    """Emits SSE-formatted event strings per the agent protocol."""

    __slots__ = ("_run_id",)

    def __init__(self, run_id: str) -> None:
        self._run_id = run_id

    def _format(self, event: str, data: dict[str, Any]) -> str:
        """Format an SSE event string."""
        logger.debug("emit event=%s run_id=%s", event, self._run_id)
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    def run_started(self) -> str:
        """Emit agent_start event."""
        return self._format("agent_start", {
            "agent_name": "",
            "run_id": self._run_id,
        })

    def step_started(self, step_name: str) -> str:
        """Emit step start event."""
        return self._format("step_start", {
            "step_name": step_name,
            "run_id": self._run_id,
        })

    def text_message(self, content: str) -> str:
        """Emit thinking event."""
        return self._format("thinking", {"content": content})

    def tool_call(self, tool: str, args: dict[str, Any]) -> str:
        """Emit tool_call event."""
        return self._format("tool_call", {"tool": tool, "args": args})

    def finding_event(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        file_path: str = "",
        line_start: int = 0,
        line_end: int = 0,
        recommendation: str = "",
        **extra: Any,
    ) -> str:
        """Emit finding event.

        Extra keyword arguments (e.g. cwe_name, cwe_likelihood) are included
        in the event payload so enriched metadata flows through to the frontend.
        """
        data: dict[str, Any] = {
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "recommendation": recommendation,
        }
        if extra:
            data.update(extra)
        return self._format("finding", data)

    def progress_event(
        self,
        files_analyzed: int,
        total_files: int,
        findings_count: int,
    ) -> str:
        """Emit progress event."""
        return self._format("progress", {
            "files_analyzed": files_analyzed,
            "total_files": total_files,
            "findings_count": findings_count,
        })

    def result_event(
        self,
        findings: list[dict[str, Any]],
        summary: str,
        score: float,
    ) -> str:
        """Emit result event with findings and summary."""
        return self._format("result", {
            "findings": findings,
            "findings_count": len(findings),
            "summary": summary,
            "score": score,
        })

    def token_savings_event(
        self,
        context_tokens: int,
        raw_tokens: int,
        prior_findings_used: int,
        duplicates_removed: int,
        actual_input_tokens: int = 0,
        actual_output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> str:
        """Emit token_savings event showing memory-based optimization."""
        saved = max(0, raw_tokens - context_tokens)
        pct = round(saved / raw_tokens * 100) if raw_tokens > 0 else 0
        data: dict[str, Any] = {
            "context_tokens": context_tokens,
            "raw_tokens": raw_tokens,
            # Clarifying aliases for backward compatibility
            "estimated_context_tokens": context_tokens,
            "estimated_raw_tokens": raw_tokens,
            "tokens_saved": saved,
            "savings_pct": pct,
            "prior_findings_used": prior_findings_used,
            "duplicates_removed": duplicates_removed,
        }
        if actual_input_tokens > 0:
            data["actual_input_tokens"] = actual_input_tokens
        if actual_output_tokens > 0:
            data["actual_output_tokens"] = actual_output_tokens
        if cost_usd > 0.0:
            data["cost_usd"] = round(cost_usd, 6)
        return self._format("token_savings", data)

    def dedup_stats_event(
        self,
        findings_deduped: int,
        prior_findings_used: int,
        duplicates_removed: int,
    ) -> str:
        """Emit dedup_stats event for skill-mode deduplication metrics."""
        return self._format("dedup_stats", {
            "findings_deduped": findings_deduped,
            "prior_findings_used": prior_findings_used,
            "duplicates_removed": duplicates_removed,
        })

    def discover_result_event(
        self,
        target_url: str,
        site_map: Any,
        learnings_context: str = "",
    ) -> str:
        """Emit discover_result event with full SiteMap data."""
        site_dict: dict[str, Any] = {
            "target_url": target_url,
            "url_count": len(site_map.urls),
            "api_count": len(site_map.api_endpoints),
            "form_count": len(site_map.forms),
            "technologies": site_map.technologies,
            "site_map_json": site_map.to_json(),
            "learnings_context": learnings_context,
        }
        return self._format("discover_result", site_dict)

    def proof_phase_event(
        self,
        finding_id: str,
        phase: str,
        iteration: int,
    ) -> str:
        """Emit proof_phase event for live phase tracking."""
        return self._format("proof_phase", {
            "finding_id": finding_id,
            "phase": phase,
            "iteration": iteration,
        })

    def proof_plan_event(
        self,
        finding_id: str,
        title: str,
        plan_text: str,
        iteration: int,
        protocol: str = "",
    ) -> str:
        """Emit proof_plan event showing verification plan."""
        data: dict[str, Any] = {
            "finding_id": finding_id,
            "title": title,
            "plan_text": plan_text,
            "iteration": iteration,
        }
        if protocol:
            data["protocol"] = protocol
        return self._format("proof_plan", data)

    def proof_review_event(
        self,
        finding_id: str,
        safe: bool,
        concerns: list[str],
        iteration: int,
    ) -> str:
        """Emit proof_review event showing safety review."""
        return self._format("proof_review", {
            "finding_id": finding_id,
            "safe": safe,
            "concerns": concerns,
            "iteration": iteration,
        })

    def proof_attempt_event(
        self,
        finding_id: str,
        reproduced: bool,
        evidence: str,
        iteration: int,
        protocol: str = "",
    ) -> str:
        """Emit proof_attempt event showing execution result."""
        data: dict[str, Any] = {
            "finding_id": finding_id,
            "reproduced": reproduced,
            "evidence": evidence,
            "iteration": iteration,
        }
        if protocol:
            data["protocol"] = protocol
        return self._format("proof_attempt", data)

    def proof_reflection_event(
        self,
        finding_id: str,
        analysis: str,
        suggested_approach: str,
        confidence: int,
        iteration: int,
    ) -> str:
        """Emit proof_reflection event showing self-learning analysis."""
        return self._format("proof_reflection", {
            "finding_id": finding_id,
            "analysis": analysis,
            "suggested_approach": suggested_approach,
            "confidence": confidence,
            "iteration": iteration,
        })

    def proof_result_event(
        self,
        finding_id: str,
        status: str,
        evidence: str,
        iterations_used: int,
        staging_url: str = "",
    ) -> str:
        """Emit proof_result event with final verdict per finding."""
        return self._format("proof_result", {
            "finding_id": finding_id,
            "status": status,
            "evidence": evidence,
            "iterations_used": iterations_used,
            "staging_url": staging_url,
        })

    def proof_summary_event(
        self,
        total: int,
        verified: int,
        not_reproduced: int,
        inconclusive: int,
        skipped: int,
    ) -> str:
        """Emit proof_summary event with overall verification results."""
        return self._format("proof_summary", {
            "total": total,
            "verified": verified,
            "not_reproduced": not_reproduced,
            "inconclusive": inconclusive,
            "skipped": skipped,
        })

    def run_finished(self, status: str = "completed") -> str:
        """Emit agent_end event."""
        return self._format("agent_end", {
            "run_id": self._run_id,
            "status": status,
        })
