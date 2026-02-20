"""SSE event emitter for agent communication."""

import json
from typing import Any


class AgUiEventEmitter:
    """Emits SSE-formatted event strings per the agent protocol."""

    __slots__ = ("_run_id",)

    def __init__(self, run_id: str) -> None:
        self._run_id = run_id

    def _format(self, event: str, data: dict[str, Any]) -> str:
        """Format an SSE event string."""
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
    ) -> str:
        """Emit finding event."""
        return self._format("finding", {
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "recommendation": recommendation,
        })

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
        """Emit result event."""
        return self._format("result", {
            "findings": findings,
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
    ) -> str:
        """Emit token_savings event showing memory-based optimization."""
        saved = max(0, raw_tokens - context_tokens)
        pct = round(saved / raw_tokens * 100) if raw_tokens > 0 else 0
        data: dict[str, Any] = {
            "context_tokens": context_tokens,
            "raw_tokens": raw_tokens,
            "tokens_saved": saved,
            "savings_pct": pct,
            "prior_findings_used": prior_findings_used,
            "duplicates_removed": duplicates_removed,
        }
        if actual_input_tokens > 0:
            data["actual_input_tokens"] = actual_input_tokens
        if actual_output_tokens > 0:
            data["actual_output_tokens"] = actual_output_tokens
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

    def run_finished(self, status: str = "completed") -> str:
        """Emit agent_end event."""
        return self._format("agent_end", {
            "run_id": self._run_id,
            "status": status,
        })
