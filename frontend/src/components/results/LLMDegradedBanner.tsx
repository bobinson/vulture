/**
 * Feature 0039: degraded-mode banner.
 *
 * Renders the canonical LLMHealthStatus.message() when LLM is unreachable.
 *
 * Two render modes:
 *   - preset (string): used on AuditResults — pass audit.degraded_reason so
 *     the banner reflects the LLM state at audit-creation time, not the
 *     live state right now.
 *   - no preset: used on AuditNew — polls /api/llm/health live to warn
 *     before the user submits.
 *
 * Returns null when LLM is reachable, when LLM is intentionally disabled
 * (provider="disabled"), or when the health endpoint is unreachable.
 */
import { useLLMHealth } from "@/hooks/useLLMHealth.ts";

interface Props {
  /** When set (truthy), this exact string is rendered. Used for the
   *  per-audit case where audit.degraded_reason persists the message
   *  recorded at audit-creation time. */
  preset?: string;
}

export function LLMDegradedBanner({ preset }: Props) {
  const { health } = useLLMHealth();

  // Per-audit preset takes precedence — even if LLM has since recovered,
  // we want to show the historical degraded state for this audit.
  let text: string | null = null;
  if (preset && preset.trim() !== "") {
    text = preset;
  } else if (
    health &&
    !health.reachable &&
    health.provider !== "disabled"
  ) {
    text = health.message;
  }

  if (!text) return null;

  return (
    <div
      role="alert"
      className="border border-yellow-300 bg-yellow-50 rounded p-3 text-sm flex items-start gap-2"
    >
      <span aria-hidden="true" className="text-yellow-700 font-bold">⚠</span>
      <div className="flex-1">
        <strong className="text-yellow-900">Audit running in degraded mode.</strong>{" "}
        <span className="text-yellow-800">{text}</span>
      </div>
    </div>
  );
}
