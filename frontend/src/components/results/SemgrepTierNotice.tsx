/**
 * Feature 0058 (R9) — "<engine> tier not active" notice for the bundled SAST
 * plugin.
 *
 * The orchestrator emits a graceful-absence line ("opengrep tier not
 * active (agent unavailable); ...") into the audit stream when the user
 * ticked the plugin but it is unavailable. This banner surfaces that line as
 * an informational notice on the results page, naming the engine it matched:
 * `opengrep` since 0102, `semgrep` in older audits and their replays. The
 * name and the `semgrep-tier-notice` test id are kept for those audits and
 * the 0058 E2E contract. Renders nothing when the stream carries no such line.
 *
 * Structure mirrors LLMDegradedBanner (the 0039 degraded-mode banner),
 * in an informational blue rather than warning yellow.
 */
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { StreamLine } from "@/lib/types.ts";

// Phrase pinned by the R9 orchestrator notice: the backend emits
// "<agentType> tier not active (agent unavailable); ..." (see
// agentUnavailableEvent in stream_service.go), where agentType is the
// lowercase plugin name. Matched case-INSENSITIVELY so the real backend
// event is detected, not just the capitalized wording used in fixtures.
const NOTICE_RE = /\b(opengrep|semgrep) tier not active/i;
const ENGINE_NAMES: Record<string, string> = { opengrep: "Opengrep", semgrep: "Semgrep" };

function noticedEngine(lines: StreamLine[]): string | null {
  for (const l of lines) {
    const m = NOTICE_RE.exec(l.text);
    if (m) return ENGINE_NAMES[m[1].toLowerCase()];
  }
  return null;
}

interface SemgrepTierNoticeProps {
  lines: StreamLine[];
}

export function SemgrepTierNotice({ lines }: SemgrepTierNoticeProps) {
  const { t } = useTranslation();
  const engine = useMemo(() => noticedEngine(lines), [lines]);

  if (!engine) return null;

  return (
    <div
      role="status"
      data-testid="semgrep-tier-notice"
      data-engine={engine}
      className="border border-blue-200 bg-blue-50 rounded p-3 text-sm flex items-start gap-2"
    >
      <span aria-hidden="true" className="text-blue-700 font-bold">ℹ</span>
      <div className="flex-1 text-blue-800">{t("results.semgrepTierNotice", { engine })}</div>
    </div>
  );
}
