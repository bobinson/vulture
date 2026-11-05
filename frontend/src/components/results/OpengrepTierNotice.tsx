/**
 * Feature 0058 (R9) — "Opengrep tier not active" notice for the bundled SAST
 * plugin (Opengrep since 0102).
 *
 * The orchestrator emits a graceful-absence line ("opengrep tier not
 * active (agent unavailable); ...") into the audit stream when the user
 * ticked the plugin but it is unavailable. This banner surfaces that line as
 * an informational notice on the results page. Renders nothing when the
 * stream carries no such line.
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
const NOTICE_RE = /\bopengrep tier not active/i;

interface OpengrepTierNoticeProps {
  lines: StreamLine[];
}

export function OpengrepTierNotice({ lines }: OpengrepTierNoticeProps) {
  const { t } = useTranslation();
  const active = useMemo(() => lines.some((l) => NOTICE_RE.test(l.text)), [lines]);

  if (!active) return null;

  return (
    <div
      role="status"
      data-testid="opengrep-tier-notice"
      className="border border-blue-200 bg-blue-50 rounded p-3 text-sm flex items-start gap-2"
    >
      <span aria-hidden="true" className="text-blue-700 font-bold">ℹ</span>
      <div className="flex-1 text-blue-800">{t("results.opengrepTierNotice")}</div>
    </div>
  );
}
