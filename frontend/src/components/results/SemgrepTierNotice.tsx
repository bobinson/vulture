/**
 * Feature 0058 (R9) — "Semgrep tier not active" notice.
 *
 * The orchestrator emits a graceful-absence line ("Semgrep tier not
 * active — running skills + signatures only") into the audit stream
 * when the user ticked `semgrep` but the plugin is unavailable. This
 * banner surfaces that line as an informational notice on the results
 * page. Renders nothing when the stream carries no such line.
 *
 * Structure mirrors LLMDegradedBanner (the 0039 degraded-mode banner),
 * in an informational blue rather than warning yellow.
 */
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { StreamLine } from "@/lib/types.ts";

// Phrase pinned by the R9 orchestrator notice (stream_handler.go).
const NOTICE_PHRASE = "Semgrep tier not active";

interface SemgrepTierNoticeProps {
  lines: StreamLine[];
}

export function SemgrepTierNotice({ lines }: SemgrepTierNoticeProps) {
  const { t } = useTranslation();

  const noticed = useMemo(
    () => lines.some((l) => l.text.includes(NOTICE_PHRASE)),
    [lines],
  );

  if (!noticed) return null;

  return (
    <div
      role="status"
      data-testid="semgrep-tier-notice"
      className="border border-blue-200 bg-blue-50 rounded p-3 text-sm flex items-start gap-2"
    >
      <span aria-hidden="true" className="text-blue-700 font-bold">ℹ</span>
      <div className="flex-1 text-blue-800">{t("results.semgrepTierNotice")}</div>
    </div>
  );
}
