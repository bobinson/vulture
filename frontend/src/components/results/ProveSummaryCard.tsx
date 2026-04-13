import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { ProveResult } from "@/lib/types.ts";

interface ProveSummaryCardProps {
  results: ProveResult[];
  totalFindings: number;
}

const BAR_COLORS: Record<string, string> = {
  verified: "bg-[#CF222E]",
  not_reproduced: "bg-[#22C55E]",
  inconclusive: "bg-[#D97706]",
  skipped: "bg-[#9898A0]",
};

const TEXT_COLORS: Record<string, string> = {
  verified: "text-[#991B1B]",
  not_reproduced: "text-[#166534]",
  inconclusive: "text-[#92400E]",
  skipped: "text-[#6B7280]",
};

export function ProveSummaryCard({ results, totalFindings }: ProveSummaryCardProps) {
  const { t } = useTranslation();

  const counts = useMemo(() => {
    const m: Record<string, number> = { verified: 0, not_reproduced: 0, inconclusive: 0, skipped: 0 };
    for (const r of results) {
      m[r.status] = (m[r.status] ?? 0) + 1;
    }
    return m;
  }, [results]);

  const tested = results.length;
  const untested = totalFindings - tested;

  if (tested === 0) return null;

  return (
    <div className="card px-4 py-3" data-testid="prove-summary-card">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("proveSummary.title")}</span>
        <span className="text-[11px] text-muted">
          {tested} of {totalFindings} {t("proveSummary.verified").toLowerCase()}
        </span>
      </div>

      {/* Progress bar */}
      <div className="flex h-2.5 rounded-full overflow-hidden bg-cream mb-2">
        {(["verified", "not_reproduced", "inconclusive", "skipped"] as const).map((status) => {
          const count = counts[status] ?? 0;
          if (count === 0) return null;
          const width = (count / totalFindings) * 100;
          return (
            <div
              key={status}
              className={`${BAR_COLORS[status]} transition-all duration-500`}
              style={{ width: `${width}%` }}
            />
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
        {(["verified", "not_reproduced", "inconclusive", "skipped"] as const).map((status) => {
          const count = counts[status] ?? 0;
          if (count === 0) return null;
          const label = status === "not_reproduced" ? t("prove.notReproduced") : t(`prove.${status}`);
          return (
            <span key={status} className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${BAR_COLORS[status]}`} />
              <span className={`font-semibold tabular-nums ${TEXT_COLORS[status]}`}>{count}</span>
              <span className="text-muted">{label}</span>
            </span>
          );
        })}
        {untested > 0 && (
          <span className="text-muted-light">{untested} {t("proveSummary.untested")}</span>
        )}
      </div>
    </div>
  );
}
