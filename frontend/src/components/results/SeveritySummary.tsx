import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { Finding, Severity } from "@/lib/types.ts";

interface SeveritySummaryProps {
  findings: Finding[];
}

const SEV_CONFIG: Record<Severity, { labelKey: string; color: string; bg: string }> = {
  critical: { labelKey: "severity.critical", color: "text-danger", bg: "bg-[#CF222E]" },
  high: { labelKey: "severity.high", color: "text-[#9A3412]", bg: "bg-[#EA580C]" },
  medium: { labelKey: "severity.medium", color: "text-[#92400E]", bg: "bg-[#D97706]" },
  low: { labelKey: "severity.low", color: "text-[#1E40AF]", bg: "bg-[#2563EB]" },
  info: { labelKey: "severity.info", color: "text-muted", bg: "bg-[#9898A0]" },
};

export function SeveritySummary({ findings }: SeveritySummaryProps) {
  const { t } = useTranslation();
  const counts = useMemo(() => {
    const map: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      map[f.severity] = (map[f.severity] ?? 0) + 1;
    }
    return map;
  }, [findings]);

  const total = findings.length;
  if (total === 0) return null;

  return (
    <div className="card p-4">
      <div className="flex items-center gap-3 mb-3">
        <h3 className="label mb-0">{t("results.severityBreakdown")}</h3>
        <span className="text-[11px] text-muted-light">{t("results.totalCount", { count: total })}</span>
      </div>

      {/* Bar chart */}
      <div className="flex h-3 rounded-full overflow-hidden bg-cream mb-3">
        {(Object.entries(SEV_CONFIG) as [Severity, typeof SEV_CONFIG[Severity]][]).map(([sev, config]) => {
          const count = counts[sev] ?? 0;
          if (count === 0) return null;
          const width = (count / total) * 100;
          return (
            <div
              key={sev}
              className={`${config.bg} transition-all duration-500`}
              style={{ width: `${width}%` }}
              title={`${t(config.labelKey)}: ${count}`}
            />
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {(Object.entries(SEV_CONFIG) as [Severity, typeof SEV_CONFIG[Severity]][]).map(([sev, config]) => {
          const count = counts[sev] ?? 0;
          if (count === 0) return null;
          return (
            <div key={sev} className="flex items-center gap-1.5">
              <span className={`w-2.5 h-2.5 rounded-full ${config.bg}`} />
              <span className={`text-[12px] font-semibold tabular-nums ${config.color}`}>{count}</span>
              <span className="text-[11px] text-muted">{t(config.labelKey)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
