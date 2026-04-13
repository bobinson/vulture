import { useTranslation } from "react-i18next";
import type { Audit } from "@/lib/types.ts";

interface AuditHistoryTimelineProps {
  audits: Audit[];
  currentAuditId?: string;
}

export function AuditHistoryTimeline({ audits, currentAuditId }: AuditHistoryTimelineProps) {
  const { t } = useTranslation();

  if (audits.length <= 1) return null;

  // Show max 10, most recent last
  const visible = audits.slice(0, 10).reverse();

  return (
    <div className="card px-4 py-3" data-testid="audit-history-timeline">
      <div className="flex items-center gap-3 mb-3">
        <span className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("auditHistory.title")}</span>
        <span className="text-[11px] text-muted-light">{t("auditHistory.findingsCount", { count: audits.length })}</span>
      </div>

      <div className="flex items-end gap-0 overflow-x-auto">
        {visible.map((audit, i) => {
          const isCurrent = audit.id === currentAuditId;
          const count = audit.findings_count ?? 0;
          const prev = i > 0 ? (visible[i - 1].findings_count ?? 0) : count;
          const trend = count < prev ? "text-[#22C55E]" : count > prev ? "text-[#CF222E]" : "text-muted-light";
          const date = audit.completed_at ?? audit.created_at;

          return (
            <div key={audit.id} className="flex flex-col items-center min-w-[60px]">
              {/* Finding count */}
              <span className={`text-[11px] font-semibold tabular-nums ${isCurrent ? "text-accent" : trend}`}>
                {count}
              </span>

              {/* Node + connector */}
              <div className="flex items-center w-full relative h-6">
                {i > 0 && (
                  <div className={`flex-1 h-0.5 ${count <= prev ? "bg-[#22C55E]/40" : "bg-[#CF222E]/40"}`} />
                )}
                {i === 0 && <div className="flex-1" />}
                <a
                  href={`/audits/${audit.id}`}
                  className={`relative z-10 rounded-full border-2 ${
                    isCurrent
                      ? "w-4 h-4 bg-accent border-accent"
                      : "w-3 h-3 bg-surface border-border hover:border-accent"
                  } transition-colors`}
                  title={`${audit.id.slice(0, 8)} - ${count} findings`}
                />
                {i < visible.length - 1 && (
                  <div className={`flex-1 h-0.5 ${
                    (visible[i + 1].findings_count ?? 0) <= count ? "bg-[#22C55E]/40" : "bg-[#CF222E]/40"
                  }`} />
                )}
                {i === visible.length - 1 && <div className="flex-1" />}
              </div>

              {/* Date */}
              <span className="text-[9px] text-muted-light tabular-nums">
                {date ? new Date(date).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
