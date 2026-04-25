import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SeverityBadge } from "./SeverityBadge.tsx";
import type { AuditComparison } from "@/lib/types.ts";

interface AuditComparisonViewProps {
  comparison: AuditComparison;
}

type Tab = "new" | "fixed" | "changed" | "persistent";

export function AuditComparisonView({ comparison }: AuditComparisonViewProps) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("new");

  if (!comparison.has_previous) return null;

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "new", label: t("comparison.newTab"), count: comparison.new_count },
    { key: "fixed", label: t("comparison.fixedTab"), count: comparison.fixed_count },
    { key: "changed", label: t("comparison.changedTab"), count: comparison.changed_count },
    { key: "persistent", label: t("comparison.persistentTab"), count: comparison.persistent_count },
  ];

  return (
    <div className="card overflow-hidden" data-testid="audit-comparison-view">
      <button
        type="button"
        className="w-full flex items-center gap-2 px-4 py-3 text-[12px] text-muted hover:text-foreground transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <svg
          className={`w-3.5 h-3.5 transition-transform ${expanded ? "rotate-90" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className="font-semibold uppercase tracking-wider text-[11px]">{t("comparison.title")}</span>
        <span className="text-[11px] text-muted-light">
          +{comparison.new_count} / -{comparison.fixed_count} / ~{comparison.changed_count}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-border">
          {/* Tab bar */}
          <div className="flex border-b border-border">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                type="button"
                data-testid={`tab-${tab.key}`}
                className={`px-4 py-2 text-[11px] font-medium transition-colors cursor-pointer ${
                  activeTab === tab.key
                    ? "text-foreground border-b-2 border-foreground"
                    : "text-muted hover:text-foreground"
                }`}
                onClick={() => setActiveTab(tab.key)}
              >
                {tab.label} ({tab.count})
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="px-4 py-3 max-h-64 overflow-y-auto">
            {activeTab === "new" && (comparison.new_findings?.length ?? 0) > 0 && (
              <div className="space-y-1.5">
                {comparison.new_findings!.map((f) => (
                  <div key={f.fingerprint} className="flex items-center gap-2 text-[12px]">
                    {f.ref && (
                      <span
                        className="text-[10px] font-mono font-semibold text-foreground shrink-0"
                        title={`Lineage ref ${f.ref} \u2014 fingerprint ${f.fingerprint}`}
                      >
                        {f.ref}
                      </span>
                    )}
                    <SeverityBadge severity={f.severity} />
                    <span className="text-foreground truncate">{f.title}</span>
                    <span className="text-[10px] font-mono text-muted-light">{f.file_path}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "fixed" && (comparison.fixed_findings?.length ?? 0) > 0 && (
              <div className="space-y-1.5">
                {comparison.fixed_findings!.map((f) => (
                  <div key={f.fingerprint} className="flex items-center gap-2 text-[12px] text-muted">
                    <svg className="w-3.5 h-3.5 text-success shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    {f.ref && (
                      <span
                        className="text-[10px] font-mono font-semibold text-[#22C55E] shrink-0"
                        title={`Lineage ref ${f.ref} \u2014 fingerprint ${f.fingerprint}`}
                      >
                        {f.ref}
                      </span>
                    )}
                    <SeverityBadge severity={f.severity} />
                    <span className="line-through truncate">{f.title}</span>
                    <span className="text-[10px] font-mono text-muted-light">{f.file_path}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "changed" && (comparison.changed_findings?.length ?? 0) > 0 && (
              <div className="space-y-1.5">
                {comparison.changed_findings!.map((f) => (
                  <div key={f.fingerprint} className="flex items-center gap-2 text-[12px]">
                    {f.ref && (
                      <span
                        className="text-[10px] font-mono font-semibold text-foreground shrink-0"
                        title={`Lineage ref ${f.ref} \u2014 fingerprint ${f.fingerprint}`}
                      >
                        {f.ref}
                      </span>
                    )}
                    <span className="text-foreground truncate">{f.title}</span>
                    <span className="text-[10px] font-mono text-muted-light">
                      {f.old_severity.toUpperCase()} {"\u2192"} {f.new_severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-mono text-muted-light">{f.file_path}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "persistent" && (
              <div className="text-[12px] text-muted">
                {comparison.persistent_count} {t("comparison.persistentTab").toLowerCase()} findings
              </div>
            )}

            {activeTab === "new" && (comparison.new_findings?.length ?? 0) === 0 && comparison.new_count === 0 && (
              <div className="text-[12px] text-muted-light">No new findings</div>
            )}
            {activeTab === "fixed" && (comparison.fixed_findings?.length ?? 0) === 0 && comparison.fixed_count === 0 && (
              <div className="text-[12px] text-muted-light">No fixed findings</div>
            )}
            {activeTab === "changed" && (comparison.changed_findings?.length ?? 0) === 0 && comparison.changed_count === 0 && (
              <div className="text-[12px] text-muted-light">No changed findings</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
