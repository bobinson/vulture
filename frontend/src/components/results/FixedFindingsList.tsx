import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SeverityBadge } from "./SeverityBadge.tsx";
import type { ComparisonFindingSummary } from "@/lib/types.ts";

interface FixedFindingsListProps {
  findings: ComparisonFindingSummary[];
}

export function FixedFindingsList({ findings }: FixedFindingsListProps) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  if (findings.length === 0) return null;

  return (
    <div className="card overflow-hidden" data-testid="fixed-findings-list">
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
        <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
        <span className="font-semibold uppercase tracking-wider text-[11px]">{t("comparison.fixedSinceLastScan")}</span>
        <span className="text-[11px] text-muted-light">({findings.length})</span>
      </button>

      {expanded && (
        <div className="border-t border-border divide-y divide-border">
          {findings.map((f) => (
            <div key={f.fingerprint} className="flex items-center gap-2 px-4 py-2 border-l-2 border-[#22C55E]">
              {f.ref && (
                <span
                  className="text-[10px] font-mono font-semibold text-[#22C55E] shrink-0"
                  title={`Lineage ref ${f.ref} — fingerprint ${f.fingerprint}`}
                >
                  {f.ref}
                </span>
              )}
              <SeverityBadge severity={f.severity} />
              <span className="text-[12px] text-muted truncate">{f.title}</span>
              <span className="text-[10px] font-mono text-muted-light ml-auto shrink-0">{f.file_path}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
