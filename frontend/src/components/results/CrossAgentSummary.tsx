import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { agentLabel } from "@/lib/constants.ts";
import type { Finding } from "@/lib/types.ts";

interface CrossAgentSummaryProps {
  findings: Finding[];
}

export function CrossAgentSummary({ findings }: CrossAgentSummaryProps) {
  const { t } = useTranslation();

  const crossAgentFindings = useMemo(() => {
    return findings.filter((f) => f.cross_agent_origins && f.cross_agent_origins.length > 0);
  }, [findings]);

  if (crossAgentFindings.length === 0) return null;

  return (
    <div className="card px-4 py-3" data-testid="cross-agent-summary">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("crossAgent.title")}</span>
        <span className="text-[11px] text-muted">
          {t("crossAgent.countLabel", { count: crossAgentFindings.length })}
        </span>
      </div>
      <div className="space-y-1.5">
        {crossAgentFindings.map((f) => (
          <div key={`${f.fingerprint}-${f.title}`} className="flex items-center gap-2 text-[12px]">
            <span className="font-medium text-foreground truncate max-w-xs">{f.title}</span>
            <span className="text-[10px] font-mono font-medium uppercase bg-cream rounded px-1.5 py-0.5 text-muted">
              {agentLabel(f.agent_type ?? "", t)}
            </span>
            <span className="text-[10px] text-muted-light italic">
              ({t("crossAgent.primary")})
            </span>
            {f.cross_agent_origins?.map((origin) => (
              <span key={origin} className="text-[10px] font-mono font-medium uppercase bg-cream/50 rounded px-1.5 py-0.5 text-muted-light">
                {agentLabel(origin, t)}
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
