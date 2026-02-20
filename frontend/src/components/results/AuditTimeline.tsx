import { useTranslation } from "react-i18next";
import { agentLabel } from "@/lib/constants.ts";
import type { AgentStep } from "@/lib/types.ts";

interface AuditTimelineProps {
  steps: AgentStep[];
}

const STATUS_CONFIG: Record<string, { color: string; bg: string; ring: string }> = {
  pending: { color: "text-muted-light", bg: "bg-cream", ring: "border-border" },
  running: { color: "text-accent", bg: "bg-accent/10", ring: "border-accent" },
  complete: { color: "text-success", bg: "bg-success/10", ring: "border-success" },
  failed: { color: "text-danger", bg: "bg-danger/10", ring: "border-danger" },
};

function StepIcon({ status }: { status: string }) {
  if (status === "complete") {
    return (
      <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    );
  }
  if (status === "failed") {
    return (
      <svg className="w-3.5 h-3.5 text-danger" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
      </svg>
    );
  }
  if (status === "running") {
    return <div className="w-2.5 h-2.5 rounded-full bg-accent animate-pulse" />;
  }
  return <div className="w-2.5 h-2.5 rounded-full bg-border" />;
}

export function AuditTimeline({ steps }: AuditTimelineProps) {
  const { t } = useTranslation();

  if (steps.length === 0) {
    return (
      <div className="card p-6 text-center">
        <div className="w-4 h-4 border-2 border-accent/30 border-t-accent rounded-full animate-spin mx-auto mb-3" />
        <p className="text-[12px] text-muted">{t("results.waitingAgents")}</p>
      </div>
    );
  }

  return (
    <div className="card p-4">
      <h3 className="label mb-4">{t("results.timeline")}</h3>
      <div className="space-y-0">
        {steps.map((step, i) => {
          const config = STATUS_CONFIG[step.status] ?? STATUS_CONFIG.pending;
          const isLast = i === steps.length - 1;
          return (
            <div key={step.agent_id} className="flex gap-3">
              {/* Timeline connector */}
              <div className="flex flex-col items-center">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center ${config.bg} border ${config.ring}`}>
                  <StepIcon status={step.status} />
                </div>
                {!isLast && <div className="w-px h-4 bg-border" />}
              </div>
              {/* Content */}
              <div className="flex-1 pb-3">
                <p className="text-[13px] font-medium text-foreground">{agentLabel(step.agent_id, t)}</p>
                <p className={`text-[11px] ${config.color}`}>
                  {t(`common.${step.status}`)}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
