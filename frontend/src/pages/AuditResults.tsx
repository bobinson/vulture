import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAudit } from "@/hooks/useAudit.ts";
import { useAgentStream } from "@/hooks/useAgentStream.ts";
import { AgentStream } from "@/components/results/AgentStream.tsx";
import { AuditTimeline } from "@/components/results/AuditTimeline.tsx";
import { FindingsTable } from "@/components/results/FindingsTable.tsx";
import { ScoreCard } from "@/components/results/ScoreCard.tsx";
import { SeveritySummary } from "@/components/results/SeveritySummary.tsx";
import { TokenSavings } from "@/components/results/TokenSavings.tsx";
import { agentLabel } from "@/lib/constants.ts";
import { api } from "@/lib/api.ts";
import type { AuditStatus, AgentStep, Source, StreamLine } from "@/lib/types.ts";

const STATUS_STYLES: Record<AuditStatus, string> = {
  pending: "bg-[#FEF3C7] text-[#92400E] border-[#FDE68A]",
  running: "bg-[#DBEAFE] text-[#1E40AF] border-[#BFDBFE]",
  completed: "bg-[#DCFCE7] text-[#166534] border-[#BBF7D0]",
  failed: "bg-[#FEE2E2] text-[#991B1B] border-[#FECACA]",
};

export function AuditResults() {
  const { id } = useParams<{ id: string }>();
  const { t } = useTranslation();
  const { audit } = useAudit(id);

  const status = audit?.status ?? "pending";
  const isTerminal = status === "completed" || status === "failed";

  // Track whether we ever received live stream data (persists via state)
  const [hadLiveStream, setHadLiveStream] = useState(false);

  // Disable SSE when audit already terminal and we never had a live stream
  const { lines: streamLines, steps: streamSteps, connected, done: streamDone, tokenSavings, dedupStats } = useAgentStream(id, isTerminal && !hadLiveStream);

  // Once stream data arrives, flag it (one-way latch)
  if (streamLines.length > 0 && !hadLiveStream) {
    setHadLiveStream(true);
  }

  const auditTypes = audit?.types;
  const auditCompletedAt = audit?.completed_at;
  const auditCreatedAt = audit?.created_at;
  const completedSteps: AgentStep[] = useMemo(() => {
    if (!isTerminal || !auditTypes || hadLiveStream) return [];
    return auditTypes.map((agentType) => ({
      agent_id: agentType,
      label: agentType,
      status: status === "completed" ? "complete" as const : "failed" as const,
      timestamp: auditCompletedAt ?? auditCreatedAt ?? "",
    }));
  }, [isTerminal, auditTypes, auditCompletedAt, auditCreatedAt, status, hadLiveStream]);

  const completedLines: StreamLine[] = useMemo(() => {
    if (!isTerminal || !audit || hadLiveStream) return [];
    const ts = audit.completed_at ? new Date(audit.completed_at) : new Date(audit.created_at);
    const result: StreamLine[] = [];
    let counter = 0;
    for (const agentType of audit.types ?? []) {
      result.push({ id: `c-${++counter}`, text: t("results.agentStarted", { agent: agentType }), type: "step", timestamp: ts });
      result.push({ id: `c-${++counter}`, text: t("results.agentFinished", { agent: agentType }), type: "step", timestamp: ts });
    }
    const findingCount = audit.findings?.length ?? 0;
    if (findingCount > 0) {
      result.push({ id: `c-${++counter}`, text: t("results.findingsCount", { count: findingCount }), type: "finding", timestamp: ts });
    }
    const label = status === "completed" ? t("results.auditCompleted") : t("common.failed");
    result.push({ id: `c-${++counter}`, text: label, type: "step", timestamp: ts });
    return result;
  }, [isTerminal, audit, status, t, hadLiveStream]);

  const useSynthetic = isTerminal && !hadLiveStream;
  const lines = useSynthetic ? completedLines : streamLines;
  const steps = useSynthetic ? completedSteps : streamSteps;
  const done = isTerminal ? true : streamDone;

  const findings = audit?.findings ?? [];
  const scores = audit?.scores ?? {};
  const hasScores = Object.keys(scores).length > 0;

  // Source data for git context
  const [source, setSource] = useState<Source | null>(null);
  useEffect(() => {
    if (!audit?.source_id) return;
    api.getSource(audit.source_id).then(setSource).catch(() => {});
  }, [audit?.source_id]);

  // For completed audits, agent output is collapsed by default
  const [showStream, setShowStream] = useState(false);

  // --- COMPLETED / FAILED layout: findings-first ---
  if (isTerminal) {
    return (
      <div className="space-y-5 max-w-6xl">
        {/* Status bar */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className={`badge border ${STATUS_STYLES[status]}`}>
              {t(`common.${status}`)}
            </span>
            <span className="text-[11px] text-muted-light font-mono" title={id}>{id?.slice(0, 11)}</span>
          </div>
          {audit?.source_path && (
            <div className="flex items-center gap-2 text-[12px] text-muted">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
              </svg>
              <span className="font-medium truncate max-w-xs" title={audit.source_path}>
                {audit.source_path}
              </span>
            </div>
          )}
        </div>

        {/* Git context from source */}
        {source && (source.git_branch || source.git_commit_short) && (
          <div className="flex items-center gap-4 text-[12px] text-muted">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
            </svg>
            <span className="font-semibold uppercase tracking-wider text-[11px]">{t("lineage.gitContext")}</span>
            {source.git_branch && (
              <span>
                {t("lineage.branch")}: <span className="font-mono bg-cream rounded px-2 py-0.5">{source.git_branch}</span>
              </span>
            )}
            {source.git_commit_short && (
              <span>
                {t("lineage.commit")}: <span className="font-mono bg-cream rounded px-2 py-0.5">{source.git_commit_short}</span>
              </span>
            )}
          </div>
        )}

        {/* Summary row: scores + severity side-by-side */}
        {(hasScores || findings.length > 0) && (
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-5 items-start">
            {/* Severity breakdown */}
            {findings.length > 0 && (
              <SeveritySummary findings={findings} />
            )}

            {/* Score cards - horizontal */}
            {hasScores && (
              <div className="flex gap-3">
                {Object.entries(scores).map(([agent, score]) => (
                  <ScoreCard key={agent} label={agentLabel(agent, t)} score={score} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Token savings from memory optimization */}
        {(tokenSavings || dedupStats) && <TokenSavings savings={tokenSavings} dedupStats={dedupStats} />}

        {/* Agent timeline - compact horizontal for completed */}
        {steps.length > 0 && (
          <div className="card px-4 py-3">
            <div className="flex items-center gap-6">
              <span className="text-[11px] font-semibold text-muted uppercase tracking-wider shrink-0">{t("results.timeline")}</span>
              {steps.map((step) => {
                const isComplete = step.status === "complete";
                const isFailed = step.status === "failed";
                return (
                  <div key={step.agent_id} className="flex items-center gap-2">
                    {isComplete && (
                      <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                    {isFailed && (
                      <svg className="w-3.5 h-3.5 text-danger" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )}
                    {!isComplete && !isFailed && (
                      <div className="w-2.5 h-2.5 rounded-full bg-border" />
                    )}
                    <span className="text-[12px] font-medium text-foreground">{agentLabel(step.agent_id, t)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* No findings state */}
        {findings.length === 0 && (
          <div className="card p-8 text-center">
            <svg className="w-10 h-10 text-success mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-[13px] text-muted">{t("results.noFindings")}</p>
          </div>
        )}

        {/* Findings table - full width */}
        {findings.length > 0 && (
          <FindingsTable findings={findings} auditId={id} />
        )}

        {/* Agent output - collapsible, collapsed by default */}
        <div>
          <button
            type="button"
            className="flex items-center gap-2 text-[12px] text-muted hover:text-foreground transition-colors cursor-pointer mb-2"
            onClick={() => setShowStream((v) => !v)}
          >
            <svg
              className={`w-3.5 h-3.5 transition-transform ${showStream ? "rotate-90" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
            {showStream ? t("results.hideOutput") : t("results.showOutput")}
          </button>
          {showStream && (
            <AgentStream lines={lines} connected={true} done={true} />
          )}
        </div>
      </div>
    );
  }

  // --- RUNNING / PENDING layout: stream-first ---
  return (
    <div className="space-y-5 max-w-6xl">
      {/* Status bar */}
      <div className="flex items-center gap-4">
        <span className={`badge border ${STATUS_STYLES[status]}`}>
          {t(`common.${status}`)}
        </span>
        <span className="text-[11px] text-muted-light font-mono">{id}</span>
      </div>

      {/* Main grid: stream + timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
          <AgentStream lines={lines} connected={connected} done={done} />
        </div>

        <div className="space-y-5">
          <AuditTimeline steps={steps} />

          {hasScores && (
            <div>
              <h3 className="label mb-3">{t("results.scores")}</h3>
              <div className="grid grid-cols-1 gap-3">
                {Object.entries(scores).map(([agent, score]) => (
                  <ScoreCard key={agent} label={agentLabel(agent, t)} score={score} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Token savings */}
      {(tokenSavings || dedupStats) && <TokenSavings savings={tokenSavings} dedupStats={dedupStats} />}

      {/* Findings as they arrive */}
      {findings.length > 0 && (
        <>
          <SeveritySummary findings={findings} />
          <FindingsTable findings={findings} auditId={id} />
        </>
      )}
    </div>
  );
}
