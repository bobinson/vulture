import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLineage } from "@/hooks/useLineage.ts";
import { useCopyFeedback } from "@/hooks/useCopyFeedback.ts";
import { proveResultToMarkdown } from "@/lib/markdown.ts";
import { LineageStatusBadge } from "./LineageStatusBadge.tsx";
import { FindingTimeline } from "./FindingTimeline.tsx";
import { safeExternalUrl } from "@/lib/types.ts";
import type { Finding, ProveResult, ProveStatus, LineageStatus } from "@/lib/types.ts";

interface ProveResultsProps {
  results: ProveResult[];
  findings: Finding[];
  auditId?: string;
}

const STATUS_CONFIG: Record<ProveStatus, { color: string; bg: string; bgLight: string; border: string }> = {
  verified: { color: "text-[#991B1B]", bg: "bg-[#CF222E]", bgLight: "bg-[#FEE2E2]", border: "border-l-2 border-[#CF222E]" },
  not_reproduced: { color: "text-[#166534]", bg: "bg-[#22C55E]", bgLight: "bg-[#DCFCE7]", border: "border-l-2 border-[#22C55E]" },
  inconclusive: { color: "text-[#92400E]", bg: "bg-[#D97706]", bgLight: "bg-[#FEF3C7]", border: "border-l-2 border-[#D97706]" },
  skipped: { color: "text-[#6B7280]", bg: "bg-[#9898A0]", bgLight: "bg-[#F3F4F6]", border: "border-l-2 border-[#9898A0]" },
};

function statusI18nKey(status: ProveStatus): string {
  if (status === "not_reproduced") return "prove.notReproduced";
  return `prove.${status}`;
}

function ProveCopyButton({ result, finding, auditId }: { result: ProveResult; finding: Finding; auditId?: string }) {
  const { copied, onCopy } = useCopyFeedback();
  return (
    <button
      type="button"
      data-testid="prove-copy-btn"
      className="w-7 h-7 inline-flex items-center justify-center rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
      title="Copy"
      onClick={(e) => { e.stopPropagation(); void onCopy(proveResultToMarkdown(result, finding, auditId)); }}
    >
      {copied ? (
        <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

const STATUSES: LineageStatus[] = ["open", "in_progress", "resolved", "accepted_risk", "false_positive", "fixed", "regression"];

export function ProveResults({ results, findings, auditId }: ProveResultsProps) {
  const { t } = useTranslation();
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const { copied: allCopied, onCopy: onCopyAll } = useCopyFeedback();
  const { lineageMap, timelineMap, showTimeline, editingLineage, savedFeedback, proveHistoryMap, loadTimeline, loadProveHistory, updateEdit, saveStatus } = useLineage(auditId);
  const [showVerificationHistory, setShowVerificationHistory] = useState<string | null>(null);

  const counts = useMemo(() => {
    const map: Record<string, number> = { verified: 0, not_reproduced: 0, inconclusive: 0, skipped: 0 };
    for (const r of results) {
      map[r.status] = (map[r.status] ?? 0) + 1;
    }
    return map;
  }, [results]);

  const findingMap = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);

  const total = results.length;
  if (total === 0) return null;

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <h3 className="label mb-0">{t("prove.verificationResults")}</h3>
        <span className="text-[11px] text-muted-light">{t("results.totalCount", { count: total })}</span>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors cursor-pointer text-muted hover:text-foreground hover:bg-cream-dark"
          onClick={() => {
            const md = results
              .map((r) => {
                const f = findingMap.get(r.finding_id);
                return f ? proveResultToMarkdown(r, f, auditId) : "";
              })
              .filter(Boolean)
              .join("\n---\n\n");
            void onCopyAll(md);
          }}
        >
          {allCopied ? (
            <>
              <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              {t("results.copied")}
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              {t("prove.copyAllResults")}
            </>
          )}
        </button>
      </div>

      {/* Summary bar */}
      <div className="card p-4">
        <div className="flex h-3 rounded-full overflow-hidden bg-cream mb-3">
          {(Object.entries(STATUS_CONFIG) as [ProveStatus, typeof STATUS_CONFIG[ProveStatus]][]).map(([status, config]) => {
            const count = counts[status] ?? 0;
            if (count === 0) return null;
            const width = (count / total) * 100;
            return (
              <div
                key={status}
                className={`${config.bg} transition-all duration-500`}
                style={{ width: `${width}%` }}
                title={`${t(statusI18nKey(status))}: ${count}`}
              />
            );
          })}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {(Object.entries(STATUS_CONFIG) as [ProveStatus, typeof STATUS_CONFIG[ProveStatus]][]).map(([status, config]) => {
            const count = counts[status] ?? 0;
            if (count === 0) return null;
            return (
              <div key={status} className="flex items-center gap-1.5">
                <span className={`w-2.5 h-2.5 rounded-full ${config.bg}`} />
                <span className={`text-[12px] font-semibold tabular-nums ${config.color}`}>{count}</span>
                <span className="text-[11px] text-muted">{t(statusI18nKey(status))}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Results list */}
      <div className="card divide-y divide-border">
        {results.map((result) => {
          const finding = findingMap.get(result.finding_id);
          const config = STATUS_CONFIG[result.status] ?? STATUS_CONFIG.skipped;
          const isExpanded = expandedIds.has(result.id);
          const fingerprint = finding?.fingerprint;
          const lineage = fingerprint ? lineageMap.get(fingerprint) : undefined;
          return (
            <div key={result.id} className={`px-4 py-3 ${config.border}`}>
              <div className="flex items-start gap-3">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium shrink-0 mt-0.5 ${config.bgLight} ${config.color}`}
                >
                  {t(statusI18nKey(result.status))}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[12px] font-medium text-foreground truncate">
                      {finding?.title ?? result.finding_id}
                    </span>
                    {finding?.agent_type && (
                      <span className="text-[10px] font-mono font-medium uppercase bg-cream rounded px-1.5 py-0.5 text-muted">
                        {finding.agent_type}
                      </span>
                    )}
                    {finding?.severity && (
                      <span className="text-[10px] font-medium uppercase text-muted-light">
                        {finding.severity}
                      </span>
                    )}
                    {lineage && (
                      <LineageStatusBadge status={lineage.current_status} />
                    )}
                  </div>
                  {finding?.file_path && (
                    <div className="text-[10px] font-mono text-muted-light mt-0.5">
                      {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}
                    </div>
                  )}
                  {(finding?.check_id || finding?.fingerprint) && (
                    <div className="flex items-center gap-3 text-[10px] text-muted-light mt-0.5">
                      {finding.check_id && (
                        <span>
                          {t("lineage.checkId")}:{" "}
                          <span className="font-mono bg-cream rounded px-1 py-0.5">{finding.check_id}</span>
                        </span>
                      )}
                      {finding.fingerprint && (
                        <span>
                          {t("lineage.fingerprint")}:{" "}
                          <span className="font-mono bg-cream rounded px-1 py-0.5" title={finding.fingerprint}>{finding.fingerprint.slice(0, 12)}</span>
                        </span>
                      )}
                    </div>
                  )}
                  <div className="flex items-center gap-2 text-[10px] text-muted-light mt-1">
                    <span>{t("prove.iterations", { count: result.iterations_used })}</span>
                    <span>&middot;</span>
                    <button
                      type="button"
                      className="text-accent hover:text-accent/80 cursor-pointer"
                      onClick={() => toggleExpanded(result.id)}
                    >
                      {isExpanded ? t("prove.hideEvidence") : t("prove.showEvidence")}
                    </button>
                    {safeExternalUrl(result.staging_url) && (
                      <>
                        <span>&middot;</span>
                        <a
                          href={safeExternalUrl(result.staging_url)!}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-accent hover:underline"
                        >
                          {t("prove.stagingUrl")}
                        </a>
                      </>
                    )}
                    {result.created_at && (
                      <>
                        <span>&middot;</span>
                        <span>{new Date(result.created_at).toLocaleString()}</span>
                      </>
                    )}
                  </div>

                  {/* Expanded detail sections */}
                  {isExpanded && (
                    <div className="mt-3 space-y-3">
                      {/* (a) Finding Description */}
                      {finding && (
                        <div className="space-y-2">
                          <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("prove.findingDescription")}</h4>
                          <p className="text-[13px] text-foreground">{finding.description}</p>
                          {finding.code_snippet && (
                            <pre className="text-[12px] font-mono bg-terminal text-terminal-text rounded-lg px-4 py-3 overflow-x-auto">
                              {finding.code_snippet}
                            </pre>
                          )}
                          {finding.recommendation && (
                            <div className="flex gap-2 p-3 bg-success/5 rounded-lg border border-success/20">
                              <svg className="w-4 h-4 text-success shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <p className="text-[13px] text-foreground">{finding.recommendation}</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* (b) Prove Evidence / Reproduction Steps */}
                      {result.evidence && (
                        <div className="space-y-1.5">
                          <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("prove.reproductionSteps")}</h4>
                          <div className="text-[11px] text-muted bg-cream/50 rounded px-2 py-1.5 border border-border whitespace-pre-wrap">
                            {result.evidence}
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-muted-light">
                            <span>{t("prove.iterations", { count: result.iterations_used })}</span>
                            {safeExternalUrl(result.staging_url) && (
                              <a href={safeExternalUrl(result.staging_url)!} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                                {result.staging_url}
                              </a>
                            )}
                          </div>
                        </div>
                      )}

                      {/* (c) Traceability */}
                      {(() => {
                        if (!lineage) {
                          return (
                            <div className="pt-2 border-t border-border">
                              <p className="text-[11px] text-muted-light">{t("prove.noLineage")}</p>
                            </div>
                          );
                        }
                        const edit = editingLineage.get(fingerprint!) ?? {
                          status: lineage.current_status,
                          notes: lineage.notes ?? "",
                          ticketUrl: lineage.ticket_url ?? "",
                        };
                        return (
                          <div className="pt-3 border-t border-border space-y-3">
                            <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider">{t("lineage.title")}</h4>
                            {(lineage.first_commit || lineage.latest_commit || lineage.fixed_commit) && (
                              <div className="flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-muted">
                                {lineage.first_commit && (
                                  <span>
                                    {t("lineage.firstDetected")}:{" "}
                                    <span className="font-mono bg-cream rounded px-1.5 py-0.5">{lineage.first_commit.slice(0, 7)}</span>
                                    {lineage.first_found_at && (
                                      <span className="ml-1 text-muted-light">({new Date(lineage.first_found_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })})</span>
                                    )}
                                  </span>
                                )}
                                {lineage.latest_commit && (
                                  <span>
                                    {t("lineage.latestOccurrence")}:{" "}
                                    <span className="font-mono bg-cream rounded px-1.5 py-0.5">{lineage.latest_commit.slice(0, 7)}</span>
                                    {lineage.latest_found_at && (
                                      <span className="ml-1 text-muted-light">({new Date(lineage.latest_found_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })})</span>
                                    )}
                                  </span>
                                )}
                                {lineage.fixed_commit && (
                                  <span className="text-success">
                                    {t("lineage.fixedIn")}:{" "}
                                    <span className="font-mono bg-success/10 rounded px-1.5 py-0.5">{lineage.fixed_commit.slice(0, 7)}</span>
                                    {lineage.fixed_at && (
                                      <span className="ml-1">({new Date(lineage.fixed_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })})</span>
                                    )}
                                  </span>
                                )}
                              </div>
                            )}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div>
                                <label className="block text-[11px] text-muted mb-1">{t("lineage.status")}</label>
                                <select
                                  className="w-full text-[12px] bg-surface border border-border rounded-md px-2 py-1.5 text-foreground"
                                  value={edit.status}
                                  onChange={(e) => updateEdit(fingerprint!, { status: e.target.value })}
                                >
                                  {STATUSES.map((s) => (
                                    <option key={s} value={s}>{t(`lineage.status_${s}`)}</option>
                                  ))}
                                </select>
                              </div>
                              <div>
                                <label className="block text-[11px] text-muted mb-1">{t("lineage.ticketUrl")}</label>
                                <input
                                  type="url"
                                  className="w-full text-[12px] bg-surface border border-border rounded-md px-2 py-1.5 text-foreground"
                                  placeholder={t("lineage.ticketPlaceholder")}
                                  value={edit.ticketUrl}
                                  onChange={(e) => updateEdit(fingerprint!, { ticketUrl: e.target.value })}
                                />
                              </div>
                            </div>
                            <div>
                              <label className="block text-[11px] text-muted mb-1">{t("lineage.notes")}</label>
                              <textarea
                                className="w-full text-[12px] bg-surface border border-border rounded-md px-2 py-1.5 text-foreground resize-none"
                                rows={2}
                                placeholder={t("lineage.notesPlaceholder")}
                                value={edit.notes}
                                onChange={(e) => updateEdit(fingerprint!, { notes: e.target.value })}
                              />
                            </div>
                            <div className="flex items-center gap-3">
                              <button
                                type="button"
                                className="px-3 py-1 text-[11px] font-medium rounded-md bg-foreground text-surface hover:bg-foreground/90 transition-colors cursor-pointer"
                                onClick={() => saveStatus(lineage.id, fingerprint!)}
                              >
                                {savedFeedback === fingerprint ? t("lineage.saved") : t("lineage.save")}
                              </button>
                              <button
                                type="button"
                                className="px-3 py-1 text-[11px] font-medium rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
                                onClick={() => loadTimeline(lineage.id)}
                              >
                                {showTimeline === lineage.id ? t("lineage.hideHistory") : t("lineage.viewHistory")}
                              </button>
                              {fingerprint && (
                                <button
                                  type="button"
                                  className="px-3 py-1 text-[11px] font-medium rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
                                  onClick={() => {
                                    loadProveHistory(fingerprint);
                                    setShowVerificationHistory((prev) => (prev === fingerprint ? null : fingerprint));
                                  }}
                                >
                                  {showVerificationHistory === fingerprint ? t("prove.verificationHistory") : t("prove.viewVerificationHistory")}
                                </button>
                              )}
                            </div>
                            {showTimeline === lineage.id && timelineMap.has(lineage.id) && (
                              <div className="pt-2">
                                <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">{t("lineage.timeline")}</h4>
                                <FindingTimeline events={timelineMap.get(lineage.id)!} />
                              </div>
                            )}
                            {showVerificationHistory === fingerprint && fingerprint && (() => {
                              const history = proveHistoryMap.get(fingerprint);
                              if (!history || history.length === 0) {
                                return (
                                  <div className="pt-2">
                                    <p className="text-[11px] text-muted-light">{t("prove.noVerificationHistory")}</p>
                                  </div>
                                );
                              }
                              return (
                                <div className="pt-2">
                                  <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">{t("prove.verificationHistory")}</h4>
                                  <div className="space-y-1.5">
                                    {history.map((h) => {
                                      const hConfig = STATUS_CONFIG[h.status] ?? STATUS_CONFIG.skipped;
                                      return (
                                        <div key={h.id} className="flex items-center gap-2 text-[11px]">
                                          <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-medium ${hConfig.bgLight} ${hConfig.color}`}>
                                            {t(statusI18nKey(h.status))}
                                          </span>
                                          <span className="font-mono text-muted-light">{h.audit_id.slice(0, 8)}</span>
                                          <span className="text-muted-light">{new Date(h.created_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}</span>
                                          {h.iterations_used > 0 && (
                                            <span className="text-muted-light">{t("prove.iterations", { count: h.iterations_used })}</span>
                                          )}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
                {/* Copy button at row end */}
                {finding && (
                  <div className="shrink-0 mt-0.5">
                    <ProveCopyButton result={result} finding={finding} auditId={auditId} />
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
