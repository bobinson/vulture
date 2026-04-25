import { Fragment, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useFindings } from "@/hooks/useFindings.ts";
import { useLineage } from "@/hooks/useLineage.ts";
import { SeverityBadge } from "./SeverityBadge.tsx";
import { CopyFindingButton } from "./CopyFindingButton.tsx";
import { LineageStatusBadge } from "./LineageStatusBadge.tsx";
import { FindingTimeline } from "./FindingTimeline.tsx";
import { FindingLifecycleBadge } from "./FindingLifecycleBadge.tsx";
import { CrossAgentBadge } from "./CrossAgentBadge.tsx";
import { agentLabel } from "@/lib/constants.ts";
import { useCopyFeedback } from "@/hooks/useCopyFeedback.ts";
import { findingToMarkdown } from "@/lib/markdown.ts";
import { ProveStatusBadge } from "./ProveStatusBadge.tsx";
import type { Finding, LineageStatus, ProveResult, Severity } from "@/lib/types.ts";

interface FindingsTableProps {
  findings: Finding[];
  auditId?: string;
  proveResults?: ProveResult[];
}

function SortIcon({ field, sortField, sortDirection }: { field: string; sortField: string; sortDirection: string }) {
  if (sortField !== field) return <span className="text-border-dark ml-1">{"\u2195"}</span>;
  return <span className="text-accent ml-1">{sortDirection === "asc" ? "\u2191" : "\u2193"}</span>;
}

function RefCopyButton({ refText }: { refText: string }) {
  const { copied, onCopy } = useCopyFeedback();
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); void onCopy(refText); }}
      title={copied ? "Copied" : `Copy ${refText}`}
      className="text-[11px] font-mono font-medium text-accent hover:underline cursor-pointer"
    >
      {copied ? `${refText} ✓` : refText}
    </button>
  );
}

function RowCopyButton({ finding, auditId }: { finding: Finding; auditId?: string }) {
  const { copied, onCopy } = useCopyFeedback();
  return (
    <button
      type="button"
      className="w-7 h-7 inline-flex items-center justify-center rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
      title="Copy"
      onClick={(e) => { e.stopPropagation(); void onCopy(findingToMarkdown(finding, auditId)); }}
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

export function FindingsTable({ findings: allFindings, auditId, proveResults }: FindingsTableProps) {
  const { t } = useTranslation();
  const { copied: allCopied, onCopy: onCopyAll } = useCopyFeedback();

  const {
    findings,
    totalFiltered,
    page,
    totalPages,
    setPage,
    sortField,
    sortDirection,
    filterSeverity,
    filterAgent,
    setFilterSeverity,
    setFilterAgent,
    toggleSort,
  } = useFindings(allFindings);

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const { lineageMap, timelineMap, showTimeline, editingLineage, savedFeedback, loadTimeline, updateEdit, saveStatus } = useLineage(auditId);

  const severities: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

  // Derive unique agent types from findings
  const agentTypes = useMemo(() => {
    const set = new Set<string>();
    for (const f of allFindings) {
      const at = f.agent_type ?? f.agent_id;
      if (at) set.add(at);
    }
    return Array.from(set).sort();
  }, [allFindings]);

  // Map finding IDs to prove results for inline badges
  const proveMap = useMemo(() => {
    if (!proveResults?.length) return new Map<string, ProveResult>();
    return new Map(proveResults.map((pr) => [pr.finding_id, pr]));
  }, [proveResults]);

  if (allFindings.length === 0) {
    return (
      <div className="card p-8 text-center">
        <p className="text-[13px] text-muted">{t("results.noFindings")}</p>
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      {/* Header with filters */}
      <div className="p-4 border-b border-border space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-[13px] font-semibold text-foreground">{t("results.findings")}</h3>
            <span className="badge bg-cream text-muted">{totalFiltered}</span>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors cursor-pointer text-muted hover:text-foreground hover:bg-cream-dark"
              onClick={() => {
                const md = allFindings.map((f) => findingToMarkdown(f, auditId)).join("\n---\n\n");
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
                  {t("results.copyAll")}
                </>
              )}
            </button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-light">{t("results.filter")}:</span>
            <div className="flex gap-1">
              {severities.map((sev) => (
                <button
                  key={sev}
                  type="button"
                  className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium capitalize ${
                    filterSeverity === sev
                      ? "bg-foreground text-surface"
                      : "text-muted hover:text-foreground hover:bg-cream-dark"
                  }`}
                  onClick={() => setFilterSeverity(sev)}
                >
                  {sev === "all" ? t("results.all") : t(`severity.${sev}`)}
                </button>
              ))}
            </div>
          </div>
        </div>
        {/* Agent type filter — only show when multiple agents */}
        {agentTypes.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-light">{t("results.agent")}:</span>
            <div className="flex gap-1">
              <button
                type="button"
                className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium ${
                  filterAgent === "all"
                    ? "bg-foreground text-surface"
                    : "text-muted hover:text-foreground hover:bg-cream-dark"
                }`}
                onClick={() => setFilterAgent("all")}
              >
                {t("results.all")}
              </button>
              {agentTypes.map((at) => (
                <button
                  key={at}
                  type="button"
                  className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium ${
                    filterAgent === at
                      ? "bg-foreground text-surface"
                      : "text-muted hover:text-foreground hover:bg-cream-dark"
                  }`}
                  onClick={() => setFilterAgent(at)}
                >
                  {agentLabel(at, t)}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-border bg-cream/50">
              <th className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider select-none">
                ID
              </th>
              <th
                className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider cursor-pointer hover:text-foreground select-none"
                onClick={() => toggleSort("severity")}
              >
                {t("results.severity")}
                <SortIcon field="severity" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider select-none">
                {t("lineage.status")}
              </th>
              <th
                className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider cursor-pointer hover:text-foreground select-none"
                onClick={() => toggleSort("agent_type")}
              >
                {t("results.agent")}
                <SortIcon field="agent_type" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider cursor-pointer hover:text-foreground select-none"
                onClick={() => toggleSort("category")}
              >
                {t("results.category")}
                <SortIcon field="category" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider cursor-pointer hover:text-foreground select-none"
                onClick={() => toggleSort("title")}
              >
                {t("results.description")}
                <SortIcon field="title" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="text-left px-4 py-2.5 text-[11px] font-semibold text-muted uppercase tracking-wider cursor-pointer hover:text-foreground select-none"
                onClick={() => toggleSort("file")}
              >
                {t("results.file")}
                <SortIcon field="file" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th className="w-10 px-2 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const key = finding.fingerprint || finding.id || `${finding.title}-${finding.file_path}-${finding.line_start ?? 0}`;
              const isExpanded = expandedId === key;
              const pathParts = finding.file_path.split("/");
              const shortPath = pathParts.length > 2
                ? pathParts.slice(-3).join("/")
                : finding.file_path;
              const agentType = finding.agent_type ?? finding.agent_id;
              return (
                <Fragment key={key}>
                  <tr
                    className="border-b border-border hover:bg-cream/30 cursor-pointer transition-colors"
                    tabIndex={0}
                    aria-expanded={isExpanded}
                    onClick={() => setExpandedId(isExpanded ? null : key)}
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpandedId(isExpanded ? null : key); } }}
                  >
                    <td className="px-4 py-2.5">
                      {(() => {
                        const lin = finding.fingerprint ? lineageMap.get(finding.fingerprint) : undefined;
                        const rn = lin?.ref_number;
                        if (!rn || rn <= 0) {
                          return <span className="text-[11px] text-muted-light">&mdash;</span>;
                        }
                        return <RefCopyButton refText={`VLT-${String(rn).padStart(4, "0")}`} />;
                      })()}
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-4 py-2.5">
                      {finding.fingerprint && lineageMap.has(finding.fingerprint) ? (
                        <LineageStatusBadge status={lineageMap.get(finding.fingerprint)!.current_status} />
                      ) : (
                        <span className="text-[11px] text-muted-light">&mdash;</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {agentType ? (
                        <div>
                          <span className="text-[10px] font-mono font-medium uppercase bg-cream rounded px-1.5 py-0.5 text-muted">
                            {agentLabel(agentType, t)}
                          </span>
                          <CrossAgentBadge origins={finding.cross_agent_origins} />
                        </div>
                      ) : (
                        <span className="text-[11px] text-muted-light">&mdash;</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-[11px] font-mono bg-cream rounded px-1.5 py-0.5 text-muted">
                        {finding.category}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 max-w-md">
                      <div className="flex items-center gap-1.5">
                        <p className="text-[13px] text-foreground font-medium truncate">{finding.title}</p>
                        <FindingLifecycleBadge
                          lineage={finding.fingerprint ? lineageMap.get(finding.fingerprint) : undefined}
                          currentAuditId={auditId}
                        />
                        {finding.id && proveMap.has(finding.id) && (
                          <ProveStatusBadge status={proveMap.get(finding.id)!.status} />
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-[11px] font-mono text-muted" title={finding.file_path}>
                        {shortPath}
                        {finding.line_start ? `:${finding.line_start}` : ""}
                      </span>
                    </td>
                    <td className="px-2 py-2.5">
                      <RowCopyButton finding={finding} auditId={auditId} />
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="bg-cream/50">
                      <td colSpan={8} className="px-6 py-4">
                        <div className="space-y-3 max-w-2xl">
                          {agentType && (
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-mono font-medium uppercase bg-cream rounded px-1.5 py-0.5 text-muted">
                                {agentLabel(agentType, t)}
                              </span>
                              <span className="text-[11px] text-muted-light">{t("results.agent").toLowerCase()}</span>
                            </div>
                          )}
                          <div className="flex items-start justify-between">
                            <p className="text-[13px] text-foreground">{finding.description}</p>
                            <CopyFindingButton finding={finding} auditId={auditId} />
                          </div>
                          <div className="text-[11px] text-muted font-mono bg-surface rounded-lg px-3 py-2 border border-border">
                            {finding.file_path}
                            {finding.line_start ? `:${finding.line_start}` : ""}
                            {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}
                          </div>
                          {(finding.check_id || finding.fingerprint) && (
                            <div className="flex items-center gap-3 text-[11px] text-muted-light">
                              {finding.check_id && (
                                <span>
                                  {t("lineage.checkId")}:{" "}
                                  <span className="font-mono bg-cream rounded px-1.5 py-0.5">{finding.check_id}</span>
                                </span>
                              )}
                              {finding.fingerprint && (
                                <span>
                                  {t("lineage.fingerprint")}:{" "}
                                  <span className="font-mono bg-cream rounded px-1.5 py-0.5" title={finding.fingerprint}>{finding.fingerprint.slice(0, 12)}</span>
                                </span>
                              )}
                            </div>
                          )}
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
                          {/* Inline prove evidence */}
                          {finding.id && proveMap.has(finding.id) && (() => {
                            const prove = proveMap.get(finding.id!)!;
                            const borderColor = prove.status === "verified" ? "border-[#CF222E]" : prove.status === "not_reproduced" ? "border-[#22C55E]" : "border-border";
                            return (
                              <div className={`border-l-2 ${borderColor} pl-3 py-2 space-y-1.5`}>
                                <div className="flex items-center gap-2">
                                  <ProveStatusBadge status={prove.status} />
                                  <span className="text-[11px] text-muted">{t("results.verificationEvidence")}</span>
                                </div>
                                {prove.evidence && (
                                  <p className="text-[12px] text-foreground">{prove.evidence}</p>
                                )}
                                <div className="flex items-center gap-4 text-[11px] text-muted">
                                  {prove.staging_url && /^https?:\/\//i.test(prove.staging_url) && (
                                    <a href={prove.staging_url} target="_blank" rel="noopener noreferrer" className="underline hover:text-foreground">
                                      {t("prove.stagingUrl")}
                                    </a>
                                  )}
                                  <span>{t("prove.iterations", { count: prove.iterations_used })}</span>
                                </div>
                              </div>
                            );
                          })()}
                          {/* Traceability section */}
                          {(() => {
                            const lineage = finding.fingerprint ? lineageMap.get(finding.fingerprint) : undefined;
                            if (!lineage) {
                              return (
                                <div className="pt-2 border-t border-border">
                                  <p className="text-[11px] text-muted-light">{t("lineage.noLineage")}</p>
                                </div>
                              );
                            }
                            const edit = editingLineage.get(finding.fingerprint!) ?? {
                              status: lineage.current_status,
                              notes: lineage.notes ?? "",
                              ticketUrl: lineage.ticket_url ?? "",
                            };
                            const STATUSES: LineageStatus[] = ["open", "in_progress", "resolved", "accepted_risk", "false_positive", "fixed", "regression"];
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
                                      onChange={(e) => updateEdit(finding.fingerprint!, { status: e.target.value })}
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
                                      onChange={(e) => updateEdit(finding.fingerprint!, { ticketUrl: e.target.value })}
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
                                    onChange={(e) => updateEdit(finding.fingerprint!, { notes: e.target.value })}
                                  />
                                </div>
                                <div className="flex items-center gap-3">
                                  <button
                                    type="button"
                                    className="px-3 py-1 text-[11px] font-medium rounded-md bg-foreground text-surface hover:bg-foreground/90 transition-colors cursor-pointer"
                                    onClick={() => saveStatus(lineage.id, finding.fingerprint!)}
                                  >
                                    {savedFeedback === finding.fingerprint ? t("lineage.saved") : t("lineage.save")}
                                  </button>
                                  <button
                                    type="button"
                                    className="px-3 py-1 text-[11px] font-medium rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
                                    onClick={() => loadTimeline(lineage.id)}
                                  >
                                    {showTimeline === lineage.id ? t("lineage.hideHistory") : t("lineage.viewHistory")}
                                  </button>
                                </div>
                                {showTimeline === lineage.id && timelineMap.has(lineage.id) && (
                                  <div className="pt-2">
                                    <h4 className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">{t("lineage.timeline")}</h4>
                                    <FindingTimeline events={timelineMap.get(lineage.id)!} />
                                  </div>
                                )}
                              </div>
                            );
                          })()}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination footer */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <span className="text-[11px] text-muted tabular-nums">
            {t("results.pageInfo", { from: page * 25 + 1, to: Math.min((page + 1) * 25, totalFiltered), total: totalFiltered })}
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              aria-label={t("common.back")}
              className="px-2 py-1 text-[11px] rounded-md transition-colors cursor-pointer text-muted hover:text-foreground hover:bg-cream-dark disabled:opacity-30 disabled:cursor-default disabled:hover:bg-transparent"
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
              </svg>
            </button>
            {Array.from({ length: totalPages }, (_, i) => i).map((p) => (
              <button
                key={p}
                type="button"
                className={`w-7 h-7 text-[11px] rounded-md transition-colors cursor-pointer font-medium tabular-nums ${
                  page === p
                    ? "bg-foreground text-surface"
                    : "text-muted hover:text-foreground hover:bg-cream-dark"
                }`}
                onClick={() => setPage(p)}
              >
                {p + 1}
              </button>
            ))}
            <button
              type="button"
              aria-label={t("common.next")}
              className="px-2 py-1 text-[11px] rounded-md transition-colors cursor-pointer text-muted hover:text-foreground hover:bg-cream-dark disabled:opacity-30 disabled:cursor-default disabled:hover:bg-transparent"
              disabled={page === totalPages - 1}
              onClick={() => setPage(page + 1)}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
