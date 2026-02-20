import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ROUTES, AGENT_TYPES, agentLabel } from "@/lib/constants.ts";
import { api } from "@/lib/api.ts";
import type { Audit, AuditStatus, DashboardStats } from "@/lib/types.ts";

const STATUS_DOTS: Record<string, string> = {
  completed: "bg-success",
  running: "bg-accent",
  pending: "bg-muted-light",
  failed: "bg-danger",
};

const STATUS_FILTERS: AuditStatus[] = ["completed", "running", "pending", "failed"];
function getScoreAvg(scores?: Record<string, number>): number | null {
  if (!scores) return null;
  const vals = Object.values(scores);
  if (vals.length === 0) return null;
  return Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
}

export function Dashboard() {
  const { t } = useTranslation();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<AuditStatus | "all">("all");
  const [typeFilter, setTypeFilter] = useState<string | "all">("all");
  const [limit, setLimit] = useState(10);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    Promise.all([
      api.getStats().then(setStats).catch(() => {}),
      api.listAudits(50).then(setAudits).catch(() => setError(true)),
    ]).finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    let result = audits;
    if (statusFilter !== "all") {
      result = result.filter((a) => a.status === statusFilter);
    }
    if (typeFilter !== "all") {
      result = result.filter((a) => a.types?.includes(typeFilter));
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (a) =>
          a.id.toLowerCase().includes(q) ||
          a.types?.some((t) => t.toLowerCase().includes(q)) ||
          a.source_id.toLowerCase().includes(q),
      );
    }
    return result;
  }, [audits, statusFilter, typeFilter, search]);

  const visible = filtered.slice(0, limit);
  const hasMore = filtered.length > limit;

  const handleLoadMore = useCallback(() => {
    setLimit((l) => l + 10);
  }, []);

  if (loading) {
    return (
      <div className="max-w-5xl flex items-center justify-center py-20">
        <div className="w-5 h-5 border-2 border-accent/20 border-t-accent rounded-full animate-spin" />
      </div>
    );
  }

  if (error && audits.length === 0) {
    return (
      <div className="max-w-5xl">
        <div className="card p-8 text-center space-y-3">
          <p className="text-[13px] text-danger">{t("errors.fetchFailed")}</p>
          <button type="button" className="btn-secondary text-[13px]" onClick={() => window.location.reload()}>
            {t("common.retry")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl space-y-6">
      {/* Subtitle */}
      <p className="text-[13px] text-muted -mt-4">{t("dashboard.subtitle")}</p>

      {/* Stats row — compact, Linear-style metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: t("dashboard.auditsRun"), value: stats?.audits_run ?? 0 },
          { label: t("dashboard.totalFindings"), value: stats?.total_findings ?? 0 },
          { label: t("dashboard.criticalIssues"), value: stats?.critical_issues ?? 0 },
          { label: t("dashboard.avgScore"), value: stats?.average_score ? `${stats.average_score}%` : "\u2014" },
        ].map((stat) => (
          <div key={stat.label} className="card px-4 py-3">
            <p className="text-[11px] text-muted font-medium uppercase tracking-wide mb-1">{stat.label}</p>
            <p className="text-xl font-semibold text-foreground tabular-nums tracking-tight">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Quick action */}
      <div className="flex items-center justify-between">
        <Link to={ROUTES.AUDIT} className="btn-primary">
          {t("dashboard.newAudit")}
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
        </Link>
      </div>

      {/* Audit list */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-[13px] font-semibold text-foreground">{t("dashboard.recentAudits")}</h2>
        </div>

        {/* Search and filters */}
        {audits.length > 0 && (
          <div className="space-y-2 mb-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                placeholder={t("dashboard.searchPlaceholder")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="input-field flex-1 !py-1.5 !text-[12px]"
              />
              <div className="flex gap-1">
                <button
                  type="button"
                  className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium ${
                    statusFilter === "all"
                      ? "bg-foreground text-surface"
                      : "text-muted hover:text-foreground hover:bg-cream-dark"
                  }`}
                  onClick={() => setStatusFilter("all")}
                >
                  {t("results.all")}
                </button>
                {STATUS_FILTERS.map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer flex items-center gap-1.5 font-medium ${
                      statusFilter === s
                        ? "bg-foreground text-surface"
                        : "text-muted hover:text-foreground hover:bg-cream-dark"
                    }`}
                    onClick={() => setStatusFilter(s)}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOTS[s]}`} />
                    {t(`common.${s}`)}
                  </button>
                ))}
              </div>
            </div>
            {/* Audit type filter */}
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-muted-light">{t("dashboard.filterByType")}:</span>
              <div className="flex gap-1">
                <button
                  type="button"
                  className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium ${
                    typeFilter === "all"
                      ? "bg-foreground text-surface"
                      : "text-muted hover:text-foreground hover:bg-cream-dark"
                  }`}
                  onClick={() => setTypeFilter("all")}
                >
                  {t("results.all")}
                </button>
                {AGENT_TYPES.map((at) => (
                  <button
                    key={at}
                    type="button"
                    className={`px-2.5 py-1 text-[11px] rounded-md transition-colors cursor-pointer font-medium ${
                      typeFilter === at
                        ? "bg-foreground text-surface"
                        : "text-muted hover:text-foreground hover:bg-cream-dark"
                    }`}
                    onClick={() => setTypeFilter(at)}
                  >
                    {agentLabel(at, t)}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {audits.length === 0 ? (
          <div className="card p-8 text-center">
            <p className="text-[13px] text-muted">{t("dashboard.noAudits")}</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-6 text-center">
            <p className="text-[13px] text-muted">{t("dashboard.noMatches")}</p>
          </div>
        ) : (
          <>
            <div className="card overflow-hidden divide-y divide-border">
              {visible.map((audit) => {
                const findCount = audit.findings_count ?? audit.findings?.length ?? 0;
                const avgScore = getScoreAvg(audit.scores);
                const sourceName = audit.source_path
                  ? audit.source_path.split("/").filter(Boolean).pop() ?? audit.source_path
                  : null;
                return (
                  <Link
                    key={audit.id}
                    to={ROUTES.AUDIT_RESULTS(audit.id)}
                    className="flex items-center justify-between px-4 py-3 hover:bg-cream/60 transition-colors group"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${STATUS_DOTS[audit.status] ?? "bg-muted-light"}`} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-[13px] font-medium text-foreground truncate group-hover:text-accent transition-colors">
                            {(audit.types ?? []).map((tp) => agentLabel(tp, t)).join(", ") || "Unknown"}
                          </p>
                          {findCount > 0 && (
                            <span className="text-[10px] font-medium text-muted bg-cream-dark px-1.5 py-0.5 rounded-full tabular-nums shrink-0">
                              {findCount}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 min-w-0">
                          {sourceName && (
                            <span className="text-[11px] text-accent/70 font-medium truncate" title={audit.source_path}>
                              {sourceName}
                            </span>
                          )}
                          <span className="text-[11px] text-muted-light font-mono truncate">{audit.id.slice(0, 11)}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 shrink-0">
                      {avgScore !== null && (
                        <span className={`text-[12px] font-semibold tabular-nums ${avgScore >= 80 ? "text-success" : avgScore >= 50 ? "text-warning" : "text-danger"}`}>
                          {avgScore}%
                        </span>
                      )}
                      <span className="text-[11px] text-muted-light tabular-nums w-20 text-right">
                        {new Date(audit.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </Link>
                );
              })}
            </div>

            {hasMore && (
              <button
                type="button"
                className="w-full mt-2 py-2 text-[12px] text-muted hover:text-foreground transition-colors cursor-pointer"
                onClick={handleLoadMore}
              >
                {t("dashboard.loadMore", { shown: visible.length, total: filtered.length })}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
