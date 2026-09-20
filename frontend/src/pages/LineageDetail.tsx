import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useAsyncResource } from "@/hooks/useAsyncResource.ts";
import { LineageStatusBadge } from "@/components/results/LineageStatusBadge.tsx";
import { LineageTimeline } from "@/components/results/LineageTimeline.tsx";
import { SeverityBadge } from "@/components/results/SeverityBadge.tsx";
import { ROUTES } from "@/lib/constants.ts";
import type { FindingLineage, Severity } from "@/lib/types.ts";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function asSeverity(value: string): Severity {
  return (SEVERITIES as string[]).includes(value) ? (value as Severity) : "info";
}

function DetailSkeleton() {
  return (
    <div className="max-w-4xl space-y-4" aria-hidden="true">
      <div className="card px-4 py-3 space-y-2">
        <div className="h-4 w-64 rounded bg-cream-dark animate-pulse" />
        <div className="h-3 w-40 rounded bg-cream-dark/70 animate-pulse" />
      </div>
      <div className="card px-4 py-3 space-y-2">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-3 w-3/4 rounded bg-cream-dark/70 animate-pulse" />
        ))}
      </div>
    </div>
  );
}

function SeenIn({ auditIds }: { auditIds: string[] }) {
  const { t } = useTranslation();
  if (auditIds.length === 0) return null;
  return (
    <section className="card px-4 py-3">
      <h2 className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">
        {t("lineage.seenIn", { count: auditIds.length })}
      </h2>
      <div className="flex flex-wrap gap-2">
        {auditIds.map((auditId) => (
          <Link
            key={auditId}
            to={ROUTES.AUDIT_RESULTS(auditId)}
            title={auditId}
            className="text-[11px] font-mono rounded-md border border-border px-2 py-1 text-accent hover:border-accent/60 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            {auditId.slice(0, 8)}
          </Link>
        ))}
      </div>
    </section>
  );
}

function DetailBody({ lineage }: { lineage: FindingLineage }) {
  const { t } = useTranslation();
  const where = lineage.file_path || "—";

  return (
    <div data-testid="lineage-detail" className="max-w-4xl space-y-4">
      <section className="card px-4 py-3">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          {/* The ref identifies THIS page; painting it accent-blue made it
              look like a link to somewhere else. */}
          <span className="text-[12px] font-mono text-muted">{lineage.ref ?? lineage.id}</span>
          <SeverityBadge severity={asSeverity(lineage.severity)} />
          <LineageStatusBadge status={lineage.current_status} />
          <span className="text-[11px] font-mono text-muted">{lineage.category}</span>
        </div>
        <h2 className="text-[15px] font-semibold text-foreground break-words">{lineage.title}</h2>
        <p className="text-[12px] font-mono text-muted break-all mt-0.5" title={t("lineage.whereFound")}>
          {where}
        </p>
        <div className="flex items-center gap-4 mt-2 text-[11px] text-muted-light flex-wrap">
          {lineage.target_key && (
            <Link
              to={ROUTES.TARGET_REPORT(lineage.target_key)}
              className="text-accent hover:underline rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
            >
              {t("lineage.backToTarget")}
            </Link>
          )}
          {lineage.git_branch && <span>{t("lineage.branch")}: {lineage.git_branch}</span>}
        </div>
      </section>

      <section className="card px-4 py-3">
        <h2 className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">
          {t("lineage.timeline")}
        </h2>
        <LineageTimeline events={lineage.events ?? []} evidence={lineage.evidence ?? null} />
      </section>

      <SeenIn auditIds={lineage.seen_in ?? []} />
    </div>
  );
}

/**
 * One finding across its whole life (LLD 10.2 drill-down).
 *
 * `seen_in` and the timeline are the two answers this page exists to give:
 * which scans reported this finding, and what each scan concluded about it —
 * including the evidence re-read that decided whether it could be closed.
 */
export function LineageDetail() {
  const { t } = useTranslation();
  const { id } = useParams<{ id: string }>();
  const { data, loading, error, reload } = useAsyncResource(id ?? null, () =>
    id ? api.getLineage(id) : Promise.reject(new Error("no lineage id")),
  );

  if (loading) return <DetailSkeleton />;

  if (error || !data) {
    return (
      <div className="card p-8 text-center space-y-3 max-w-4xl">
        <p className="text-[13px] text-danger">{t("lineage.notFound")}</p>
        <div className="flex items-center justify-center gap-2">
          <button type="button" className="btn-secondary text-[12px]" onClick={reload}>
            {t("common.retry")}
          </button>
          <Link to={ROUTES.TARGETS} className="btn-secondary inline-flex text-[12px]">
            {t("targets.allTargets")}
          </Link>
        </div>
      </div>
    );
  }

  return <DetailBody lineage={data} />;
}
