import { memo } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { ROUTES } from "@/lib/constants.ts";
import { deriveTargetName, isUnattributed, parseWireDate } from "@/lib/targets.ts";
import type { TargetSummary } from "@/lib/types.ts";

function useDisplayName(target: TargetSummary): string {
  const { t } = useTranslation();
  if (isUnattributed(target.target_key)) return t("targets.unattributed");
  return target.display_name || deriveTargetName(target.target_key);
}

/**
 * One of the three counts on a codebase row.
 *
 * The label is sentence case and wraps: "Could not confirm" does not fit a
 * 10px uppercase, letter-spaced box, and at the original width the three
 * labels overlapped each other into "ACTIVEUNCONFIRMED". The hover text says
 * what the count actually means — none of the three words is self-describing.
 */
function Count({
  value,
  label,
  hint,
  tone,
}: {
  value: number;
  label: string;
  hint: string;
  tone: string;
}) {
  return (
    <div className="flex flex-col items-end w-24 shrink-0 text-right" title={hint}>
      <span className={`text-[13px] font-semibold tabular-nums ${tone}`}>{value}</span>
      <span className="text-[10px] text-muted-light leading-tight">{label}</span>
    </div>
  );
}

const TargetRow = memo(function TargetRow({ target }: { target: TargetSummary }) {
  const { t } = useTranslation();
  const name = useDisplayName(target);
  const lastScan = parseWireDate(target.last_scan_at);

  return (
    <div data-testid="target-row" className="hover:bg-cream/60 transition-colors">
      <Link
        data-testid="target-row-link"
        to={ROUTES.TARGET_REPORT(target.target_key)}
        className="flex items-center justify-between gap-4 px-4 py-3 rounded focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-accent"
        title={t("targets.openReport", { name })}
      >
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-foreground truncate">{name}</p>
          <div className="flex items-center gap-2 text-[11px] text-muted-light">
            <span className="tabular-nums">{t("targets.scanCount", { count: target.scan_count })}</span>
            {lastScan && (
              <span className="tabular-nums">
                {t("targets.lastScan")}: {lastScan.toLocaleDateString()}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <Count
            value={target.active_count}
            label={t("targets.active")}
            hint={t("targets.activeHint")}
            tone="text-foreground"
          />
          <Count
            value={target.unconfirmed_count}
            label={t("targets.unconfirmed")}
            hint={t("targets.unconfirmedHint")}
            tone={target.unconfirmed_count > 0 ? "text-[#9A3412]" : "text-muted-light"}
          />
          <Count
            value={target.fixed_count}
            label={t("targets.fixed")}
            hint={t("targets.fixedHint")}
            tone="text-success"
          />
        </div>
      </Link>
    </div>
  );
});

/** Skeleton rows sized like real ones, so the first paint does not jump. */
function TargetsSkeleton() {
  return (
    <div className="card divide-y divide-border" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <div key={i} className="flex items-center justify-between gap-4 px-4 py-3">
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="h-3.5 w-40 rounded bg-cream-dark animate-pulse" />
            <div className="h-2.5 w-28 rounded bg-cream-dark/70 animate-pulse" />
          </div>
          <div className="flex gap-3">
            {[0, 1, 2].map((c) => (
              <div key={c} className="w-24 space-y-1.5">
                <div className="h-3.5 w-6 ml-auto rounded bg-cream-dark animate-pulse" />
                <div className="h-2 w-10 ml-auto rounded bg-cream-dark/70 animate-pulse" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

interface TargetsListProps {
  targets: TargetSummary[];
  loading: boolean;
  error: string | null;
  /** Re-run the request behind this list. Omitted = no retry offered. */
  onRetry?: () => void;
}

/**
 * The target list: one row per codebase, with what a reader actually needs to
 * decide where to look — how many findings are still active, how many the
 * scanner could not confirm either way, how many are closed, and when the
 * codebase was last scanned. Clicking a row opens that target's aggregate.
 */
export function TargetsList({ targets, loading, error, onRetry }: TargetsListProps) {
  const { t } = useTranslation();

  if (loading) return <TargetsSkeleton />;

  if (error && targets.length === 0) {
    return (
      <div className="card p-6 text-center space-y-3">
        <p className="text-[13px] text-danger">{t("targets.loadFailed")}</p>
        {onRetry && (
          <button type="button" className="btn-secondary text-[12px]" onClick={onRetry}>
            {t("common.retry")}
          </button>
        )}
      </div>
    );
  }

  if (targets.length === 0) {
    return (
      <div className="card p-8 text-center space-y-2">
        <p className="text-[13px] text-muted">{t("targets.empty")}</p>
        <Link to={ROUTES.AUDIT} className="btn-primary inline-flex">
          {t("dashboard.newAudit")}
        </Link>
      </div>
    );
  }

  return (
    <div className="card overflow-hidden divide-y divide-border">
      {targets.map((target) => (
        <TargetRow key={target.target_key} target={target} />
      ))}
    </div>
  );
}
