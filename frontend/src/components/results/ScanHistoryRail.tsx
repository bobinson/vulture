import { memo, useMemo } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { ROUTES } from "@/lib/constants.ts";
import { formatScanStamp } from "@/lib/targets.ts";
import type { TargetScan } from "@/lib/types.ts";

interface RailEntryProps {
  scan: TargetScan;
  current: boolean;
}

const RailEntry = memo(function RailEntry({ scan, current }: RailEntryProps) {
  const { t } = useTranslation();
  const stamp = formatScanStamp(scan.created_at);

  return (
    <li
      data-testid="rail-entry"
      data-audit-id={scan.audit_id}
      data-current={current ? "true" : "false"}
      className={`shrink-0 w-44 rounded-md border px-3 py-2 transition-colors ${
        current
          ? "border-accent bg-accent/5"
          : "border-border bg-surface hover:border-accent/50"
      }`}
    >
      <Link
        data-testid="rail-entry-link"
        to={`/audit/${scan.audit_id}`}
        aria-current={current ? "page" : undefined}
        className="block rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        title={t("scanHistory.openScan", { when: stamp })}
      >
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium text-foreground tabular-nums truncate">
            {stamp}
          </span>
          {current && (
            <span className="text-[9px] font-semibold uppercase tracking-wide text-accent shrink-0">
              {t("scanHistory.current")}
            </span>
          )}
        </div>
        <div className="text-[10px] font-mono text-muted-light truncate mt-0.5">
          {scan.audit_id.slice(0, 8)}
        </div>
        {scan.sub_path && (
          <div
            data-testid="rail-subpath"
            className="text-[10px] font-mono text-accent/80 truncate mt-0.5"
            title={scan.sub_path}
          >
            {scan.sub_path}
          </div>
        )}
        {scan.git_branch && (
          <div className="text-[10px] text-muted-light truncate">{scan.git_branch}</div>
        )}
        <div className="flex items-center gap-2 mt-1">
          <span
            data-testid="rail-det-count"
            className="text-[10px] font-medium text-[#075985] bg-[#E0F2FE] rounded px-1.5 py-0.5 tabular-nums"
            title={t("scanHistory.detCount")}
          >
            {t("aggregate.tier_det")} {scan.det_count}
          </span>
          <span
            data-testid="rail-llm-count"
            className="text-[10px] font-medium text-[#5B21B6] bg-[#EDE9FE] rounded px-1.5 py-0.5 tabular-nums"
            title={t("scanHistory.llmCount")}
          >
            {t("aggregate.tier_llm")} {scan.llm_count}
          </span>
        </div>
      </Link>
    </li>
  );
});

interface ScanHistoryRailProps {
  scans: TargetScan[];
  currentAuditId?: string;
  /**
   * The codebase these scans belong to. When known, the rail offers the way
   * OUT of a single scan and into everything ever reported for the codebase —
   * without it a reader can walk between scans but can never reach the whole
   * picture from here.
   */
  targetKey?: string;
}

/**
 * Every scan of the current scan's TARGET, newest first, with the current one
 * marked (LLD 10.2).
 *
 * Keyed by target rather than by source path, so a sub-path scan
 * (`.vscode`) and a root scan of the same project sit on one rail; the
 * sub-path badge is what tells them apart. Sorting is done here rather than
 * trusted from the server: the rail's whole value is that "the one above is
 * more recent" is always true.
 */
export function ScanHistoryRail({ scans, currentAuditId, targetKey }: ScanHistoryRailProps) {
  const { t } = useTranslation();

  const ordered = useMemo(
    () =>
      [...scans].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [scans],
  );

  if (ordered.length === 0) return null;

  return (
    <section data-testid="scan-history-rail" className="card px-4 py-3">
      <div className="flex items-center gap-3 mb-2">
        <h2 className="text-[11px] font-semibold text-muted uppercase tracking-wider">
          {t("scanHistory.title")}
        </h2>
        <span className="text-[11px] text-muted-light">
          {t("scanHistory.count", { count: ordered.length })}
        </span>
        {targetKey && (
          <Link
            data-testid="rail-view-all"
            to={ROUTES.TARGET_REPORT(targetKey)}
            className="ml-auto text-[11px] text-accent hover:underline rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            {t("scanHistory.viewAll")} &rarr;
          </Link>
        )}
      </div>
      <ul className="flex gap-2 overflow-x-auto pb-1">
        {ordered.map((scan) => (
          <RailEntry
            key={scan.audit_id}
            scan={scan}
            current={scan.audit_id === currentAuditId}
          />
        ))}
      </ul>
    </section>
  );
}
