import { memo } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { SeverityBadge } from "./SeverityBadge.tsx";
import { LineageStatusBadge } from "./LineageStatusBadge.tsx";
import { lastEventOutcome } from "@/lib/lineage.ts";
import { parseWireDate } from "@/lib/targets.ts";
import type { AggregateRow } from "@/lib/types.ts";

interface SeenBarProps {
  seen: number;
  total: number;
  tier: AggregateRow["tier"];
}

/**
 * "Seen in k of the target's N scans" — the single most useful signal on the
 * aggregate, because k close to N is a finding that has survived every scan
 * and k of 1 is a finding that appeared once.
 *
 * The number alone is NOT self-describing, and the two tiers make it mean
 * opposite things: the rule scan looks for everything on every scan, so 1 of 5
 * there says "it came and went", while AI review re-reads only part of the
 * code, so 1 of 5 there says almost nothing about whether the problem is gone.
 * The hover text is therefore written per tier rather than as one sentence.
 *
 * `total` of 0 is a real case (a target whose scans have not been counted
 * yet); the width falls back to 0 rather than dividing by it.
 */
function SeenBar({ seen, total, tier }: SeenBarProps) {
  const { t } = useTranslation();
  const pct = total > 0 ? Math.min(100, Math.round((seen / total) * 100)) : 0;
  const explain = t(`aggregate.seenHint_${tier}`, { seen, total });
  return (
    <div className="flex items-center gap-2" title={explain}>
      <div
        data-testid="seen-bar"
        role="progressbar"
        aria-valuenow={seen}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-label={explain}
        className="h-1.5 w-12 rounded-full bg-cream-dark overflow-hidden shrink-0"
      >
        <div className="h-full rounded-full bg-accent/70" style={{ width: `${pct}%` }} />
      </div>
      <span data-testid="seen-count-label" className="text-[11px] text-muted tabular-nums">
        {`${seen}/${total}`}
      </span>
    </div>
  );
}

/**
 * Which kind of analysis produced the row. Deliberately quiet: it qualifies
 * the evidence, it is not a severity. The hover text says what the label
 * means, because "Rule" and "AI" are shorthand — the difference between them
 * is exactly what makes the "seen in k of N" column readable.
 */
function TierChip({ tier }: { tier: AggregateRow["tier"] }) {
  const { t } = useTranslation();
  const style =
    tier === "llm"
      ? "bg-[#EDE9FE] text-[#5B21B6]"
      : "bg-[#E0F2FE] text-[#075985]";
  const hint = t(`aggregate.tierHint_${tier}`);
  return (
    <span
      data-testid="tier-chip"
      data-tier={tier}
      title={hint}
      aria-label={hint}
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide ${style}`}
    >
      {t(`aggregate.tier_${tier}`)}
    </span>
  );
}

function formatDay(value?: string): string {
  const date = parseWireDate(value);
  if (date === null) return "—";
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** The four statuses that mean "nobody needs to act on this any more". */
const CLOSED: ReadonlySet<AggregateRow["status"]> = new Set([
  "fixed",
  "resolved",
  "accepted_risk",
  "false_positive",
]);

// memo'd and given a stable key: the aggregate can run to hundreds of rows and
// a filter change re-renders the page, not the rows whose data did not move.
/**
 * What the last scan OBSERVED about the row, under its status chip.
 *
 * The status alone cannot answer the question the report exists for. Two rows
 * both reading "Open" mean opposite things: one where the last scan re-read
 * the file and the code is still there, and one the last scan never mentioned.
 * The backend already computes `last_event` for exactly this and it was being
 * fetched and discarded. Reuses the `lineage.evidence_*` phrasing the finding
 * page uses, so one observation is worded one way everywhere.
 */
function LastObservation({ lastEvent }: { lastEvent: string }) {
  const { t } = useTranslation();
  const outcome = lastEventOutcome(lastEvent);
  if (outcome === null) return null;
  return (
    <p
      data-testid="aggregate-last-observation"
      data-outcome={outcome}
      className="text-[10px] text-muted-light leading-tight mt-0.5 max-w-[9rem] whitespace-normal"
    >
      {t(`lineage.evidence_${outcome}`)}
    </p>
  );
}

const AggregateRowView = memo(function AggregateRowView({ row }: { row: AggregateRow }) {
  const { t } = useTranslation();
  const where = row.line_start ? `${row.rel_path}:${row.line_start}` : row.rel_path;
  // A closed row sits alongside the live ones under "Show all"; it is dimmed
  // rather than moved, so the table stays one list in one order.
  const closed = CLOSED.has(row.status);

  return (
    <tr
      data-testid="aggregate-row"
      className={`border-t border-border hover:bg-cream/60 ${closed ? "opacity-70" : ""}`}
    >
      <td className="px-3 py-2 align-top whitespace-nowrap">
        <Link
          data-testid="aggregate-row-link"
          to={`/lineage/${row.lineage_id}`}
          className="text-[12px] font-mono text-accent hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent rounded"
          title={t("aggregate.openFinding")}
        >
          {row.ref}
        </Link>
      </td>
      <td className="px-3 py-2 align-top whitespace-nowrap">
        <SeverityBadge severity={row.severity} />
      </td>
      <td className="px-3 py-2 align-top min-w-[16rem] max-w-[32rem]">
        <p data-testid="aggregate-title" className="text-[13px] text-foreground break-words">
          {row.title}
        </p>
        <p className="text-[11px] text-muted font-mono break-all mt-0.5">{where}</p>
      </td>
      <td className="px-3 py-2 align-top whitespace-nowrap">
        <span className="text-[11px] text-muted font-mono">{row.category}</span>
      </td>
      <td className="px-3 py-2 align-top whitespace-nowrap">
        <TierChip tier={row.tier} />
      </td>
      <td className="px-3 py-2 align-top whitespace-nowrap">
        <SeenBar seen={row.seen_count} total={row.scan_count} tier={row.tier} />
      </td>
      <td className="px-3 py-2 align-top">
        <LineageStatusBadge status={row.status} />
        <LastObservation lastEvent={row.last_event} />
      </td>
      <td className="px-3 py-2 align-top whitespace-nowrap text-[11px] text-muted tabular-nums">
        {formatDay(row.last_seen_at)}
      </td>
    </tr>
  );
});

interface AggregateTableProps {
  rows: AggregateRow[];
  /**
   * Whether the caller is currently hiding the closed rows. It only changes
   * the empty state's advice: telling a reader to turn off a filter that is
   * already off is worse than saying nothing.
   */
  activeOnly?: boolean;
}

/**
 * The unique-findings table of the aggregate report: one row per lineage row,
 * never per occurrence. Every column answers one question — which finding
 * (ref), how bad (severity), what and where (title + rel_path:line), who found
 * it (rule scan or AI review), how persistent (seen k of N), where it stands
 * (status), when last (last seen).
 */
export function AggregateTable({ rows, activeOnly = true }: AggregateTableProps) {
  const { t } = useTranslation();

  if (rows.length === 0) {
    return (
      <div data-testid="aggregate-empty" className="card p-8 text-center">
        <p className="text-[13px] text-muted">{t("aggregate.noFindings")}</p>
        <p className="text-[12px] text-muted-light mt-1">
          {activeOnly ? t("aggregate.noFindingsHint") : t("aggregate.noFindingsHintAll")}
        </p>
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      {/* Eight columns do not fit a narrow window, so this scrolls sideways.
          A scrollable box that nothing inside it can focus is unreachable from
          a keyboard, hence tabIndex and a name for it (WCAG 2.1.1). */}
      <div
        data-testid="aggregate-table-scroll"
        className="overflow-x-auto"
        tabIndex={0}
        role="region"
        aria-label={t("aggregate.tableLabel")}
      >
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="text-[10px] uppercase tracking-wider text-muted">
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colRef")}</th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colSeverity")}</th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colFinding")}</th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colCategory")}</th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colTier")}</th>
              <th
                scope="col"
                className="px-3 py-2 font-semibold"
                title={t("aggregate.seenHint")}
                aria-label={`${t("aggregate.colSeen")} — ${t("aggregate.seenHint")}`}
              >
                {t("aggregate.colSeen")}
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colStatus")}</th>
              <th scope="col" className="px-3 py-2 font-semibold">{t("aggregate.colLastSeen")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <AggregateRowView key={row.lineage_id} row={row} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
