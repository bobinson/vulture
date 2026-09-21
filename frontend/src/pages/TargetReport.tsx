import { useCallback } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useAggregate } from "@/hooks/useAggregate.ts";
import { useTargetScans } from "@/hooks/useTargetScans.ts";
import { AggregateTable } from "@/components/results/AggregateTable.tsx";
import { ROUTES } from "@/lib/constants.ts";
import {
  deriveTargetName,
  formatScanStamp,
  isUnattributed,
  targetKeyLabel,
} from "@/lib/targets.ts";
import type {
  AggregateFilters,
  AggregateTiles,
  FindingTier,
  Severity,
  TargetScan,
} from "@/lib/types.ts";

const PAGE_SIZE = 50;
const TIERS: FindingTier[] = ["det", "llm"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Tiles keep their height whether or not the numbers have arrived, so the
 * table below them never jumps when the request lands.
 *
 * `failed` stops the placeholder pulsing forever next to an error message —
 * an animation that never resolves reads as "still loading", which is the one
 * thing that is not happening.
 */
function TileRow({ tiles, failed }: { tiles: AggregateTiles | null; failed?: boolean }) {
  const { t } = useTranslation();
  const cells: { key: keyof AggregateTiles; label: string; tone: string }[] = [
    { key: "unique", label: t("aggregate.tileUnique"), tone: "text-foreground" },
    { key: "active", label: t("aggregate.tileActive"), tone: "text-foreground" },
    { key: "unconfirmed", label: t("aggregate.tileUnconfirmed"), tone: "text-[#9A3412]" },
    { key: "fixed", label: t("aggregate.tileFixed"), tone: "text-success" },
    { key: "critical", label: t("aggregate.tileCritical"), tone: "text-danger" },
  ];

  return (
    <div>
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
      {cells.map((cell) => (
        <div key={cell.key} className="card px-4 py-3 min-h-[64px]">
          <p className="text-[11px] text-muted font-medium uppercase tracking-wide mb-1">
            {cell.label}
          </p>
          {tiles ? (
            <p className={`text-xl font-semibold tabular-nums tracking-tight ${cell.tone}`}>
              {tiles[cell.key]}
            </p>
          ) : failed ? (
            <p className="text-xl font-semibold text-muted-light tracking-tight">—</p>
          ) : (
            <div className="h-6 w-10 rounded bg-cream-dark animate-pulse" aria-hidden="true" />
          )}
        </div>
      ))}
      </div>
      <p className="text-[11px] text-muted-light mt-1.5">{t("aggregate.tilesCaption")}</p>
    </div>
  );
}

interface ScanPickerProps {
  scans: TargetScan[];
  selected: Set<string> | null;
  loading: boolean;
  onToggle: (auditId: string) => void;
  onAll: () => void;
}

/** Which scans the aggregate covers. All of them, unless the reader says otherwise. */
function ScanPicker({ scans, selected, loading, onToggle, onAll }: ScanPickerProps) {
  const { t } = useTranslation();
  if (loading && scans.length === 0) {
    return (
      <div className="card px-4 py-3 h-[70px]" aria-hidden="true">
        <div className="h-2.5 w-24 rounded bg-cream-dark/70 animate-pulse" />
        <div className="flex gap-2 mt-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-6 w-40 rounded-md bg-cream-dark/70 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }
  if (scans.length === 0) return null;
  const onlyOneLeft = selected !== null && selected.size === 1;

  return (
    <fieldset className="card px-4 py-3">
      <div className="flex items-center justify-between gap-3 mb-2">
        <legend className="text-[11px] font-semibold text-muted uppercase tracking-wider">
          {t("aggregate.scansLegend")}
        </legend>
        <button
          type="button"
          onClick={onAll}
          disabled={selected === null}
          className="text-[11px] text-accent hover:underline disabled:text-muted-light disabled:no-underline disabled:cursor-default rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          {t("aggregate.selectAllScans")}
        </button>
      </div>
      <div className="flex flex-wrap gap-2">
        {scans.map((scan) => {
          const on = selected === null || selected.has(scan.audit_id);
          const when = formatScanStamp(scan.created_at);
          // Unchecking the LAST remaining scan used to silently re-check every
          // scan, because "none selected" and "all selected" are the same
          // request. Locking the last one says so instead of guessing.
          const locked = on && onlyOneLeft;
          const findings = scan.det_count + scan.llm_count;
          return (
            <label
              key={scan.audit_id}
              className={`inline-flex items-center gap-1.5 text-[11px] rounded-md border px-2 py-1 transition-colors focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-accent ${
                locked ? "cursor-default" : "cursor-pointer"
              } ${on ? "border-accent/60 bg-accent/5 text-foreground" : "border-border text-muted"}`}
              title={
                locked ? t("aggregate.scanKeepOne") : t("aggregate.toggleScan", { when })
              }
            >
              <input
                type="checkbox"
                checked={on}
                disabled={locked}
                onChange={() => onToggle(scan.audit_id)}
                className="accent-[#2563eb]"
              />
              <span className="tabular-nums">{when}</span>
              {scan.sub_path && <span className="font-mono text-accent/80">{scan.sub_path}</span>}
              <span className="tabular-nums text-muted-light" title={t("aggregate.scanFindings", { count: findings })}>
                {t("aggregate.scanFindings", { count: findings })}
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

/** Skeleton rows sized like the real table rows. */
function TableSkeleton() {
  return (
    <div className="card divide-y divide-border" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-3">
          <div className="h-3 w-20 rounded bg-cream-dark animate-pulse" />
          <div className="h-3 w-14 rounded bg-cream-dark/70 animate-pulse" />
          <div className="h-3 flex-1 rounded bg-cream-dark/70 animate-pulse" />
          <div className="h-3 w-12 rounded bg-cream-dark/70 animate-pulse" />
          <div className="h-3 w-16 rounded bg-cream-dark/70 animate-pulse" />
        </div>
      ))}
    </div>
  );
}

interface ChipFilterProps {
  legend: string;
  options: readonly string[];
  labelFor: (option: string) => string;
  selected: Set<string>;
  onToggle: (option: string) => void;
}

/**
 * A multi-select chip row. Selecting nothing means "no filter" rather than
 * "nothing", so the ALL state and the EMPTY state cannot be confused — the
 * same rule the query serialiser follows.
 */
function ChipFilter({ legend, options, labelFor, selected, onToggle }: ChipFilterProps) {
  return (
    <fieldset className="flex items-center gap-2 flex-wrap">
      <legend className="sr-only">{legend}</legend>
      <span className="text-[11px] text-muted-light">{legend}:</span>
      {options.map((option) => {
        const on = selected.has(option);
        return (
          <button
            key={option}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(option)}
            className={`px-2 py-0.5 text-[11px] rounded-md font-medium transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
              on
                ? "bg-foreground text-surface"
                : "text-muted hover:text-foreground hover:bg-cream-dark"
            }`}
          >
            {labelFor(option)}
          </button>
        );
      })}
    </fieldset>
  );
}

/** A comma-joined query parameter as a set; absent or empty means "no filter". */
function parseListParam(raw: string | null): Set<string> {
  return new Set((raw ?? "").split(",").filter(Boolean));
}

/** Add or remove one value, returning the comma-joined param or null for none. */
function toggleInList(current: Set<string>, value: string): string | null {
  const next = new Set(current);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next.size > 0 ? [...next].join(",") : null;
}

/** The selected audit ids, or `undefined` when the selection is "all". */
function subsetOf(scans: TargetScan[], selected: Set<string> | null): string[] | undefined {
  if (selected === null) return undefined;
  const ids = scans.map((s) => s.audit_id).filter((id) => selected.has(id));
  return ids.length > 0 && ids.length < scans.length ? ids : undefined;
}

function parseScansParam(raw: string | null): Set<string> | null {
  if (!raw) return null;
  const ids = raw.split(",").filter(Boolean);
  return ids.length > 0 ? new Set(ids) : null;
}

/**
 * A target's aggregate report — the DEFAULT view of a target (LLD 10.2).
 *
 * Every finding ever reported for the codebase is reachable here: the table is
 * one row per unique finding, "Active only" is a filter over it rather than a
 * different dataset, and turning it off reveals the fixed, resolved and
 * dismissed rows in place.
 *
 * All filtering and paging happen server-side. A filter change refetches one
 * page of the aggregate; the target list and the scan list are owned by other
 * hooks and are untouched by it.
 */
export function TargetReport() {
  const { t } = useTranslation();
  const params = useParams<{ key: string }>();
  const targetKey = params.key;
  const [search, setSearch] = useSearchParams();

  const activeOnly = search.get("status") !== "all";
  const selectedScans = parseScansParam(search.get("scans"));
  const page = Number.parseInt(search.get("page") ?? "1", 10) || 1;
  const tiers = parseListParam(search.get("tier"));
  const severities = parseListParam(search.get("severity"));
  const minSeen = Number.parseInt(search.get("min_seen") ?? "", 10);

  const { scans, loading: scansLoading } = useTargetScans(targetKey);

  // The scan selection only reaches the wire when it is a real subset:
  // "all selected" is the server's own default, and repeating it would make
  // the deep link go stale the moment a new scan of the target lands.
  const scanIds = subsetOf(scans, selectedScans);

  const filters: AggregateFilters = {
    scans: scanIds,
    status: activeOnly ? "active" : "all",
    // The endpoint takes ONE tier; selecting both is the same as selecting
    // neither, and saying so costs a parameter for nothing.
    tier: tiers.size === 1 ? ([...tiers][0] as FindingTier) : undefined,
    severity: severities.size > 0 ? [...severities] : undefined,
    min_seen: Number.isFinite(minSeen) && minSeen > 1 ? minSeen : undefined,
    page,
    page_size: PAGE_SIZE,
  };

  // A `?scans=` deep link cannot be turned into a request until the scan list
  // has landed: `subsetOf` reads `scans` to decide whether the selection is a
  // real subset, so firing early asks for the UNFILTERED page, renders it, and
  // then throws it away when the scan list arrives — two aggregate queries and
  // a flash of the wrong dataset for one page view.
  const scansPending = selectedScans !== null && scansLoading;
  const { data, loading, error, reload, stale } = useAggregate(
    scansPending ? undefined : targetKey,
    filters,
  );
  const busy = loading || scansPending;

  const patch = useCallback(
    (changes: Record<string, string | null>) => {
      setSearch(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(changes)) {
            if (value === null) next.delete(key);
            else next.set(key, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearch],
  );

  const toggleActiveOnly = useCallback(() => {
    patch({ status: activeOnly ? "all" : null, page: null });
  }, [patch, activeOnly]);

  const toggleScan = useCallback(
    (auditId: string) => {
      const current = parseScansParam(search.get("scans")) ?? new Set(scans.map((s) => s.audit_id));
      const next = new Set(current);
      if (next.has(auditId)) next.delete(auditId);
      else next.add(auditId);
      const all = next.size === scans.length;
      patch({ scans: all || next.size === 0 ? null : [...next].join(","), page: null });
    },
    [patch, scans, search],
  );

  const toggleTier = useCallback(
    (tier: string) => patch({ tier: toggleInList(parseListParam(search.get("tier")), tier), page: null }),
    [patch, search],
  );

  const toggleSeverity = useCallback(
    (severity: string) =>
      patch({
        severity: toggleInList(parseListParam(search.get("severity")), severity),
        page: null,
      }),
    [patch, search],
  );

  const selectAllScans = useCallback(() => patch({ scans: null, page: null }), [patch]);
  const goToPage = useCallback((n: number) => patch({ page: String(n) }), [patch]);

  if (!targetKey) return null;

  const name = isUnattributed(targetKey) ? t("targets.unattributed") : deriveTargetName(targetKey);
  const tiles = data?.tiles ?? null;
  const hiddenCount = tiles?.fixed ?? 0;
  const total = data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div data-testid="aggregate-report" className="max-w-6xl space-y-4">
      <div className="flex items-center justify-between gap-3 -mt-4">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-foreground truncate" title={targetKey}>
            {name}
          </h2>
          <p className="text-[12px] text-muted font-mono truncate" title={targetKey}>
            {targetKeyLabel(targetKey)}
          </p>
        </div>
        <Link to={ROUTES.TARGETS} className="btn-secondary text-[12px] shrink-0">
          {t("targets.allTargets")}
        </Link>
      </div>

      <TileRow tiles={tiles} failed={Boolean(error)} />

      <ScanPicker
        scans={scans}
        selected={selectedScans}
        loading={scansLoading}
        onToggle={toggleScan}
        onAll={selectAllScans}
      />

      <div className="flex items-center gap-3 flex-wrap">
        <button
          type="button"
          data-testid="aggregate-active-only-toggle"
          role="switch"
          aria-checked={activeOnly}
          onClick={toggleActiveOnly}
          title={activeOnly ? t("aggregate.showAllHint") : t("aggregate.activeOnlyHint")}
          className={`inline-flex items-center gap-2 px-2.5 py-1 text-[12px] font-medium rounded-md border transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
            activeOnly
              ? "border-accent/60 bg-accent/5 text-foreground"
              : "border-border text-muted hover:text-foreground"
          }`}
        >
          <span
            aria-hidden="true"
            className={`w-2 h-2 rounded-full ${activeOnly ? "bg-accent" : "bg-border-dark"}`}
          />
          {t("aggregate.activeOnly")}
        </button>

        {/* "Hiding 0 fixed findings" is what a first scan of a codebase reads,
            and a count of nothing is not worth a sentence. With nothing yet
            fixed, say what the filter DOES instead. */}
        <p className="text-[11px] text-muted" data-testid="aggregate-filter-summary">
          {!activeOnly
            ? t("aggregate.showAllIncludes")
            : hiddenCount > 0
              ? t("aggregate.activeOnlyExcludes", { count: hiddenCount })
              : t("aggregate.activeOnlyHint")}
        </p>
      </div>

      <div className="flex items-center gap-5 flex-wrap">
        <ChipFilter
          legend={t("aggregate.colTier")}
          options={TIERS}
          labelFor={(tier) => t(`aggregate.tier_${tier}`)}
          selected={tiers}
          onToggle={toggleTier}
        />
        <ChipFilter
          legend={t("aggregate.colSeverity")}
          options={SEVERITIES}
          labelFor={(severity) => t(`severity.${severity}`)}
          selected={severities}
          onToggle={toggleSeverity}
        />
      </div>

      {error && (
        <div className="card p-6 text-center space-y-3">
          <p className="text-[13px] text-danger">{t("aggregate.loadFailed")}</p>
          <button type="button" className="btn-secondary text-[12px]" onClick={reload}>
            {t("common.retry")}
          </button>
        </div>
      )}

      {/* The skeleton is the FIRST load only. A filter change keeps the page
          that is already on screen — dimmed and marked busy — so the table
          does not collapse to a five-row placeholder and back on every chip. */}
      {!error && busy && !data && <TableSkeleton />}

      {!error && data && (
        <div
          aria-busy={stale || undefined}
          className={stale ? "opacity-60 transition-opacity duration-150" : "transition-opacity duration-150"}
        >
          <AggregateTable rows={data.rows ?? []} activeOnly={activeOnly} />
        </div>
      )}

      {!error && !busy && !data && <AggregateTable rows={[]} activeOnly={activeOnly} />}

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between gap-3">
          <p className="text-[11px] text-muted tabular-nums">
            {t("aggregate.pageOf", { page, pages: lastPage, total })}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn-secondary text-[12px] disabled:opacity-50"
              disabled={page <= 1}
              onClick={() => goToPage(page - 1)}
            >
              {t("aggregate.prevPage")}
            </button>
            <button
              type="button"
              className="btn-secondary text-[12px] disabled:opacity-50"
              disabled={page >= lastPage}
              onClick={() => goToPage(page + 1)}
            >
              {t("aggregate.nextPage")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
