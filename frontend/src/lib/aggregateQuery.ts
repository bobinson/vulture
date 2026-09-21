import type { AggregateFilters } from "./types.ts";

/**
 * Serialise the aggregate filters into the query string of
 * `GET /api/targets/{key}/aggregate` (LLD 10.1).
 *
 * Two rules, both deliberate:
 *
 *  - **An unset filter sends nothing.** "omit = all scans", "omit = both
 *    tiers" and "default active" are server-side defaults; a client that
 *    materialises them turns a server default change into a client release.
 *  - **A multi-valued filter is comma-joined, never repeated.** `scans=a,b`,
 *    not `scans=a&scans=b` — the endpoint reads one value per name.
 *
 * The result is a value, not an object, so a hook can depend on it directly
 * and a re-render with a fresh-but-equal filter object does not refetch.
 */
export function buildAggregateQuery(filters: AggregateFilters): string {
  const params = new URLSearchParams();
  const list = (key: string, values?: string[]) => {
    if (values && values.length > 0) params.set(key, values.join(","));
  };
  const scalar = (key: string, value?: string | number) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  };

  list("scans", filters.scans);
  scalar("status", filters.status);
  scalar("tier", filters.tier);
  scalar("min_seen", filters.min_seen);
  list("severity", filters.severity);
  scalar("page", filters.page);
  scalar("page_size", filters.page_size);

  const query = params.toString();
  return query ? `?${query}` : "";
}
