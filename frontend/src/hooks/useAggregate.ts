import { api } from "@/lib/api.ts";
import { buildAggregateQuery } from "@/lib/aggregateQuery.ts";
import { useAsyncResource, type AsyncResource } from "./useAsyncResource.ts";
import type { AggregateFilters, AggregateResponse } from "@/lib/types.ts";

/**
 * One page of a target's aggregate report (LLD 10.1).
 *
 * Paging and filtering are the server's job: this hook asks for the page the
 * filters describe and holds nothing else, so a filter change costs one
 * request for one page rather than a full download sliced in the browser.
 * The request key is the serialised query, so the target list and the scan
 * list — owned by `useTargets` / `useTargetScans` — are never re-pulled by a
 * filter change.
 *
 * THE LAST GOOD PAGE IS RETAINED across a filter change, and only across one
 * of the SAME target. `useAsyncResource` reports `data: null` the instant the
 * key changes, which is correct for a resource whose identity changed and
 * wrong for a re-query of the same one: at the default page size that turned
 * every filter toggle into 50 rows (1,277 DOM nodes) collapsing to a five-row
 * placeholder and back, taking the tiles and the pager with them. Keying the
 * retention on `targetKey` is what keeps it from ever showing target A's rows
 * under target B's heading.
 */
export function useAggregate(
  targetKey: string | undefined,
  filters: AggregateFilters,
): AsyncResource<AggregateResponse> {
  const query = buildAggregateQuery(filters);
  const key = targetKey ? `${targetKey}${query}` : null;
  return useAsyncResource(
    key,
    () => (targetKey ? api.getAggregate(targetKey, query) : Promise.reject(new Error("no target"))),
    { family: targetKey },
  );
}
