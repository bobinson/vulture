import { api } from "@/lib/api.ts";
import { useAsyncResource } from "./useAsyncResource.ts";
import type { TargetScan } from "@/lib/types.ts";

/**
 * Every scan of one target, newest first — the source of both the scan picker
 * on the aggregate report and the scan-history rail on the per-scan results
 * page. Keyed by target, so a root scan and a sub-path scan of the same
 * project sit on the same rail whatever path form each was submitted under.
 */
export function useTargetScans(targetKey: string | undefined): {
  scans: TargetScan[];
  loading: boolean;
  error: string | null;
} {
  const { data, loading, error } = useAsyncResource(targetKey ?? null, () =>
    targetKey ? api.listTargetScans(targetKey) : Promise.reject(new Error("no target")),
  );
  return { scans: data ?? [], loading, error };
}
