import { api } from "@/lib/api.ts";
import { useAsyncResource } from "./useAsyncResource.ts";
import type { TargetSummary } from "@/lib/types.ts";

/** Every scanned target, for the dashboard target list (LLD 10.2). */
export function useTargets(): {
  targets: TargetSummary[];
  loading: boolean;
  error: string | null;
  reload: () => void;
} {
  const { data, loading, error, reload } = useAsyncResource("targets", () => api.listTargets());
  return { targets: data ?? [], loading, error, reload };
}
