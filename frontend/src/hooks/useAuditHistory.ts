import { useMemo } from "react";
import { useTargetScans } from "./useTargetScans.ts";
import type { Audit, TargetScan } from "@/lib/types.ts";

/** A scan row rendered as the Audit shape the history timeline already reads. */
function scanToAudit(scan: TargetScan): Audit {
  return {
    id: scan.audit_id,
    source_id: "",
    status: "completed",
    types: scan.types,
    findings_count: scan.det_count + scan.llm_count,
    created_at: scan.created_at,
    completed_at: scan.created_at,
  };
}

/**
 * The scan history of the codebase the current audit belongs to.
 *
 * Feature 0091: keyed by `target_key`, not by `source_path`. A target groups
 * every scan of one codebase whatever path form it was submitted under — the
 * container mount, the native path, a sub-path scan — so a mount change no
 * longer hides a project's own history from it.
 *
 * Both shapes come from ONE request: `scans` for the scan-history rail,
 * `audits` for the existing history timeline.
 */
export function useAuditHistory(targetKey?: string): { scans: TargetScan[]; audits: Audit[] } {
  const { scans } = useTargetScans(targetKey);
  const audits = useMemo(() => scans.map(scanToAudit), [scans]);
  return { scans, audits };
}
