import { useEffect, useState } from "react";
import { api } from "@/lib/api.ts";
import type { AuditComparison } from "@/lib/types.ts";

export function useAuditComparison(auditId?: string, isCompleted?: boolean) {
  const [comparison, setComparison] = useState<AuditComparison | null>(null);

  useEffect(() => {
    if (!auditId || !isCompleted) return;
    api.getAuditComparison(auditId).then(setComparison).catch(() => {});
  }, [auditId, isCompleted]);

  return comparison;
}
