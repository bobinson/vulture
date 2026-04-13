import { useEffect, useState } from "react";
import { api } from "@/lib/api.ts";
import type { Audit } from "@/lib/types.ts";

export function useAuditHistory(sourcePath?: string) {
  const [history, setHistory] = useState<Audit[]>([]);

  useEffect(() => {
    if (!sourcePath) return;
    api.listAuditsBySource(sourcePath, 10).then(setHistory).catch(() => {});
  }, [sourcePath]);

  return history;
}
