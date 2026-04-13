import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api.ts";
import type { Audit, Severity } from "@/lib/types.ts";

/** Map LLM severity abbreviations/variants to canonical form. */
const SEVERITY_ALIASES: Record<string, Severity> = {
  c: "critical", crit: "critical", critical: "critical",
  h: "high", high: "high",
  m: "medium", med: "medium", medium: "medium",
  l: "low", low: "low",
  i: "info", info: "info", informational: "info",
};

function normalizeSeverity(raw: string): Severity {
  return SEVERITY_ALIASES[raw.toLowerCase().trim()] ?? "info";
}

/** Normalize finding severity from LLM output to canonical lowercase form. */
function normalizeAudit(audit: Audit): Audit {
  if (!audit.findings) return audit;
  return {
    ...audit,
    findings: audit.findings.map((f) => ({
      ...f,
      severity: normalizeSeverity(f.severity),
    })),
  };
}

const INITIAL_DELAY = 2000;
const MAX_DELAY = 10000;
const BACKOFF_FACTOR = 1.5;

export function useAudit(auditId?: string) {
  const [audit, setAudit] = useState<Audit | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const createAudit = useCallback(
    async (sourceId: string, types: string[]) => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.createAudit({ source_id: sourceId, types });
        setAudit(normalizeAudit(result));
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Failed to create audit";
        setError(message);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const fetchAudit = useCallback(async (id: string) => {
    try {
      const result = await api.getAudit(id);
      setAudit(normalizeAudit(result));
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch audit";
      setError(message);
      return null;
    }
  }, []);

  useEffect(() => {
    if (!auditId) return;
    let delay = INITIAL_DELAY;
    let timer: ReturnType<typeof setTimeout>;
    let aborted = false;
    const poll = async () => {
      const result = await fetchAudit(auditId);
      if (aborted) return;
      if (result && (result.status === "completed" || result.status === "failed")) return;
      timer = setTimeout(poll, delay);
      delay = Math.min(delay * BACKOFF_FACTOR, MAX_DELAY);
    };
    poll();
    return () => { aborted = true; clearTimeout(timer); };
  }, [auditId, fetchAudit]);

  return { audit, loading, error, createAudit, fetchAudit };
}
