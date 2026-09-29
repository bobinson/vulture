import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api.ts";
import { normalizeSeverity } from "@/lib/severity.ts";
import type { Audit } from "@/lib/types.ts";

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

  // Several reads can be in flight at once (the poll, a re-read after a
  // triage save); only the latest one started may set the state, so a slow,
  // earlier response never overwrites a newer one.
  const readSeqRef = useRef(0);

  const fetchAudit = useCallback(async (id: string) => {
    const seq = ++readSeqRef.current;
    try {
      const result = await api.getAudit(id);
      if (seq === readSeqRef.current) setAudit(normalizeAudit(result));
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch audit";
      if (seq === readSeqRef.current) setError(message);
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
