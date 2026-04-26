/**
 * Feature 0039: live LLM provider health hook.
 *
 * Polls /api/llm/health every `pollIntervalMs` (default 30s). Returns the
 * current LLMHealth or null when the endpoint is unreachable / disabled.
 *
 * Backend caches /api/llm/health for 5s, so polling at 30s puts roughly
 * 1 of 6 polls onto the underlying agent network.
 */
import { useEffect, useState } from "react";
import { api } from "@/lib/api.ts";
import type { LLMHealth } from "@/lib/types.ts";

export function useLLMHealth(pollIntervalMs = 30_000): {
  health: LLMHealth | null;
  loading: boolean;
} {
  const [health, setHealth] = useState<LLMHealth | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const fetchHealth = async () => {
      try {
        const data = await api.getLLMHealth();
        if (!cancelled) setHealth(data);
      } catch {
        if (!cancelled) setHealth(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchHealth();
    const t = setInterval(fetchHealth, pollIntervalMs);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [pollIntervalMs]);

  return { health, loading };
}
