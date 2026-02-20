import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api.ts";
import type { AgentStep, StreamLine, TokenSavings, DedupStats } from "@/lib/types.ts";

const SSE_EVENT_TYPES = [
  "RunStarted", "RunFinished", "RunError",
  "StepStarted", "StepFinished",
  "TextMessageStart", "TextMessageContent", "TextMessageEnd",
  "ToolCallStart", "ToolCallArgs", "ToolCallEnd",
  "StateDelta", "StateSnapshot",
] as const;

export function useAgentStream(auditId: string | undefined, disabled = false) {
  const [lines, setLines] = useState<StreamLine[]>([]);
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [tokenSavings, setTokenSavings] = useState<TokenSavings | null>(null);
  const [dedupStats, setDedupStats] = useState<DedupStats | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const lineCounterRef = useRef(0);

  const addLine = useCallback(
    (text: string, type: StreamLine["type"]) => {
      setLines((prev) => [
        ...prev,
        { id: `l-${++lineCounterRef.current}`, text, type, timestamp: new Date() },
      ]);
    },
    [],
  );

  const updateStep = useCallback(
    (agentId: string, status: AgentStep["status"]) => {
      setSteps((prev) => {
        const exists = prev.find((s) => s.agent_id === agentId);
        if (exists) {
          return prev.map((s) =>
            s.agent_id === agentId ? { ...s, status, timestamp: new Date().toISOString() } : s,
          );
        }
        return [
          ...prev,
          { agent_id: agentId, label: agentId, status, timestamp: new Date().toISOString() },
        ];
      });
    },
    [],
  );

  const handleSSEEvent = useCallback(
    (eventType: string, data: Record<string, unknown>) => {
      switch (eventType) {
        case "RunStarted":
          addLine(`Audit started: ${String(data.runId ?? "")}`, "info");
          break;

        case "StepStarted": {
          const name = String(data.stepName ?? "agent");
          updateStep(name, "running");
          addLine(`Agent started: ${name}`, "step");
          break;
        }

        case "StepFinished": {
          const name = String(data.stepName ?? "agent");
          updateStep(name, "complete");
          addLine(`Agent finished: ${name}`, "step");
          break;
        }

        case "TextMessageContent": {
          const delta = data.delta;
          if (typeof delta === "string") {
            addLine(delta, "info");
          }
          break;
        }

        case "StateDelta": {
          const delta = data.delta;
          if (Array.isArray(delta)) {
            for (const op of delta) {
              const patch = op as Record<string, unknown>;
              if (patch.op === "add" && patch.value) {
                const finding = patch.value as Record<string, unknown>;
                const severity = String(finding.severity ?? "info").toUpperCase();
                const title = String(finding.title ?? "Finding");
                const file = String(finding.file_path ?? "");
                addLine(`[${severity}] ${title} \u2014 ${file}`, "finding");
              }
            }
          } else if (delta && typeof delta === "object") {
            const d = delta as Record<string, unknown>;
            // Handle dedup_stats event from skill mode (no LLM)
            if (d.dedup_stats && typeof d.dedup_stats === "object") {
              setDedupStats(d.dedup_stats as DedupStats);
              const ds = d.dedup_stats as DedupStats;
              addLine(
                `Memory optimization: ${ds.findings_deduped} findings deduplicated, ${ds.duplicates_removed} duplicates removed`,
                "info",
              );
            } else if (d.token_savings && typeof d.token_savings === "object") {
              setTokenSavings(d.token_savings as TokenSavings);
              const ts = d.token_savings as TokenSavings;
              addLine(
                `Memory optimization: ${ts.tokens_saved} tokens saved (${ts.savings_pct}%), ${ts.duplicates_removed} duplicates removed`,
                "info",
              );
            } else if (d.files_analyzed != null) {
              addLine(
                `Progress: ${String(d.files_analyzed)}/${String(d.total_files)} files, ${String(d.findings_count)} findings`,
                "progress",
              );
            }
          }
          break;
        }

        case "StateSnapshot":
          addLine("Results snapshot received", "info");
          break;

        case "RunFinished":
          addLine("Audit completed", "step");
          setDone(true);
          // Close EventSource to prevent auto-reconnect replay loop
          if (esRef.current) {
            esRef.current.close();
            esRef.current = null;
          }
          break;

        case "RunError":
          addLine(`Error: ${String(data.error ?? "Unknown error")}`, "error");
          setDone(true);
          if (esRef.current) {
            esRef.current.close();
            esRef.current = null;
          }
          break;

        default:
          break;
      }
    },
    [addLine, updateStep],
  );

  useEffect(() => {
    if (!auditId || disabled) return;

    const url = api.getStreamUrl(auditId);
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    for (const eventType of SSE_EVENT_TYPES) {
      es.addEventListener(eventType, (msg: MessageEvent) => {
        try {
          const data = JSON.parse(msg.data as string) as Record<string, unknown>;
          handleSSEEvent(eventType, data);
        } catch {
          addLine(String(msg.data), "info");
        }
      });
    }

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [auditId, disabled, handleSSEEvent, addLine]);

  return { lines, steps, connected, done, tokenSavings, dedupStats };
}
