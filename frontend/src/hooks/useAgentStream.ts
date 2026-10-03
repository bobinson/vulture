import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { api } from "@/lib/api.ts";
import { OWASP, parseComplianceMapping, type ComplianceMapping } from "@/lib/compliance.ts";
import {
  EMPTY_LIVE_FINDINGS,
  createLiveBatcher,
  flattenLiveFindings,
  liveFindingsBatchReducer,
  toLiveFindings,
  type LiveBatcher,
  type LiveFindingsAction,
} from "@/lib/liveFindings.ts";
import type { AgentStep, StreamLine, TokenSavings, DedupStats, OwaspCoverageManifest } from "@/lib/types.ts";

const SSE_EVENT_TYPES = [
  "RunStarted", "RunFinished", "RunError",
  "StepStarted", "StepFinished",
  "TextMessageStart", "TextMessageContent", "TextMessageEnd",
  "ToolCallStart", "ToolCallArgs", "ToolCallEnd",
  "StateDelta", "StateSnapshot",
] as const;

/** Maximum number of stream lines retained in state. */
const MAX_LINES = 500;

/** Per-finding L5 verdict update. Consumers (e.g. AuditResults.tsx)
 *  merge these into their findings state so the row's badge updates
 *  in place without a refetch. Feature 0046 issue #12. */
export interface ValidationUpdate {
  id: string;
  status?: string;
  confidence?: number;
}

const EMPTY_VALIDATION_UPDATES: Record<string, ValidationUpdate> = {};

function validationUpdatesReducer(
  state: Record<string, ValidationUpdate>,
  action: ValidationUpdate,
): Record<string, ValidationUpdate> {
  const prev = state[action.id];
  // No-op if nothing actually changed — avoids triggering downstream
  // re-renders on duplicate verdicts (e.g. cache rehydration).
  if (prev && prev.status === action.status && prev.confidence === action.confidence) {
    return state;
  }
  return { ...state, [action.id]: { ...prev, ...action } };
}

export function useAgentStream(auditId: string | undefined, disabled = false) {
  const [lines, setLines] = useState<StreamLine[]>([]);
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [tokenSavings, setTokenSavings] = useState<TokenSavings | null>(null);
  const [dedupStats, setDedupStats] = useState<DedupStats | null>(null);
  // Feature 0063: OWASP coverage manifest, carried on the OWASP agent's
  // result StateSnapshot (owasp_coverage).
  const [owaspCoverage, setOwaspCoverage] = useState<OwaspCoverageManifest | null>(null);
  // Feature 0096: the OWASP agent's CWE -> category table, so the page can
  // label its in-memory rows before the backend persists the labels.
  const [owaspMapping, setOwaspMapping] = useState<ComplianceMapping | null>(null);
  // Feature 0096 (R15): the findings the stream has delivered, per agent, so
  // the page has rows to show (and label) before anything is persisted.
  // 0096 M9: actions are queued and applied once per animation frame (at
  // most every 250 ms), so N findings in a frame cost one state update — and
  // one pass of the page's labelling, filtering and sorting — not N.
  const [liveByAgent, dispatchLiveBatch] = useReducer(liveFindingsBatchReducer, EMPTY_LIVE_FINDINGS);
  const [liveBatcher] = useState<LiveBatcher>(() => createLiveBatcher(dispatchLiveBatch));
  const liveFindings = useMemo(() => flattenLiveFindings(liveByAgent), [liveByAgent]);
  // Feature 0046 issues #12 + #18: accumulate L5 verdict patches via
  // a reducer so React batches updates instead of creating a fresh
  // top-level object per verdict. Each dispatch is O(1) on average
  // (single key update); the reducer mutates a copy keyed on id.
  const [validationUpdates, dispatchValidation] = useReducer(
    validationUpdatesReducer,
    EMPTY_VALIDATION_UPDATES,
  );
  const esRef = useRef<EventSource | null>(null);
  const lineCounterRef = useRef(0);

  const recordValidationUpdate = useCallback((u: ValidationUpdate) => {
    dispatchValidation(u);
  }, []);

  // Issue #9: Cap lines at MAX_LINES, dropping oldest entries
  const addLine = useCallback(
    (text: string, type: StreamLine["type"]) => {
      setLines((prev) => {
        const next = [
          ...prev,
          { id: `l-${++lineCounterRef.current}`, text, type, timestamp: new Date() },
        ];
        if (next.length > MAX_LINES) {
          return next.slice(next.length - MAX_LINES);
        }
        return next;
      });
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

  // Issues #1, #2: Store callbacks in refs so the effect handler is stable.
  // Refs synced via useEffect (post-commit) to satisfy react-hooks/refs —
  // writing to .current during render breaks concurrent-mode safety.
  const addLineRef = useRef(addLine);
  useEffect(() => { addLineRef.current = addLine; });

  const updateStepRef = useRef(updateStep);
  useEffect(() => { updateStepRef.current = updateStep; });

  // Stable handler ref -- never changes identity, calls current refs internally.
  // addLine/updateStep use refs because they are user-defined callbacks that could change.
  // setDone/setConnected/setDedupStats/setTokenSavings are React state setters,
  // which are guaranteed stable across renders (React contract), so closing over
  // them directly is safe. The live batcher is created once (useState
  // initialiser) and never replaced, so closing over it is equally stable.
  const handleSSEEventRef = useRef(
    (eventType: string, data: Record<string, unknown>) => {
      const dispatchLive = (a: LiveFindingsAction) => liveBatcher.push(a);
      const addLineFn = addLineRef.current;
      const updateStepFn = updateStepRef.current;

      switch (eventType) {
        case "RunStarted":
          addLineFn(`Audit started: ${String(data.runId ?? "")}`, "info");
          break;

        case "StepStarted": {
          const name = String(data.stepName ?? "agent");
          updateStepFn(name, "running");
          addLineFn(`Agent started: ${name}`, "step");
          break;
        }

        case "StepFinished": {
          const name = String(data.stepName ?? "agent");
          updateStepFn(name, "complete");
          addLineFn(`Agent finished: ${name}`, "step");
          break;
        }

        case "TextMessageContent": {
          const delta = data.delta;
          if (typeof delta === "string") {
            addLineFn(delta, "info");
          }
          break;
        }

        case "StateDelta":
          handleStateDelta(data, addLineFn, setDedupStats, setTokenSavings, recordValidationUpdate, dispatchLive);
          break;

        case "StateSnapshot":
          addLineFn("Results snapshot received", "info");
          handleSnapshot(data, setOwaspCoverage, setOwaspMapping, dispatchLive);
          break;

        case "RunFinished":
          liveBatcher.flush();
          addLineFn("Audit completed", "step");
          setDone(true);
          if (esRef.current) {
            esRef.current.close();
            esRef.current = null;
          }
          break;

        case "RunError":
          liveBatcher.flush();
          addLineFn(`Error: ${String(data.error ?? "Unknown error")}`, "error");
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
  );

  // Issue #10: Effect depends only on [auditId, disabled] (liveBatcher never changes)
  useEffect(() => {
    if (!auditId || disabled) return;

    let cancelled = false;

    const connect = async () => {
      try {
        const streamToken = await api.getStreamToken(auditId);
        if (cancelled) return;

        const url = api.getStreamUrl(auditId, streamToken);
        const es = new EventSource(url);
        esRef.current = es;

        es.onopen = () => setConnected(true);
        es.onerror = () => {
          setConnected(false);
          es.close();
          esRef.current = null;
        };

        for (const eventType of SSE_EVENT_TYPES) {
          es.addEventListener(eventType, (msg: MessageEvent) => {
            try {
              const data = JSON.parse(msg.data as string) as Record<string, unknown>;
              handleSSEEventRef.current(eventType, data);
            } catch {
              addLineRef.current(String(msg.data), "info");
            }
          });
        }
      } catch {
        addLineRef.current("Failed to establish stream connection", "error");
      }
    };

    connect();

    return () => {
      cancelled = true;
      liveBatcher.cancel();
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [auditId, disabled, liveBatcher]);

  return {
    lines,
    steps,
    connected,
    done,
    tokenSavings,
    dedupStats,
    validationUpdates,
    owaspCoverage,
    owaspMapping,
    liveFindings,
  };
}

/**
 * Handle a result StateSnapshot: the OWASP coverage manifest (0063) and the
 * OWASP mapping (0096). Both are taken only from a snapshot the backend
 * attributes to the owasp agent (`agentType` is set server-side, not by the
 * agent's payload), mirroring the backend's own trust rule; an invalid one is
 * dropped whole. A snapshot's `findings` array is its agent's finished set,
 * and replaces the rows that agent streamed (0096 R15).
 */
function handleSnapshot(
  data: Record<string, unknown>,
  setCoverage: (m: OwaspCoverageManifest) => void,
  setMapping: (m: ComplianceMapping) => void,
  dispatchLive: (a: LiveFindingsAction) => void,
) {
  const snap = data.snapshot as Record<string, unknown> | undefined;
  const agent = streamAgent(data);
  if (Array.isArray(snap?.findings)) {
    dispatchLive({ kind: "replace", agent, findings: toLiveFindings(snap.findings, agent) });
  }
  // The manifest and the mapping are the owasp agent's alone (0096 M3): a
  // snapshot any other agent sent cannot set either.
  if (data.agentType !== OWASP) return;
  const cov = snap?.owasp_coverage;
  if (cov && typeof cov === "object" && !Array.isArray(cov)) {
    setCoverage(cov as OwaspCoverageManifest);
  }
  const mapping = parseComplianceMapping(snap?.mapping);
  if (mapping) setMapping(mapping);
}

/** The agent the backend attributes an event to (set server-side, not by the agent). */
function streamAgent(data: Record<string, unknown>): string {
  return typeof data.agentType === "string" ? data.agentType : "";
}

/** Handle StateDelta events -- extracted to keep handleSSEEvent under complexity limit. */
function handleStateDelta(
  data: Record<string, unknown>,
  addLineFn: (text: string, type: StreamLine["type"]) => void,
  setDedupStatsFn: React.Dispatch<React.SetStateAction<DedupStats | null>>,
  setTokenSavingsFn: React.Dispatch<React.SetStateAction<TokenSavings | null>>,
  recordValidationUpdate: (u: ValidationUpdate) => void,
  dispatchLive: (a: LiveFindingsAction) => void,
) {
  const delta = data.delta;
  if (Array.isArray(delta)) {
    const added = handleFindingsDelta(delta, addLineFn, recordValidationUpdate);
    const agent = streamAgent(data);
    dispatchLive({ kind: "add", agent, findings: toLiveFindings(added, agent) });
    return;
  }
  if (delta && typeof delta === "object") {
    handleObjectDelta(delta as Record<string, unknown>, addLineFn, setDedupStatsFn, setTokenSavingsFn);
  }
}

/** Process array deltas (individual findings); returns the added finding values. */
function handleFindingsDelta(
  delta: unknown[],
  addLineFn: (text: string, type: StreamLine["type"]) => void,
  recordValidationUpdate: (u: ValidationUpdate) => void,
): unknown[] {
  const added: unknown[] = [];
  // L5 validation_update deltas arrive as multiple `replace` ops with
  // path `/findings/<id>/validation_status` etc. Group per finding id,
  // then emit BOTH a one-line stream entry and a structured update so
  // the consumer can patch its findings state in place.
  const replaceByID: Record<string, ValidationUpdate> = {};
  for (const op of delta) {
    const patch = op as Record<string, unknown>;
    if (patch.op === "add" && patch.value) {
      const finding = patch.value as Record<string, unknown>;
      const severity = String(finding.severity ?? "info").toUpperCase();
      const title = String(finding.title ?? "Finding");
      const file = String(finding.file_path ?? "");
      addLineFn(`[${severity}] ${title} \u2014 ${file}`, "finding");
      added.push(patch.value);
      continue;
    }
    if (patch.op !== "replace" || typeof patch.path !== "string") continue;
    const parts = patch.path.split("/");
    if (parts.length < 4 || parts[1] !== "findings") continue;
    const id = parts[2];
    const field = parts[3];
    const entry = replaceByID[id] ?? { id };
    if (field === "validation_status" && typeof patch.value === "string") {
      entry.status = patch.value;
    } else if (field === "validation_confidence" && typeof patch.value === "number") {
      entry.confidence = patch.value;
    }
    replaceByID[id] = entry;
  }
  for (const id of Object.keys(replaceByID)) {
    const u = replaceByID[id];
    if (!u.status) continue;
    recordValidationUpdate(u);
    const confStr = u.confidence !== undefined ? ` (${(u.confidence * 100).toFixed(0)}%)` : "";
    addLineFn(`L5 verdict: ${id.slice(0, 10)} \u2192 ${u.status}${confStr}`, "info");
  }
  return added;
}

/** Process object deltas (dedup_stats, token_savings, progress). */
function handleObjectDelta(
  d: Record<string, unknown>,
  addLineFn: (text: string, type: StreamLine["type"]) => void,
  setDedupStatsFn: React.Dispatch<React.SetStateAction<DedupStats | null>>,
  setTokenSavingsFn: React.Dispatch<React.SetStateAction<TokenSavings | null>>,
) {
  if (d.dedup_stats && typeof d.dedup_stats === "object") {
    setDedupStatsFn(d.dedup_stats as DedupStats);
    const ds = d.dedup_stats as DedupStats;
    addLineFn(
      `Memory optimization: ${ds.findings_deduped} findings deduplicated, ${ds.duplicates_removed} duplicates removed`,
      "info",
    );
    return;
  }
  if (d.token_savings && typeof d.token_savings === "object") {
    setTokenSavingsFn(d.token_savings as TokenSavings);
    const ts = d.token_savings as TokenSavings;
    addLineFn(
      `Memory optimization: ${ts.tokens_saved} tokens saved (${ts.savings_pct}%), ${ts.duplicates_removed} duplicates removed`,
      "info",
    );
    return;
  }
  if (d.files_analyzed != null) {
    addLineFn(
      `Progress: ${String(d.files_analyzed)}/${String(d.total_files)} files, ${String(d.findings_count)} findings`,
      "progress",
    );
  }
}
