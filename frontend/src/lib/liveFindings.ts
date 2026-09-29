import { normalizeSeverity } from "./severity.ts";
import type { Finding } from "./types.ts";

/**
 * Feature 0096 (R15): the findings a live run holds before the backend
 * persists any. The audit record carries no rows while it runs — findings are
 * stored, already labelled, in the step that completes it — so the results
 * page shows the rows the stream delivered, and labels them with the OWASP
 * agent's streamed mapping.
 *
 * Rows are kept per agent: each streamed finding is appended to its agent's
 * rows, and that agent's result snapshot (its finished set) replaces them.
 */

/** Live rows keyed by the agent the backend attributes them to. */
export type LiveFindingsState = Readonly<Record<string, readonly Finding[]>>;

export type LiveFindingsAction =
  | { kind: "add"; agent: string; findings: Finding[] }
  | { kind: "replace"; agent: string; findings: Finding[] };

export const EMPTY_LIVE_FINDINGS: LiveFindingsState = {};

/**
 * Apply actions in order, as one state step. Equal to reducing them one by
 * one, but each touched agent's rows are copied ONCE per batch rather than
 * once per streamed finding — the per-delta copy made the live path O(n^2).
 * Arrays already in `state` (and a snapshot's own array) are never mutated;
 * a batch that changes nothing returns `state` itself.
 */
export function applyLiveActions(state: LiveFindingsState, actions: readonly LiveFindingsAction[]): LiveFindingsState {
  const touched = new Map<string, Finding[]>();
  for (const a of actions) {
    if (a.kind === "replace") {
      touched.set(a.agent, [...a.findings]);
      continue;
    }
    if (a.findings.length === 0) continue;
    let rows = touched.get(a.agent);
    if (!rows) {
      rows = [...(state[a.agent] ?? [])];
      touched.set(a.agent, rows);
    }
    for (const f of a.findings) rows.push(f);
  }
  if (touched.size === 0) return state;
  return { ...state, ...Object.fromEntries(touched) };
}

export function liveFindingsReducer(state: LiveFindingsState, action: LiveFindingsAction): LiveFindingsState {
  return applyLiveActions(state, [action]);
}

/** The reducer the stream hook holds: it receives one batch per flush. */
export function liveFindingsBatchReducer(
  state: LiveFindingsState,
  actions: readonly LiveFindingsAction[],
): LiveFindingsState {
  return applyLiveActions(state, actions);
}

/** Schedules `cb` once; returns a function that cancels it. */
export type LiveSchedule = (cb: () => void) => () => void;

/** Upper bound on how long a queued action waits when no frame arrives (a hidden tab gets none). */
export const LIVE_FLUSH_MAX_MS = 250;

/**
 * Next animation frame or LIVE_FLUSH_MAX_MS, whichever comes first: a visible
 * page updates once per frame, a hidden one (no frames) still every 250 ms.
 */
export const defaultLiveSchedule: LiveSchedule = (cb) => {
  let done = false;
  const run = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (frame !== undefined) cancelAnimationFrame(frame);
    cb();
  };
  const timer = setTimeout(run, LIVE_FLUSH_MAX_MS);
  const frame = typeof requestAnimationFrame === "function" ? requestAnimationFrame(run) : undefined;
  return () => {
    done = true;
    clearTimeout(timer);
    if (frame !== undefined) cancelAnimationFrame(frame);
  };
};

export interface LiveBatcher {
  /** Queue an action; the first action of a batch schedules its flush. */
  push(action: LiveFindingsAction): void;
  /** Deliver the queue now (the run ended) and cancel the scheduled flush. */
  flush(): void;
  /** Drop the queue and the scheduled flush (the stream was torn down). */
  cancel(): void;
}

/**
 * Coalesce live actions into one dispatch per frame (0096 M9). Order is kept:
 * the batch is the actions in arrival order, applied by `applyLiveActions`.
 */
export function createLiveBatcher(
  dispatch: (actions: LiveFindingsAction[]) => void,
  schedule: LiveSchedule = defaultLiveSchedule,
): LiveBatcher {
  let queue: LiveFindingsAction[] = [];
  let cancelScheduled: (() => void) | null = null;
  const flush = () => {
    cancelScheduled?.();
    cancelScheduled = null;
    if (queue.length === 0) return;
    const batch = queue;
    queue = [];
    dispatch(batch);
  };
  return {
    push(action) {
      queue.push(action);
      if (!cancelScheduled) cancelScheduled = schedule(flush);
    },
    flush,
    cancel() {
      cancelScheduled?.();
      cancelScheduled = null;
      queue = [];
    },
  };
}

export function flattenLiveFindings(state: LiveFindingsState): Finding[] {
  return Object.values(state).flat();
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * A streamed finding value as a row, or null when it is not one. The agent is
 * the one the backend names on the event (`agentType`), never the payload's
 * own claim, and a payload's `compliance_labels` are dropped: only a mapping
 * labels a row, as on the backend.
 */
export function toLiveFinding(raw: unknown, agentType: string): Finding | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.title !== "string" || r.title === "") return null;
  const { compliance_labels: _labels, ...rest } = r;
  void _labels;
  return {
    ...(rest as Partial<Finding>),
    agent_type: agentType || str(r.agent_type) || undefined,
    severity: normalizeSeverity(str(r.severity)),
    category: str(r.category),
    title: r.title,
    description: str(r.description),
    recommendation: str(r.recommendation),
    file_path: str(r.file_path),
  };
}

/** Each value that is a finding, as a row attributed to `agentType`. */
export function toLiveFindings(values: unknown[], agentType: string): Finding[] {
  const out: Finding[] = [];
  for (const v of values) {
    const f = toLiveFinding(v, agentType);
    if (f) out.push(f);
  }
  return out;
}
