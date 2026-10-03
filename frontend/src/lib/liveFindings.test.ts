import { describe, expect, it, vi } from "vitest";
import {
  EMPTY_LIVE_FINDINGS,
  applyLiveActions,
  createLiveBatcher,
  flattenLiveFindings,
  liveFindingsReducer,
  type LiveFindingsAction,
  type LiveFindingsState,
} from "./liveFindings.ts";
import type { Finding } from "./types.ts";

/**
 * Feature 0096 (M9): the live path must not be O(n^2). Every streamed finding
 * used to copy its agent's whole array and re-render the page; deltas are now
 * queued and applied once per frame, with a result identical to applying each
 * action on its own, in order.
 */

const row = (agent: string, n: number): Finding => ({
  agent_type: agent,
  severity: "high",
  category: "CWE-798",
  title: `${agent}-${n}`,
  description: "",
  recommendation: "",
  file_path: "a.ts",
});

const sequential = (actions: LiveFindingsAction[]): LiveFindingsState =>
  actions.reduce(liveFindingsReducer, EMPTY_LIVE_FINDINGS);

/** A deterministic mixed sequence: adds from three agents, snapshots, empty adds. */
function mixedActions(): LiveFindingsAction[] {
  const agents = ["cwe", "xss", "secrets"];
  const out: LiveFindingsAction[] = [];
  let seed = 7;
  const next = () => (seed = (seed * 1103515245 + 12345) % 2147483648);
  for (let i = 0; i < 400; i++) {
    const agent = agents[next() % agents.length];
    const r = next() % 10;
    if (r === 0) out.push({ kind: "replace", agent, findings: [row(agent, 10_000 + i)] });
    else if (r === 1) out.push({ kind: "add", agent, findings: [] });
    else out.push({ kind: "add", agent, findings: [row(agent, i), row(agent, i + 0.5)] });
  }
  return out;
}

describe("applyLiveActions", () => {
  it("equals the unbatched reducer, whatever the batch boundaries", () => {
    const actions = mixedActions();
    const want = sequential(actions);
    for (const size of [1, 3, 17, 64, actions.length]) {
      let state: LiveFindingsState = EMPTY_LIVE_FINDINGS;
      for (let i = 0; i < actions.length; i += size) {
        state = applyLiveActions(state, actions.slice(i, i + size));
      }
      expect(state, `batch size ${size}`).toEqual(want);
      expect(flattenLiveFindings(state)).toEqual(flattenLiveFindings(want));
    }
  });

  it("a snapshot in the middle of a batch replaces what came before it, and later adds append", () => {
    const state = applyLiveActions(EMPTY_LIVE_FINDINGS, [
      { kind: "add", agent: "cwe", findings: [row("cwe", 1)] },
      { kind: "replace", agent: "cwe", findings: [row("cwe", 2)] },
      { kind: "add", agent: "cwe", findings: [row("cwe", 3)] },
    ]);
    expect(state.cwe.map((f) => f.title)).toEqual(["cwe-2", "cwe-3"]);
  });

  it("never mutates the previous state or a snapshot's array", () => {
    const snap = [row("cwe", 1)];
    const before = applyLiveActions(EMPTY_LIVE_FINDINGS, [{ kind: "replace", agent: "cwe", findings: snap }]);
    const frozen = before.cwe;
    applyLiveActions(before, [{ kind: "add", agent: "cwe", findings: [row("cwe", 2)] }]);
    expect(frozen).toHaveLength(1);
    expect(snap).toHaveLength(1);
  });

  it("returns the same state for a batch that changes nothing", () => {
    const state = applyLiveActions(EMPTY_LIVE_FINDINGS, [{ kind: "add", agent: "cwe", findings: [row("cwe", 1)] }]);
    expect(applyLiveActions(state, [])).toBe(state);
    expect(applyLiveActions(state, [{ kind: "add", agent: "cwe", findings: [] }])).toBe(state);
  });
});

describe("createLiveBatcher", () => {
  function manualSchedule() {
    const pending: (() => void)[] = [];
    const schedule = vi.fn((cb: () => void) => {
      pending.push(cb);
      return () => {
        const i = pending.indexOf(cb);
        if (i >= 0) pending.splice(i, 1);
      };
    });
    const runFrame = () => pending.splice(0).forEach((cb) => cb());
    return { schedule, runFrame, pending };
  }

  it("N actions within one frame reach the reducer as ONE dispatch, in order", () => {
    const { schedule, runFrame } = manualSchedule();
    const dispatch = vi.fn<(actions: LiveFindingsAction[]) => void>();
    const b = createLiveBatcher(dispatch, schedule);
    const actions = mixedActions().slice(0, 250);
    for (const a of actions) b.push(a);
    expect(dispatch).not.toHaveBeenCalled();
    expect(schedule).toHaveBeenCalledTimes(1);
    runFrame();
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(dispatch.mock.calls[0][0]).toEqual(actions);
    expect(applyLiveActions(EMPTY_LIVE_FINDINGS, dispatch.mock.calls[0][0])).toEqual(sequential(actions));
  });

  it("schedules again for the next frame's actions", () => {
    const { schedule, runFrame } = manualSchedule();
    const dispatch = vi.fn();
    const b = createLiveBatcher(dispatch, schedule);
    b.push({ kind: "add", agent: "cwe", findings: [row("cwe", 1)] });
    runFrame();
    b.push({ kind: "add", agent: "cwe", findings: [row("cwe", 2)] });
    runFrame();
    expect(dispatch).toHaveBeenCalledTimes(2);
    expect(schedule).toHaveBeenCalledTimes(2);
  });

  it("flush() delivers the queue now and cancels the scheduled frame (terminal switch)", () => {
    const { schedule, runFrame, pending } = manualSchedule();
    const dispatch = vi.fn();
    const b = createLiveBatcher(dispatch, schedule);
    b.push({ kind: "add", agent: "cwe", findings: [row("cwe", 1)] });
    b.flush();
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(pending).toHaveLength(0);
    runFrame();
    b.flush();
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it("cancel() drops the queue without dispatching (unmount)", () => {
    const { schedule, runFrame } = manualSchedule();
    const dispatch = vi.fn();
    const b = createLiveBatcher(dispatch, schedule);
    b.push({ kind: "add", agent: "cwe", findings: [row("cwe", 1)] });
    b.cancel();
    runFrame();
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("the default schedule flushes within ~250 ms even with no animation frame (hidden tab)", () => {
    vi.useFakeTimers();
    const raf = vi.fn(() => 1);
    vi.stubGlobal("requestAnimationFrame", raf);
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
    try {
      const dispatch = vi.fn();
      const b = createLiveBatcher(dispatch);
      b.push({ kind: "add", agent: "cwe", findings: [row("cwe", 1)] });
      expect(raf).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(249);
      expect(dispatch).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1);
      expect(dispatch).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });
});
