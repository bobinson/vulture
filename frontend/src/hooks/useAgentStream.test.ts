import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAgentStream } from "./useAgentStream";

vi.mock("@/lib/api.ts", () => ({
  api: {
    getStreamToken: vi.fn().mockResolvedValue("token-123"),
    getStreamUrl: vi.fn(
      (id: string, token: string) => `/api/audits/${id}/stream?stream_token=${token}`,
    ),
  },
}));

type SSEHandler = (event: MessageEvent) => void;

class MockEventSource {
  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  listeners: Record<string, SSEHandler[]> = {};
  closed = false;

  constructor(url: string) {
    this.url = url;
  }

  addEventListener(type: string, handler: SSEHandler) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(handler);
  }

  close() {
    this.closed = true;
  }

  emit(type: string, data: Record<string, unknown>) {
    const handlers = this.listeners[type] ?? [];
    const event = new MessageEvent(type, { data: JSON.stringify(data) });
    for (const h of handlers) h(event);
  }
}

let latestES: MockEventSource | null = null;

/** Wait for the async connect() to create the EventSource. */
async function waitForES(): Promise<MockEventSource> {
  await vi.waitFor(() => expect(latestES).not.toBeNull());
  return latestES!;
}

beforeEach(() => {
  latestES = null;
  vi.stubGlobal("EventSource", class extends MockEventSource {
    constructor(url: string) {
      super(url);
      // eslint-disable-next-line @typescript-eslint/no-this-alias
      latestES = this;
      // Auto-trigger onopen async
      setTimeout(() => latestES?.onopen?.(), 0);
    }
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useAgentStream", () => {
  it("does not connect when auditId is undefined", () => {
    renderHook(() => useAgentStream(undefined));
    expect(latestES).toBeNull();
  });

  it("does not connect when disabled", () => {
    renderHook(() => useAgentStream("audit-1", true));
    expect(latestES).toBeNull();
  });

  it("connects to SSE when auditId provided", async () => {
    renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    expect(es.url).toContain("/api/audits/audit-1/stream");
  });

  it("handles RunStarted event", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("RunStarted", { runId: "run-1" }));
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toContain("run-1");
    expect(result.current.lines[0].type).toBe("info");
  });

  it("handles StepStarted event and creates agent step", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("StepStarted", { stepName: "chaos" }));
    expect(result.current.steps.length).toBe(1);
    expect(result.current.steps[0].agent_id).toBe("chaos");
    expect(result.current.steps[0].status).toBe("running");
    expect(result.current.lines[0].text).toContain("chaos");
  });

  it("handles StepFinished event and updates agent step", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("StepStarted", { stepName: "chaos" }));
    act(() => es.emit("StepFinished", { stepName: "chaos" }));
    expect(result.current.steps[0].status).toBe("complete");
  });

  it("handles TextMessageContent event", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("TextMessageContent", { delta: "Scanning files..." }));
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toBe("Scanning files...");
    expect(result.current.lines[0].type).toBe("info");
  });

  it("ignores TextMessageContent without string delta", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("TextMessageContent", { delta: 42 }));
    expect(result.current.lines.length).toBe(0);
  });

  it("handles StateDelta with finding array", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() =>
      es.emit("StateDelta", {
        delta: [
          {
            op: "add",
            value: { severity: "critical", title: "SQL Injection", file_path: "/db.ts" },
          },
        ],
      }),
    );
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].type).toBe("finding");
    expect(result.current.lines[0].text).toContain("CRITICAL");
    expect(result.current.lines[0].text).toContain("SQL Injection");
  });

  it("handles StateDelta with progress object", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() =>
      es.emit("StateDelta", {
        delta: { files_analyzed: 10, total_files: 50, findings_count: 3 },
      }),
    );
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].type).toBe("progress");
    expect(result.current.lines[0].text).toContain("10/50");
  });

  it("handles StateSnapshot event", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("StateSnapshot", {}));
    expect(result.current.lines[0].text).toBe("Results snapshot received");
  });

  it("handles RunFinished event and sets done", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    expect(result.current.done).toBe(false);
    act(() => es.emit("RunFinished", {}));
    expect(result.current.done).toBe(true);
    expect(es.closed).toBe(true);
  });

  it("handles RunError event and sets done", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("RunError", { error: "Agent crashed" }));
    expect(result.current.done).toBe(true);
    expect(result.current.lines[0].text).toContain("Agent crashed");
    expect(result.current.lines[0].type).toBe("error");
  });

  it("closes EventSource on unmount", async () => {
    const { unmount } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    expect(es.closed).toBe(false);
    unmount();
    expect(es.closed).toBe(true);
  });

  it("handles malformed SSE data gracefully", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    const handlers = es.listeners["TextMessageContent"] ?? [];
    act(() => {
      for (const h of handlers) {
        h(new MessageEvent("TextMessageContent", { data: "not json" }));
      }
    });
    // Should add the raw string as info line
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toBe("not json");
  });

  it("creates new step entry for unknown agent", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() => es.emit("StepStarted", { stepName: "owasp" }));
    act(() => es.emit("StepStarted", { stepName: "soc2" }));
    expect(result.current.steps.length).toBe(2);
    expect(result.current.steps[0].agent_id).toBe("owasp");
    expect(result.current.steps[1].agent_id).toBe("soc2");
  });

  it("handles StateDelta with token_savings data", async () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const es = await waitForES();
    act(() =>
      es.emit("StateDelta", {
        delta: {
          token_savings: {
            context_tokens: 50,
            raw_tokens: 150,
            tokens_saved: 100,
            savings_pct: 67,
            prior_findings_used: 5,
            duplicates_removed: 10,
          },
        },
      }),
    );
    expect(result.current.tokenSavings).not.toBeNull();
    expect(result.current.tokenSavings!.tokens_saved).toBe(100);
    expect(result.current.tokenSavings!.savings_pct).toBe(67);
    expect(result.current.tokenSavings!.prior_findings_used).toBe(5);
    expect(result.current.tokenSavings!.duplicates_removed).toBe(10);
    // Also adds info line about savings
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toContain("100 tokens saved");
  });

  it("returns null tokenSavings initially", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    expect(result.current.tokenSavings).toBeNull();
  });

  describe("live findings (0096 R15)", () => {
    const cred = { severity: "HIGH", category: "CWE-798", title: "Hardcoded credential", file_path: "src/a.ts" };
    const redos = { severity: "medium", category: "CWE-1333", title: "Regex backtracking", file_path: "src/b.ts" };
    const add = (value: unknown) => ({ op: "add", path: "/findings/-", value });

    // 0096 M9: live rows are applied once per animation frame. A manual frame
    // queue lets each test say when the frame runs.
    let frames: FrameRequestCallback[] = [];
    const runFrame = () => act(() => frames.splice(0).forEach((cb) => cb(performance.now())));
    beforeEach(() => {
      frames = [];
      vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => frames.push(cb));
      vi.stubGlobal("cancelAnimationFrame", (id: number) => { frames[id - 1] = () => {}; });
    });

    it("is empty until a finding arrives", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      await waitForES();
      expect(result.current.liveFindings).toEqual([]);
    });

    it("holds each streamed finding as a row, attributed to the agent the backend names", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateDelta", { agentType: "cwe", delta: [add(cred)] }));
      act(() => es.emit("StateDelta", { agentType: "cwe", delta: [add(redos)] }));
      runFrame();
      expect(result.current.liveFindings).toHaveLength(2);
      expect(result.current.liveFindings[0]).toMatchObject({
        agent_type: "cwe",
        severity: "high",
        category: "CWE-798",
        title: "Hardcoded credential",
        file_path: "src/a.ts",
        description: "",
        recommendation: "",
      });
    });

    it("never takes labels from an agent's payload — only a mapping labels a row", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      const forged = { ...cred, agent_type: "owasp", compliance_labels: [{ framework: "owasp", category_id: "A01" }] };
      act(() => es.emit("StateDelta", { agentType: "cwe", delta: [add(forged)] }));
      runFrame();
      expect(result.current.liveFindings[0].agent_type).toBe("cwe");
      expect(result.current.liveFindings[0].compliance_labels).toBeUndefined();
    });

    it("drops a value that is not a finding", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() =>
        es.emit("StateDelta", { agentType: "cwe", delta: [add("nope"), add({ severity: "high" }), add([cred])] }),
      );
      runFrame();
      expect(result.current.liveFindings).toEqual([]);
    });

    it("replaces an agent's streamed rows with the finished set on its result snapshot", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateDelta", { agentType: "cwe", delta: [add(cred), add(redos)] }));
      act(() => es.emit("StateDelta", { agentType: "xss", delta: [add({ ...cred, category: "CWE-79", title: "XSS" })] }));
      act(() => es.emit("StateSnapshot", { agentType: "cwe", snapshot: { findings: [{ ...cred, id: "f-1" }], score: 70 } }));
      runFrame();
      const titles = result.current.liveFindings.map((f) => f.title).sort();
      expect(titles).toEqual(["Hardcoded credential", "XSS"]);
      expect(result.current.liveFindings.find((f) => f.agent_type === "cwe")?.id).toBe("f-1");
    });

    it("N deltas within one frame cause a single state update, equal to the unbatched result", async () => {
      let renders = 0;
      const { result } = renderHook(() => {
        renders++;
        return useAgentStream("audit-1");
      });
      const es = await waitForES();
      await vi.waitFor(() => expect(result.current.connected).toBe(true));
      const before = result.current.liveFindings;
      const N = 200;
      act(() => {
        for (let i = 0; i < N; i++) {
          es.emit("StateDelta", { agentType: i % 2 ? "cwe" : "xss", delta: [add({ ...cred, title: `t-${i}` })] });
        }
      });
      // Nothing applied before the frame: the deltas are queued, not rendered.
      expect(result.current.liveFindings).toBe(before);
      const rendersBefore = renders;
      const liveBefore = result.current.liveFindings;
      runFrame();
      expect(renders - rendersBefore).toBe(1);
      expect(result.current.liveFindings).not.toBe(liveBefore);
      // Same rows, same per-agent order, as one reducer step per delta.
      const got = result.current.liveFindings;
      expect(got).toHaveLength(N);
      const byAgent = (agent: string) => got.filter((f) => f.agent_type === agent).map((f) => f.title);
      expect(byAgent("xss")).toEqual(Array.from({ length: N / 2 }, (_, k) => `t-${2 * k}`));
      expect(byAgent("cwe")).toEqual(Array.from({ length: N / 2 }, (_, k) => `t-${2 * k + 1}`));
    });

    it("RunFinished flushes queued rows at once, without waiting for the frame", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => {
        es.emit("StateDelta", { agentType: "cwe", delta: [add(cred)] });
        es.emit("RunFinished", {});
      });
      expect(result.current.done).toBe(true);
      expect(result.current.liveFindings).toHaveLength(1);
    });

    it("keeps an agent's streamed rows when its snapshot carries no findings array", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateDelta", { agentType: "cwe", delta: [add(cred)] }));
      act(() => es.emit("StateSnapshot", { agentType: "cwe", snapshot: { score: 70 } }));
      runFrame();
      expect(result.current.liveFindings).toHaveLength(1);
    });
  });

  describe("OWASP mapping (0096)", () => {
    const mapping = {
      version: 1,
      framework: "owasp",
      edition: "2025",
      selected: [],
      table: { "CWE-798": [{ id: "A07", name: "Authentication Failures" }] },
    };

    it("is null until a result snapshot carries one", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      await waitForES();
      expect(result.current.owaspMapping).toBeNull();
    });

    it("takes the mapping from the owasp agent's result snapshot", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateSnapshot", { agentType: "owasp", snapshot: { findings: [], mapping } }));
      expect(result.current.owaspMapping).toEqual(mapping);
    });

    it("ignores a mapping carried by any other agent's snapshot", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateSnapshot", { agentType: "cwe", snapshot: { findings: [], mapping } }));
      act(() => es.emit("StateSnapshot", { snapshot: { findings: [], mapping } }));
      expect(result.current.owaspMapping).toBeNull();
    });

    it("accepts owasp_coverage only from the owasp agent's snapshot, like the mapping", async () => {
      const coverage = { edition: "2025", cwe_stage_status: "completed", categories: [] };
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() => es.emit("StateSnapshot", { agentType: "cwe", snapshot: { findings: [], owasp_coverage: coverage } }));
      act(() => es.emit("StateSnapshot", { snapshot: { findings: [], owasp_coverage: coverage } }));
      expect(result.current.owaspCoverage).toBeNull();
      act(() => es.emit("StateSnapshot", { agentType: "owasp", snapshot: { findings: [], owasp_coverage: coverage } }));
      expect(result.current.owaspCoverage).toEqual(coverage);
    });

    it("drops an invalid mapping", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      const es = await waitForES();
      act(() =>
        es.emit("StateSnapshot", { agentType: "owasp", snapshot: { mapping: { ...mapping, version: 9 } } }),
      );
      expect(result.current.owaspMapping).toBeNull();
    });
  });
});
