import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAgentStream } from "./useAgentStream";

vi.mock("@/lib/api.ts", () => ({
  api: {
    getStreamUrl: vi.fn((id: string) => `/api/audits/${id}/stream`),
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

  it("connects to SSE when auditId provided", () => {
    renderHook(() => useAgentStream("audit-1"));
    expect(latestES).not.toBeNull();
    expect(latestES!.url).toBe("/api/audits/audit-1/stream");
  });

  it("handles RunStarted event", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("RunStarted", { runId: "run-1" }));
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toContain("run-1");
    expect(result.current.lines[0].type).toBe("info");
  });

  it("handles StepStarted event and creates agent step", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("StepStarted", { stepName: "chaos" }));
    expect(result.current.steps.length).toBe(1);
    expect(result.current.steps[0].agent_id).toBe("chaos");
    expect(result.current.steps[0].status).toBe("running");
    expect(result.current.lines[0].text).toContain("chaos");
  });

  it("handles StepFinished event and updates agent step", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("StepStarted", { stepName: "chaos" }));
    act(() => latestES!.emit("StepFinished", { stepName: "chaos" }));
    expect(result.current.steps[0].status).toBe("complete");
  });

  it("handles TextMessageContent event", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("TextMessageContent", { delta: "Scanning files..." }));
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toBe("Scanning files...");
    expect(result.current.lines[0].type).toBe("info");
  });

  it("ignores TextMessageContent without string delta", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("TextMessageContent", { delta: 42 }));
    expect(result.current.lines.length).toBe(0);
  });

  it("handles StateDelta with finding array", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() =>
      latestES!.emit("StateDelta", {
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

  it("handles StateDelta with progress object", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() =>
      latestES!.emit("StateDelta", {
        delta: { files_analyzed: 10, total_files: 50, findings_count: 3 },
      }),
    );
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].type).toBe("progress");
    expect(result.current.lines[0].text).toContain("10/50");
  });

  it("handles StateSnapshot event", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("StateSnapshot", {}));
    expect(result.current.lines[0].text).toBe("Results snapshot received");
  });

  it("handles RunFinished event and sets done", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    expect(result.current.done).toBe(false);
    act(() => latestES!.emit("RunFinished", {}));
    expect(result.current.done).toBe(true);
    expect(latestES!.closed).toBe(true);
  });

  it("handles RunError event and sets done", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("RunError", { error: "Agent crashed" }));
    expect(result.current.done).toBe(true);
    expect(result.current.lines[0].text).toContain("Agent crashed");
    expect(result.current.lines[0].type).toBe("error");
  });

  it("closes EventSource on unmount", () => {
    const { unmount } = renderHook(() => useAgentStream("audit-1"));
    const es = latestES!;
    expect(es.closed).toBe(false);
    unmount();
    expect(es.closed).toBe(true);
  });

  it("handles malformed SSE data gracefully", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    const handlers = latestES!.listeners["TextMessageContent"] ?? [];
    act(() => {
      for (const h of handlers) {
        h(new MessageEvent("TextMessageContent", { data: "not json" }));
      }
    });
    // Should add the raw string as info line
    expect(result.current.lines.length).toBe(1);
    expect(result.current.lines[0].text).toBe("not json");
  });

  it("creates new step entry for unknown agent", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() => latestES!.emit("StepStarted", { stepName: "owasp" }));
    act(() => latestES!.emit("StepStarted", { stepName: "soc2" }));
    expect(result.current.steps.length).toBe(2);
    expect(result.current.steps[0].agent_id).toBe("owasp");
    expect(result.current.steps[1].agent_id).toBe("soc2");
  });

  it("handles StateDelta with token_savings data", () => {
    const { result } = renderHook(() => useAgentStream("audit-1"));
    act(() =>
      latestES!.emit("StateDelta", {
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
});
