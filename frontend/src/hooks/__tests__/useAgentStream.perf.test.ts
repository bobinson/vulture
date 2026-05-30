import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAgentStream } from "../useAgentStream";

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

  removeEventListener(type: string, handler: SSEHandler) {
    const arr = this.listeners[type];
    if (!arr) return;
    this.listeners[type] = arr.filter((h) => h !== handler);
  }

  close() {
    this.closed = true;
  }

  emit(type: string, data: Record<string, unknown>) {
    const handlers = this.listeners[type] ?? [];
    const event = new MessageEvent(type, { data: JSON.stringify(data) });
    for (const h of handlers) h(event);
  }

  listenerCount(type: string): number {
    return (this.listeners[type] ?? []).length;
  }

  totalListenerCount(): number {
    let count = 0;
    for (const handlers of Object.values(this.listeners)) {
      count += handlers.length;
    }
    return count;
  }
}

let latestES: MockEventSource | null = null;
let esInstances: MockEventSource[] = [];

beforeEach(() => {
  latestES = null;
  esInstances = [];
  vi.stubGlobal(
    "EventSource",
    class extends MockEventSource {
      constructor(url: string) {
        super(url);
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        latestES = this;
        esInstances.push(this);
        setTimeout(() => this.onopen?.(), 0);
      }
    },
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useAgentStream performance fixes", () => {
  // Issue #9: Lines array must be capped at 500
  describe("lines array cap (Issue #9)", () => {
    it("caps lines at 500 entries", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      await vi.waitFor(() => expect(latestES).not.toBeNull());

      // Emit 600 events
      act(() => {
        for (let i = 0; i < 600; i++) {
          latestES!.emit("TextMessageContent", { delta: `line-${i}` });
        }
      });

      expect(result.current.lines.length).toBeLessThanOrEqual(500);
    });

    it("preserves newest lines when capped", async () => {
      const { result } = renderHook(() => useAgentStream("audit-1"));
      await vi.waitFor(() => expect(latestES).not.toBeNull());

      act(() => {
        for (let i = 0; i < 600; i++) {
          latestES!.emit("TextMessageContent", { delta: `line-${i}` });
        }
      });

      // The last line should be the most recently added
      const lastLine = result.current.lines[result.current.lines.length - 1];
      expect(lastLine.text).toBe("line-599");
    });
  });

  // Issues #1, #2, #10: Effect should only depend on [auditId, disabled]
  describe("effect dependency stability (Issues #1, #2, #10)", () => {
    it("does not create multiple EventSource instances on re-render", async () => {
      const { rerender } = renderHook(
        ({ auditId }) => useAgentStream(auditId),
        { initialProps: { auditId: "audit-1" as string | undefined } },
      );
      await vi.waitFor(() => expect(latestES).not.toBeNull());

      // Force re-renders without changing auditId
      rerender({ auditId: "audit-1" });
      rerender({ auditId: "audit-1" });
      rerender({ auditId: "audit-1" });

      // Wait a tick to ensure no async reconnections
      await vi.waitFor(() => {
        // Only one EventSource should have been created
        expect(esInstances.length).toBe(1);
      });
    });

    it("closes old EventSource when auditId changes", async () => {
      const { rerender } = renderHook(
        ({ auditId }) => useAgentStream(auditId),
        { initialProps: { auditId: "audit-1" as string | undefined } },
      );
      await vi.waitFor(() => expect(latestES).not.toBeNull());
      const firstES = latestES!;

      rerender({ auditId: "audit-2" });
      await vi.waitFor(() => expect(esInstances.length).toBe(2));

      expect(firstES.closed).toBe(true);
    });

    it("does not leak listeners across re-renders", async () => {
      renderHook(() => useAgentStream("audit-1"));
      await vi.waitFor(() => expect(latestES).not.toBeNull());

      // Emit events to trigger state updates (which used to cause re-renders
      // that re-ran the effect and added duplicate listeners)
      act(() => {
        latestES!.emit("TextMessageContent", { delta: "msg-1" });
        latestES!.emit("TextMessageContent", { delta: "msg-2" });
      });

      // Each event type should have exactly 1 listener
      expect(latestES!.listenerCount("TextMessageContent")).toBe(1);
      expect(latestES!.listenerCount("RunStarted")).toBe(1);
      expect(latestES!.listenerCount("RunFinished")).toBe(1);
    });
  });

  // Cleanup test
  describe("cleanup", () => {
    it("closes EventSource on unmount", async () => {
      const { unmount } = renderHook(() => useAgentStream("audit-1"));
      await vi.waitFor(() => expect(latestES).not.toBeNull());
      const es = latestES!;

      expect(es.closed).toBe(false);
      unmount();
      expect(es.closed).toBe(true);
    });

    it("sets cancelled flag to prevent late connections", async () => {
      const { unmount } = renderHook(() => useAgentStream("audit-1"));
      // Unmount immediately before async connect completes
      unmount();
      // Should not throw or create an EventSource after unmount
      // (The cancelled flag prevents it)
      await vi.waitFor(() => {
        // If an ES was created and then cleaned up, it should be closed
        if (latestES) {
          expect(latestES.closed).toBe(true);
        }
      });
    });
  });
});
