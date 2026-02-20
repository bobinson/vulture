import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAudit } from "./useAudit";

vi.mock("@/lib/api.ts", () => ({
  api: {
    createAudit: vi.fn(),
    getAudit: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";

const mockCreateAudit = vi.mocked(api.createAudit);
const mockGetAudit = vi.mocked(api.getAudit);

beforeEach(() => {
  vi.useFakeTimers();
  mockCreateAudit.mockReset();
  mockGetAudit.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

const SAMPLE_AUDIT = {
  id: "audit-1",
  source_id: "src-1",
  status: "running" as const,
  types: ["chaos"],
  created_at: "2026-01-01T00:00:00Z",
};

describe("useAudit", () => {
  it("returns initial state with no auditId", () => {
    const { result } = renderHook(() => useAudit());
    expect(result.current.audit).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("creates audit successfully", async () => {
    mockCreateAudit.mockResolvedValue(SAMPLE_AUDIT);
    const { result } = renderHook(() => useAudit());

    let created: unknown;
    await act(async () => {
      created = await result.current.createAudit("src-1", ["chaos"]);
    });

    expect(created).toEqual(SAMPLE_AUDIT);
    expect(result.current.audit).toEqual(SAMPLE_AUDIT);
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("handles createAudit error", async () => {
    mockCreateAudit.mockRejectedValue(new Error("Network error"));
    const { result } = renderHook(() => useAudit());

    await act(async () => {
      await result.current.createAudit("src-1", ["chaos"]);
    });

    expect(result.current.audit).toBeNull();
    expect(result.current.error).toBe("Network error");
    expect(result.current.loading).toBe(false);
  });

  it("handles non-Error rejection in createAudit", async () => {
    mockCreateAudit.mockRejectedValue("string error");
    const { result } = renderHook(() => useAudit());

    await act(async () => {
      await result.current.createAudit("src-1", ["chaos"]);
    });

    expect(result.current.error).toBe("Failed to create audit");
  });

  it("fetches audit when auditId is provided", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    const { result } = renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });

    expect(result.current.audit).toEqual(SAMPLE_AUDIT);
    expect(mockGetAudit).toHaveBeenCalledWith("audit-1");
  });

  it("polls every 5 seconds", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    renderHook(() => useAudit("audit-1"));

    // Wait for initial fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(1);

    // Advance 5 seconds for poll
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(2);
  });

  it("stops polling when status is completed", async () => {
    const completedAudit = { ...SAMPLE_AUDIT, status: "completed" as const };
    mockGetAudit.mockResolvedValue(completedAudit);
    renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(1);

    // Additional polls should not fire after completed
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    // Should not have been called again because poll was cleared
    expect(mockGetAudit).toHaveBeenCalledTimes(1);
  });

  it("stops polling when status is failed", async () => {
    const failedAudit = { ...SAMPLE_AUDIT, status: "failed" as const };
    mockGetAudit.mockResolvedValue(failedAudit);
    renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(1);
  });

  it("handles fetchAudit error", async () => {
    mockGetAudit.mockRejectedValue(new Error("Not found"));
    const { result } = renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });

    expect(result.current.error).toBe("Not found");
    expect(result.current.audit).toBeNull();
  });

  it("cleans up interval on unmount", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    const { unmount } = renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });

    unmount();

    // Advancing time after unmount should not cause additional calls
    const callsBefore = mockGetAudit.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(callsBefore);
  });
});
