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

  it("uses exponential backoff starting at 2s", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    renderHook(() => useAudit("audit-1"));

    // Initial fetch fires immediately
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(1);

    // First retry at 2s (initial delay * 1.5 = 3s for next)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(2);

    // Second retry at 3s (2000 * 1.5)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(3);
  });

  it("caps backoff delay at 10s", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    renderHook(() => useAudit("audit-1"));

    // Initial fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(1);

    // Run through enough iterations to exceed 10s cap:
    // delays: 2s, 3s, 4.5s, 6.75s, 10s (capped), 10s...
    let total = 0;
    const delays = [2000, 3000, 4500, 6750, 10000];
    for (let i = 0; i < delays.length; i++) {
      total += delays[i];
      await act(async () => {
        await vi.advanceTimersByTimeAsync(delays[i]);
      });
      expect(mockGetAudit).toHaveBeenCalledTimes(i + 2);
    }

    // Next should also be 10s (capped)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(delays.length + 2);
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

  it("cleans up timeout on unmount", async () => {
    mockGetAudit.mockResolvedValue(SAMPLE_AUDIT);
    const { unmount } = renderHook(() => useAudit("audit-1"));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });

    unmount();

    // Advancing time after unmount should not cause additional calls
    const callsBefore = mockGetAudit.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20000);
    });
    expect(mockGetAudit).toHaveBeenCalledTimes(callsBefore);
  });
});
