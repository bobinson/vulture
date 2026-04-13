import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useLineage } from "./useLineage";

vi.mock("@/lib/api.ts", () => ({
  api: {
    getAuditLineage: vi.fn(),
    getLineageTimeline: vi.fn(),
    getProveResultsByFingerprint: vi.fn(),
    updateLineageStatus: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";

const mockGetAuditLineage = vi.mocked(api.getAuditLineage);
const mockGetLineageTimeline = vi.mocked(api.getLineageTimeline);
const mockGetProveResultsByFingerprint = vi.mocked(api.getProveResultsByFingerprint);

beforeEach(() => {
  vi.clearAllMocks();
  mockGetAuditLineage.mockResolvedValue([]);
});

describe("useLineage", () => {
  it("returns stable loadTimeline callback reference across re-renders", async () => {
    const { result, rerender } = renderHook(() => useLineage("audit-1"));

    await act(async () => {});

    const firstRef = result.current.loadTimeline;
    rerender();
    const secondRef = result.current.loadTimeline;

    expect(firstRef).toBe(secondRef);
  });

  it("returns stable loadProveHistory callback reference across re-renders", async () => {
    const { result, rerender } = renderHook(() => useLineage("audit-1"));

    await act(async () => {});

    const firstRef = result.current.loadProveHistory;
    rerender();
    const secondRef = result.current.loadProveHistory;

    expect(firstRef).toBe(secondRef);
  });

  it("loadTimeline fetches timeline and sets showTimeline", async () => {
    const events = [{ id: "e1", lineage_id: "l1", event_type: "detected" as const, created_at: "2026-01-01" }];
    mockGetLineageTimeline.mockResolvedValue(events);

    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    await act(async () => {
      result.current.loadTimeline("l1");
    });

    expect(mockGetLineageTimeline).toHaveBeenCalledWith("l1");
    expect(result.current.showTimeline).toBe("l1");
    expect(result.current.timelineMap.has("l1")).toBe(true);
  });

  it("loadTimeline toggles showTimeline when already cached", async () => {
    const events = [{ id: "e1", lineage_id: "l1", event_type: "detected" as const, created_at: "2026-01-01" }];
    mockGetLineageTimeline.mockResolvedValue(events);

    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    // First call: fetches and shows
    await act(async () => {
      result.current.loadTimeline("l1");
    });
    expect(result.current.showTimeline).toBe("l1");

    // Second call: toggles off (no additional fetch)
    act(() => {
      result.current.loadTimeline("l1");
    });
    expect(result.current.showTimeline).toBeNull();
    expect(mockGetLineageTimeline).toHaveBeenCalledTimes(1); // only one API call

    // Third call: toggles back on (still no additional fetch)
    act(() => {
      result.current.loadTimeline("l1");
    });
    expect(result.current.showTimeline).toBe("l1");
    expect(mockGetLineageTimeline).toHaveBeenCalledTimes(1); // still only one API call
  });

  it("loadTimeline remains stable even after timeline data changes state", async () => {
    const events = [{ id: "e1", lineage_id: "l1", event_type: "detected" as const, created_at: "2026-01-01" }];
    mockGetLineageTimeline.mockResolvedValue(events);

    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    const refBefore = result.current.loadTimeline;

    // Load a timeline which changes timelineMap state
    await act(async () => {
      result.current.loadTimeline("l1");
    });

    const refAfter = result.current.loadTimeline;
    expect(refBefore).toBe(refAfter);
  });

  it("loadProveHistory does not re-fetch already cached fingerprint", async () => {
    const results = [{ id: "p1", audit_id: "a1", finding_id: "f1", status: "verified" as const, evidence: "yes", iterations_used: 1, staging_url: "", created_at: "2026-01-01" }];
    mockGetProveResultsByFingerprint.mockResolvedValue(results);

    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    // First call: fetches
    await act(async () => {
      result.current.loadProveHistory("fp1");
    });
    expect(mockGetProveResultsByFingerprint).toHaveBeenCalledTimes(1);

    // Second call: should not fetch again
    await act(async () => {
      result.current.loadProveHistory("fp1");
    });
    expect(mockGetProveResultsByFingerprint).toHaveBeenCalledTimes(1);
  });

  it("loadProveHistory remains stable even after prove data changes state", async () => {
    const results = [{ id: "p1", audit_id: "a1", finding_id: "f1", status: "verified" as const, evidence: "yes", iterations_used: 1, staging_url: "", created_at: "2026-01-01" }];
    mockGetProveResultsByFingerprint.mockResolvedValue(results);

    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    const refBefore = result.current.loadProveHistory;

    await act(async () => {
      result.current.loadProveHistory("fp1");
    });

    const refAfter = result.current.loadProveHistory;
    expect(refBefore).toBe(refAfter);
  });
});
