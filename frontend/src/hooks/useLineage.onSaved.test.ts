import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useLineage } from "./useLineage";
import type { FindingLineage } from "@/lib/types.ts";

// 0096 follow-up: a triage saved in the findings table changes what the
// backend serves as the audit's OWASP coverage (triaged false positives are
// left out at read time), so the page needs to know a save landed in order to
// re-fetch the audit. useLineage reports it through `onStatusSaved`.

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
const mockUpdateLineageStatus = vi.mocked(api.updateLineageStatus);

const ROW = {
  id: "l1", fingerprint: "fp1", source_path: "/w", agent_type: "cwe", current_status: "open",
  first_audit_id: "a0", first_found_at: "2026-01-01", severity: "high", category: "CWE-798",
  title: "t", file_path: "f", created_at: "2026-01-01", updated_at: "2026-01-01",
} as FindingLineage;

beforeEach(() => {
  vi.clearAllMocks();
  mockGetAuditLineage.mockResolvedValue([ROW]);
});

async function saveAs(result: { current: ReturnType<typeof useLineage> }, status: string) {
  act(() => result.current.updateEdit("l1", { status }));
  await act(async () => {
    result.current.saveStatus("l1");
  });
}

describe("useLineage onStatusSaved", () => {
  it("is called once the status save succeeds, with the updated row", async () => {
    const updated = { ...ROW, current_status: "false_positive" } as FindingLineage;
    mockUpdateLineageStatus.mockResolvedValue(updated);
    const onStatusSaved = vi.fn();
    const { result } = renderHook(() => useLineage("audit-1", { onStatusSaved }));
    await act(async () => {});

    await saveAs(result, "false_positive");

    expect(mockUpdateLineageStatus).toHaveBeenCalledWith("l1", "false_positive", undefined, undefined);
    expect(onStatusSaved).toHaveBeenCalledTimes(1);
    expect(onStatusSaved).toHaveBeenCalledWith(updated);
    expect(result.current.lineageRows[0].current_status).toBe("false_positive");
  });

  it("is not called when the save fails", async () => {
    mockUpdateLineageStatus.mockRejectedValue(new Error("boom"));
    const onStatusSaved = vi.fn();
    const { result } = renderHook(() => useLineage("audit-1", { onStatusSaved }));
    await act(async () => {});

    await saveAs(result, "false_positive");

    expect(onStatusSaved).not.toHaveBeenCalled();
    expect(result.current.error).toBe("boom");
  });

  it("calls the latest callback without changing saveStatus's identity", async () => {
    mockUpdateLineageStatus.mockResolvedValue({ ...ROW, current_status: "false_positive" } as FindingLineage);
    const first = vi.fn();
    const second = vi.fn();
    const { result, rerender } = renderHook(
      ({ cb }: { cb: () => void }) => useLineage("audit-1", { onStatusSaved: cb }),
      { initialProps: { cb: first } },
    );
    await act(async () => {});
    const before = result.current.saveStatus;

    rerender({ cb: second });
    expect(result.current.saveStatus).toBe(before);

    await saveAs(result, "false_positive");
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });

  it("still saves without a callback", async () => {
    mockUpdateLineageStatus.mockResolvedValue({ ...ROW, current_status: "accepted_risk" } as FindingLineage);
    const { result } = renderHook(() => useLineage("audit-1"));
    await act(async () => {});

    await saveAs(result, "accepted_risk");

    expect(result.current.lineageRows[0].current_status).toBe("accepted_risk");
    expect(result.current.savedFeedback).toBe("l1");
  });
});
