import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAudit } from "./useAudit";
import type { Audit } from "@/lib/types.ts";

// 0096 follow-up: the results page re-fetches the audit after every triage
// save, so two reads can be in flight at once. The coverage card must show
// the LATEST read's manifest: a slower, earlier response must not overwrite
// the state a later one already set.

vi.mock("@/lib/api.ts", () => ({
  api: { createAudit: vi.fn(), getAudit: vi.fn() },
}));

import { api } from "@/lib/api.ts";

const mockGetAudit = vi.mocked(api.getAudit);

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

const audit = (found: number) =>
  ({ id: "a1", source_id: "s", status: "completed", types: ["owasp"], created_at: "x", findings: [], owasp_coverage: { found } }) as unknown as Audit;

beforeEach(() => mockGetAudit.mockReset());

describe("useAudit fetchAudit ordering", () => {
  it("keeps the latest read when an earlier one resolves after it", async () => {
    const first = deferred<Audit>();
    const second = deferred<Audit>();
    mockGetAudit.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => useAudit());

    let p1: Promise<unknown>, p2: Promise<unknown>;
    act(() => {
      p1 = result.current.fetchAudit("a1");
      p2 = result.current.fetchAudit("a1");
    });
    await act(async () => {
      second.resolve(audit(0));
      await p2;
    });
    await act(async () => {
      first.resolve(audit(1));
      await p1;
    });

    expect((result.current.audit as unknown as { owasp_coverage: { found: number } }).owasp_coverage.found).toBe(0);
  });

  it("still returns each read's own result to its caller", async () => {
    mockGetAudit.mockResolvedValueOnce(audit(1));
    const { result } = renderHook(() => useAudit());
    let got: Audit | null = null;
    await act(async () => {
      got = await result.current.fetchAudit("a1");
    });
    expect(got).toEqual(audit(1));
    expect(result.current.audit).toEqual(audit(1));
  });
});
