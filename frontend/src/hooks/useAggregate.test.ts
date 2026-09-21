import { describe, expect, it, beforeEach, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useAggregate } from "./useAggregate";
import type { AggregateFilters } from "@/lib/types";

// Feature 0091 P5 (RED) — LLD §10.1 query contract for
//   GET /api/targets/{key}/aggregate
//     ?scans=a,b&status=active|all&tier=det|llm&min_seen=k
//     &severity=critical,high&page=1&page_size=50
//
// The real api client builds the URL, so `fetch` is stubbed rather than the
// api module: this test pins the wire format, not an internal call shape.

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

const TARGET_KEY = "path:/home/user/danger/blu-simulator";
const TARGET_KEY_ENC = encodeURIComponent(TARGET_KEY);
const AGG_PATH = `/api/targets/${TARGET_KEY_ENC}/aggregate`;

const RESPONSE = {
  total: 40,
  page: 1,
  page_size: 50,
  tiles: { unique: 40, active: 34, unconfirmed: 1, fixed: 5, critical: 9 },
  rows: [
    {
      lineage_id: "l-92190",
      ref: "VLT-92190",
      severity: "critical",
      category: "CWE-506",
      title: "VS Code task runs on folderOpen",
      rel_path: ".vscode/tasks.json",
      line_start: 7,
      tier: "llm",
      seen_count: 2,
      scan_count: 5,
      status: "open",
      first_seen_at: "2026-09-09T10:03:00Z",
      last_seen_at: "2026-09-09T10:39:00Z",
      last_event: "confirmed_by_evidence",
    },
  ],
};

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockImplementation(() => jsonResponse(RESPONSE));
});

function requestedUrls(): string[] {
  return mockFetch.mock.calls.map((call) => String(call[0]));
}

function lastQuery(): URLSearchParams {
  const url = requestedUrls().at(-1) ?? "";
  return new URL(url, "http://localhost").searchParams;
}

describe("useAggregate — query serialisation", () => {
  it("requests the aggregate of the URL-encoded target key", async () => {
    const { result } = renderHook(() => useAggregate(TARGET_KEY, {}));
    await waitFor(() => expect(result.current.loading).toBe(false));

    const url = requestedUrls()[0];
    expect(url.startsWith(AGG_PATH)).toBe(true);
  });

  it("sends no filter params at all when no filter is set", async () => {
    const { result } = renderHook(() => useAggregate(TARGET_KEY, {}));
    await waitFor(() => expect(result.current.loading).toBe(false));

    // "omit = all scans", "omit = both tiers", "default active" are all
    // server-side defaults; the client must not invent them.
    expect(requestedUrls()[0]).toBe(AGG_PATH);
  });

  it("serialises every filter under the contract's parameter names", async () => {
    const filters: AggregateFilters = {
      scans: ["2281d2a2", "b94cfa15"],
      status: "all",
      tier: "llm",
      min_seen: 2,
      severity: ["critical", "high"],
      page: 3,
      page_size: 25,
    };
    const { result } = renderHook(() => useAggregate(TARGET_KEY, filters));
    await waitFor(() => expect(result.current.loading).toBe(false));

    const q = lastQuery();
    expect(q.get("scans")).toBe("2281d2a2,b94cfa15");
    expect(q.get("status")).toBe("all");
    expect(q.get("tier")).toBe("llm");
    expect(q.get("min_seen")).toBe("2");
    expect(q.get("severity")).toBe("critical,high");
    expect(q.get("page")).toBe("3");
    expect(q.get("page_size")).toBe("25");

    // …and nothing the contract does not name.
    expect([...q.keys()].sort()).toEqual(
      ["min_seen", "page", "page_size", "scans", "severity", "status", "tier"],
    );
  });

  it("comma-joins multi-valued filters rather than repeating the parameter", async () => {
    const { result } = renderHook(() =>
      useAggregate(TARGET_KEY, { severity: ["critical", "high", "medium"] }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(lastQuery().getAll("severity")).toEqual(["critical,high,medium"]);
  });

  it("sends status=active explicitly when the caller asks for it", async () => {
    const { result } = renderHook(() => useAggregate(TARGET_KEY, { status: "active" }));
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(lastQuery().get("status")).toBe("active");
  });

  it("drops an empty scans or severity list instead of sending an empty value", async () => {
    const { result } = renderHook(() =>
      useAggregate(TARGET_KEY, { scans: [], severity: [], status: "active" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    const q = lastQuery();
    expect(q.has("scans")).toBe(false);
    expect(q.has("severity")).toBe(false);
    expect(q.get("status")).toBe("active");
  });

  it("exposes the parsed aggregate payload", async () => {
    const { result } = renderHook(() => useAggregate(TARGET_KEY, {}));
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.error).toBeNull();
    expect(result.current.data?.total).toBe(40);
    expect(result.current.data?.tiles.unconfirmed).toBe(1);
    expect(result.current.data?.rows).toHaveLength(1);
    expect(result.current.data?.rows[0].ref).toBe("VLT-92190");
  });
});

describe("useAggregate — refetch scope", () => {
  it("changing a filter refetches only the aggregate, never the target list or its scans", async () => {
    const { result, rerender } = renderHook(
      ({ filters }: { filters: AggregateFilters }) => useAggregate(TARGET_KEY, filters),
      { initialProps: { filters: { status: "active" } as AggregateFilters } },
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(mockFetch).toHaveBeenCalledTimes(1);

    rerender({ filters: { status: "all" } });
    await waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(2));

    // Both calls are the aggregate; the target list and the scan list are
    // owned by other hooks and must not be re-pulled by a filter change.
    for (const url of requestedUrls()) {
      expect(url.startsWith(AGG_PATH)).toBe(true);
    }
    expect(requestedUrls().some((u) => u === "/api/targets")).toBe(false);
    expect(requestedUrls().some((u) => u.includes("/scans"))).toBe(false);
    expect(lastQuery().get("status")).toBe("all");
  });

  it("re-rendering with an equal filter object does not refetch", async () => {
    const { result, rerender } = renderHook(
      ({ filters }: { filters: AggregateFilters }) => useAggregate(TARGET_KEY, filters),
      { initialProps: { filters: { status: "active", severity: ["critical"] } as AggregateFilters } },
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // A fresh object with identical values — the common React parent-render
    // case. Depending on object identity here would refetch on every render.
    rerender({ filters: { status: "active", severity: ["critical"] } });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("surfaces an error without clearing the target key", async () => {
    mockFetch.mockImplementation(() => jsonResponse({ error: "boom" }, 500));
    const { result } = renderHook(() => useAggregate(TARGET_KEY, {}));
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.error).not.toBeNull();
    expect(result.current.data).toBeNull();
  });
});
