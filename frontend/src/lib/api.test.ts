import { describe, expect, it, vi, beforeEach } from "vitest";
import { api, ApiError } from "./api";

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
  localStorage.clear();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

describe("api.getStats", () => {
  it("fetches dashboard stats", async () => {
    const stats = { audits_run: 5, total_findings: 20, critical_issues: 2, average_score: 75 };
    mockFetch.mockReturnValueOnce(jsonResponse(stats));

    const result = await api.getStats();
    expect(result).toEqual(stats);
    expect(mockFetch).toHaveBeenCalledWith(
      "/api/stats",
      expect.objectContaining({ headers: expect.objectContaining({ "Content-Type": "application/json" }) }),
    );
  });
});

describe("api.listAudits", () => {
  it("passes limit and offset", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse([]));
    await api.listAudits(10, 5);
    expect(mockFetch).toHaveBeenCalledWith(
      "/api/audits?limit=10&offset=5",
      expect.any(Object),
    );
  });
});

describe("api.searchMemories", () => {
  it("encodes query parameter", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse([]));
    await api.searchMemories("retry pattern", 10);
    expect(mockFetch).toHaveBeenCalledWith(
      "/api/memories/search?q=retry%20pattern&limit=10",
      expect.any(Object),
    );
  });
});

describe("api.updateRemediation", () => {
  it("sends PATCH with status and notes", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: "updated" }));
    await api.updateRemediation("mem-1", "resolved", "Fixed in PR #42");
    expect(mockFetch).toHaveBeenCalledWith(
      "/api/memories/mem-1",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ status: "resolved", notes: "Fixed in PR #42" }),
      }),
    );
  });
});

describe("auth headers", () => {
  it("includes Bearer token when present", async () => {
    localStorage.setItem("vulture_token", "test-jwt");
    mockFetch.mockReturnValueOnce(jsonResponse([]));
    await api.listAudits();
    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer test-jwt" }),
      }),
    );
  });
});

describe("error handling", () => {
  it("throws ApiError on non-ok response", async () => {
    mockFetch.mockReturnValueOnce(
      Promise.resolve({
        ok: false,
        status: 404,
        text: () => Promise.resolve("not found"),
      }),
    );
    await expect(api.getStats()).rejects.toThrow(ApiError);
  });
});

describe("request deduplication", () => {
  it("deduplicates concurrent GET requests to the same endpoint", async () => {
    let resolveResponse: (value: unknown) => void;
    const responsePromise = new Promise((resolve) => {
      resolveResponse = resolve;
    });
    mockFetch.mockReturnValue(
      responsePromise.then((data) => ({
        ok: true,
        status: 200,
        json: () => Promise.resolve(data),
        text: () => Promise.resolve(JSON.stringify(data)),
      })),
    );

    // Fire two concurrent requests to the same endpoint
    const p1 = api.getAudit("audit-1");
    const p2 = api.getAudit("audit-1");

    // fetch should only be called once
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Resolve and verify both get the same result
    resolveResponse!({ id: "audit-1", status: "running" });
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toEqual(r2);
  });

  it("does not deduplicate POST requests", async () => {
    mockFetch
      .mockReturnValueOnce(jsonResponse({ id: "a1" }))
      .mockReturnValueOnce(jsonResponse({ id: "a2" }));

    const p1 = api.createAudit({ source_id: "s1", types: ["owasp"] });
    const p2 = api.createAudit({ source_id: "s1", types: ["owasp"] });

    await Promise.all([p1, p2]);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("allows new GET after previous one completes", async () => {
    mockFetch
      .mockReturnValueOnce(jsonResponse({ id: "audit-1", status: "running" }))
      .mockReturnValueOnce(jsonResponse({ id: "audit-1", status: "completed" }));

    // First request
    await api.getAudit("audit-1");
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second request after first completed - should make a new fetch
    await api.getAudit("audit-1");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("clears in-flight cache when request fails", async () => {
    mockFetch.mockReturnValueOnce(
      Promise.resolve({
        ok: false,
        status: 500,
        text: () => Promise.resolve("server error"),
      }),
    );

    // First request fails
    await api.getAudit("audit-1").catch(() => {});

    // Retry should make a new fetch, not return cached error
    mockFetch.mockReturnValueOnce(jsonResponse({ id: "audit-1", status: "running" }));
    const result = await api.getAudit("audit-1");
    expect(result).toEqual({ id: "audit-1", status: "running" });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });
});

describe("api.getStreamUrl", () => {
  // SSE auth uses a short-lived stream_token (issued by POST
  // /stream-token), NOT the long-lived JWT — the backend reads
  // ?stream_token= (auth_middleware.go). Putting the JWT in the URL
  // was the old, less-secure pattern and is no longer supported.
  it("appends the stream_token query param", () => {
    const url = api.getStreamUrl("audit-123", "st-abc");
    expect(url).toContain("/api/audits/audit-123/stream");
    expect(url).toContain("stream_token=st-abc");
  });

  it("url-encodes the stream token", () => {
    const url = api.getStreamUrl("audit-123", "a/b+c=");
    expect(url).toContain("stream_token=a%2Fb%2Bc%3D");
    expect(url).not.toContain("stream_token=a/b+c=");
  });
});
