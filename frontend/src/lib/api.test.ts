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

describe("api.getStreamUrl", () => {
  it("returns SSE url without token", () => {
    localStorage.clear();
    const url = api.getStreamUrl("audit-123");
    expect(url).toBe("/api/audits/audit-123/stream");
  });

  it("includes token as query param", () => {
    localStorage.setItem("vulture_token", "jwt-abc");
    const url = api.getStreamUrl("audit-123");
    expect(url).toContain("token=jwt-abc");
  });
});
