import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, act, waitFor, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";

/**
 * Feature 0091 P5 — the INTERACTION half of the aggregate performance
 * question, next to AggregateTable.perf.test.tsx's render half.
 *
 * `AggregateTable.perf.test.tsx` measures what one mount of the table costs.
 * It cannot see the three things that decide what a reader actually
 * experiences, because all three live on the page around the table:
 *
 *   1. how many requests one page view costs,
 *   2. whether a filter change refetches things the filter did not touch,
 *   3. whether the table SURVIVES a filter change or is torn down and
 *      replaced by a placeholder for the length of the round trip.
 *
 * (3) is the one memoisation cannot help with: a memo on the row is worth
 * nothing if the row is unmounted. Measured before the fix: 50 rows / 1,277
 * DOM nodes collapsed to a five-row skeleton and back on every chip.
 */

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

import { TargetReport } from "./TargetReport";
import type { AggregateRow, TargetScan } from "@/lib/types";

const TARGET_KEY = "path:/home/user/src/vulture";
const ENC = encodeURIComponent(TARGET_KEY);
const PAGE_ROWS = 50;

function json(data: unknown) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

function rows(n: number): AggregateRow[] {
  const sev: AggregateRow["severity"][] = ["critical", "high", "medium", "low", "info"];
  const st: AggregateRow["status"][] = ["open", "in_progress", "unconfirmed", "regression"];
  return Array.from({ length: n }, (_, i) => ({
    lineage_id: `l-${i}`,
    ref: `VLT-${90000 + i}`,
    severity: sev[i % sev.length],
    category: `CWE-${100 + (i % 40)}`,
    title: `Seeded aggregate finding ${i}`,
    rel_path: `src/pkg${i % 40}/module_${i}.py`,
    line_start: (i % 300) + 1,
    tier: i % 3 === 0 ? "llm" : "det",
    seen_count: 1 + (i % 6),
    scan_count: 6,
    status: st[i % st.length],
    first_seen_at: "2026-09-01T10:03:00Z",
    last_seen_at: "2026-09-09T10:39:00Z",
    last_event: "detected",
  }));
}

function scans(n: number): TargetScan[] {
  return Array.from({ length: n }, (_, i) => ({
    audit_id: `a-${i}`,
    created_at: new Date(Date.UTC(2026, 8, 1 + (i % 28), 10)).toISOString(),
    types: ["cwe"],
    det_count: 3,
    llm_count: 1,
    sub_path: "",
    git_branch: "develop",
  })) as TargetScan[];
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockImplementation((url: string) => {
    if (url.includes("/scans")) return json(scans(20));
    if (url.includes("/aggregate")) {
      return json({
        total: 120,
        page: 1,
        page_size: PAGE_ROWS,
        tiles: { unique: 120, active: 100, unconfirmed: 3, fixed: 17, critical: 9 },
        rows: rows(PAGE_ROWS),
      });
    }
    return json([]);
  });
});

function urls(): string[] {
  return mockFetch.mock.calls.map((c) => String(c[0]));
}

function renderReport(initial = `/targets/${ENC}`) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/targets/:key" element={<TargetReport />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("TargetReport request shape", () => {
  it("costs exactly two requests to open: the scan list and one page of the aggregate", async () => {
    renderReport();
    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));

    // No per-row, per-scan or per-chip request: the page is two GETs.
    expect(mockFetch.mock.calls.length).toBe(2);
    expect(urls().filter((u) => u.includes("/scans")).length).toBe(1);
    expect(urls().filter((u) => u.includes("/aggregate")).length).toBe(1);
  });

  it("refetches only the aggregate on a filter change, never the scan list", async () => {
    renderReport();
    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));
    const before = mockFetch.mock.calls.length;

    await act(async () => {
      screen.getByRole("button", { name: /severity.critical/i }).click();
    });
    await waitFor(() => expect(mockFetch.mock.calls.length).toBe(before + 1));

    const issued = urls().slice(before);
    expect(issued).toHaveLength(1);
    expect(issued[0]).toContain("severity=critical");
    expect(issued.some((u) => u.includes("/scans"))).toBe(false);
  });

  it("asks for the aggregate ONCE on a ?scans= deep link, not once before the scan list and once after", async () => {
    // `subsetOf` needs the scan list to decide whether the selection is a real
    // subset. Firing before it lands asks for the UNFILTERED page, renders it,
    // and throws it away — two aggregate queries and a flash of the wrong
    // dataset for one page view.
    renderReport(`/targets/${ENC}?scans=a-0,a-1`);
    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));

    const aggregates = urls().filter((u) => u.includes("/aggregate"));
    expect(aggregates).toHaveLength(1);
    expect(decodeURIComponent(aggregates[0])).toContain("scans=a-0,a-1");
  });
});

describe("TargetReport does not tear the table down to refilter it", () => {
  it("keeps the page that is on screen while the next one loads", async () => {
    renderReport();
    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));

    // Synchronously after the click, with the new page still in flight.
    act(() => {
      screen.getByRole("button", { name: /severity.high/i }).click();
    });

    expect(screen.queryAllByTestId("aggregate-row").length).toBe(PAGE_ROWS);
    // …and said so, rather than pretending the stale page is current.
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();

    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));
    expect(document.querySelector('[aria-busy="true"]')).toBeNull();
  });

  it("still shows the skeleton on the FIRST load, when there is no page to keep", async () => {
    renderReport();
    expect(screen.queryAllByTestId("aggregate-row").length).toBe(0);
    expect(document.querySelector(".animate-pulse")).not.toBeNull();
    // Let the in-flight requests settle inside act() so the teardown of this
    // test is not itself an unacted update.
    await waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(PAGE_ROWS));
  });
});
