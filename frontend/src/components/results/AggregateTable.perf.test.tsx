import { describe, expect, it, vi } from "vitest";
import { act, render } from "@testing-library/react";
import { useState, type ReactNode } from "react";

// Same router stub as AggregateTable.test.tsx: the table renders <Link>s and
// this file mounts it without a router.
vi.mock("react-router", () => ({
  Link: ({ to, children, ...rest }: { to: string; children: ReactNode }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}));

import { AggregateTable } from "./AggregateTable";
import type { AggregateRow } from "@/lib/types";

/**
 * Feature 0091 P5 — the RENDER half of the aggregate performance question.
 *
 * The server-side gate (p95 < 200ms for the aggregate endpoint) says nothing
 * about what happens after the JSON lands. The table is capped at 50 rows by
 * the endpoint's default page size, but `page_size` is a query parameter a
 * deep link can carry up to 500, and the component itself takes an unbounded
 * array — so the numbers that matter are 50 (the default), 200 (a widened
 * page) and 1000 (past the endpoint cap; the point at which a per-row cost
 * would be unmissable).
 *
 * WHAT THESE NUMBERS ARE. jsdom, not a browser: this measures React's
 * reconciliation plus DOM construction, which is the part of the cost the
 * component owns. It does not measure layout, paint or style recalculation,
 * which belong to the browser and to the CSS. A regression in the component's
 * own work — an unmemoised row, a per-row subscription, a prop rebuilt every
 * render — shows up here; a slow gradient does not.
 *
 * The thresholds are deliberately loose (a CI box is not a workstation) and
 * exist to catch an ORDER-OF-MAGNITUDE regression, not a 20% one. The logged
 * numbers are the measurement; the assertions are the alarm.
 */

function makeRows(n: number): AggregateRow[] {
  const severities: AggregateRow["severity"][] = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];
  const statuses: AggregateRow["status"][] = [
    "open",
    "in_progress",
    "unconfirmed",
    "regression",
    "fixed",
    "resolved",
    "false_positive",
    "accepted_risk",
  ];
  return Array.from({ length: n }, (_, i) => ({
    lineage_id: `l-${i}`,
    ref: `VLT-${90000 + i}`,
    severity: severities[i % severities.length],
    category: `CWE-${100 + (i % 40)}`,
    title: `Seeded aggregate finding number ${i} with a realistically long title`,
    rel_path: `src/pkg${i % 40}/module_${i}.py`,
    line_start: (i % 300) + 1,
    tier: i % 3 === 0 ? "llm" : "det",
    seen_count: 1 + (i % 6),
    scan_count: 6,
    status: statuses[i % statuses.length],
    first_seen_at: "2026-09-01T10:03:00Z",
    last_seen_at: "2026-09-09T10:39:00Z",
    last_event: "confirmed_by_evidence",
  }));
}

/** Median of repeated samples: one mount can be dominated by a GC pause. */
function median(samples: number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function timeMount(rows: AggregateRow[], runs: number): number {
  const samples: number[] = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    const { unmount } = render(<AggregateTable rows={rows} />);
    samples.push(performance.now() - start);
    unmount();
  }
  return median(samples);
}

/**
 * A parent that re-renders on demand, so the memoisation of the row can be
 * measured: the same `rows` REFERENCE handed down again must not cost what the
 * first mount cost.
 */
function Harness({ rows }: { rows: AggregateRow[] }) {
  const [, setTick] = useState(0);
  return (
    <>
      <button
        type="button"
        data-testid="rerender"
        onClick={() => setTick((n) => n + 1)}
      >
        tick
      </button>
      <AggregateTable rows={rows} />
    </>
  );
}

// Wall-clock budget for the measurements below.
//
// These tests take medians over repeated mounts — test 1 alone mounts 22 times,
// five of them at 1000 rows — so they are DELIBERATELY slow. On this workstation
// that is ~3s against vitest's 5s default; a GitHub runner is roughly twice as
// slow and blew straight through it, failing on the clock while both assertions
// were nowhere near tripping.
//
// Raised rather than sampled less, because the sample count is what keeps the
// medians stable: cutting it would trade a timeout flake for a noisier ratio,
// which fails as a false POSITIVE and is far worse. Nothing here asserts an
// absolute duration — `perRow1000 < perRow50 * 3` and `rerender < mount / 5`
// are both ratios and hold on any hardware — so a generous budget weakens no
// claim.
const PERF_TIMEOUT_MS = 30_000;

describe("AggregateTable render cost", () => {
  it(
    "mounts 50 / 200 / 1000 rows in a cost that grows linearly, not worse",
    () => {
      // Warm up: the first mount in a file pays module init and jsdom warm-up.
      timeMount(makeRows(50), 3);

      const at50 = timeMount(makeRows(50), 7);
      const at200 = timeMount(makeRows(200), 7);
      const at1000 = timeMount(makeRows(1000), 5);

      const perRow50 = at50 / 50;
      const perRow1000 = at1000 / 1000;
      console.log(
        `AggregateTable mount (jsdom, median):\n` +
          `    50 rows: ${at50.toFixed(1)}ms  (${(perRow50 * 1000).toFixed(0)}us/row)\n` +
          `   200 rows: ${at200.toFixed(1)}ms  (${((at200 / 200) * 1000).toFixed(0)}us/row)\n` +
          `  1000 rows: ${at1000.toFixed(1)}ms  (${(perRow1000 * 1000).toFixed(0)}us/row)`,
      );

      // Linear, not quadratic: the per-row cost at 1000 rows must not be far
      // above the per-row cost at 50. A super-linear shape here is the signature
      // of work done per row that depends on the row COUNT.
      expect(perRow1000).toBeLessThan(perRow50 * 3);
    },
    PERF_TIMEOUT_MS,
  );

  it(
    "does not re-render its rows when the parent re-renders with the same rows",
    () => {
      const rows = makeRows(1000);
      const { getByTestId } = render(<Harness rows={rows} />);
      const button = getByTestId("rerender");

      // act() is not decoration here: without it the state update is scheduled
      // and the timer closes before React has committed anything, so the
      // measurement reads ~0.1ms and proves nothing.
      act(() => button.click());

      const samples: number[] = [];
      for (let i = 0; i < 7; i++) {
        const start = performance.now();
        act(() => button.click());
        samples.push(performance.now() - start);
      }
      const rerender = median(samples);
      const mount = timeMount(rows, 3);
      console.log(
        `AggregateTable re-render with a stable rows reference (1000 rows): ` +
          `${rerender.toFixed(1)}ms vs ${mount.toFixed(1)}ms to mount`,
      );

      // memo() on the row means a parent re-render costs the table's own frame,
      // not a thousand rows. A fifth of the mount cost is a loose bound on
      // "the rows were skipped".
      expect(rerender).toBeLessThan(mount / 5);
    },
    PERF_TIMEOUT_MS,
  );

  it(
    "costs a full row pass when a filter change brings new row objects",
    () => {
      // The filter-change case, which memo cannot help with and is not supposed
      // to: the server returned a different page, so every row object is new.
      // What this pins is the SIZE of that cost at the page sizes the endpoint
      // can actually return — 50 by default, 500 at the handler's cap.
      for (const size of [50, 500]) {
        function Refetching() {
          const [gen, setGen] = useState(0);
          return (
            <>
              <button
                type="button"
                data-testid="refetch"
                onClick={() => setGen((n) => n + 1)}
              >
                refetch
              </button>
              <AggregateTable
                rows={makeRows(size).map((r) => ({
                  ...r,
                  seen_count: 1 + (gen % 5),
                }))}
              />
            </>
          );
        }
        const { getByTestId, unmount } = render(<Refetching />);
        const button = getByTestId("refetch");
        act(() => button.click());

        const samples: number[] = [];
        for (let i = 0; i < 5; i++) {
          const start = performance.now();
          act(() => button.click());
          samples.push(performance.now() - start);
        }
        console.log(
          `AggregateTable filter change (${size} new row objects): ${median(samples).toFixed(1)}ms`,
        );
        unmount();
      }
    },
    PERF_TIMEOUT_MS,
  );
});
