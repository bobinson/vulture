import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";

/**
 * Feature 0091 P5 — the dashboard's FIRST PAINT.
 *
 * The target list and the audit list come from different endpoints and 0091
 * put the target list first, because the codebase — not the run — is what a
 * reader navigates by. A single page-wide loading gate undoes that: the list
 * that landed first cannot paint until the list that landed last has, and the
 * reader looks at a spinner in front of data the browser is already holding.
 *
 * The audit side is held OPEN by the test and released explicitly, rather
 * than being put on a timer. A timer would be racing `waitFor`'s own poll
 * interval: whichever fires first decides whether the spinner is still on
 * screen when the target rows are asserted, and under suite load the timer
 * wins often enough to make the guard flaky (measured: 2 of 6 full-suite
 * runs, `expected null not to be null`). A guard that fails at random gets
 * deleted, so the gate is explicit and the measurement is exact: while
 * nothing has resolved the audit request, the audit section MUST still be
 * working and the target rows MUST already be painted.
 */

vi.mock("react-router", () => ({
  Link: ({ to, children, ...rest }: { to: string; children: React.ReactNode }) => (
    <a href={to} {...rest}>{children}</a>
  ),
  useNavigate: () => vi.fn(),
}));

vi.mock("@/lib/api.ts", () => ({
  api: {
    getStats: vi.fn(),
    listAudits: vi.fn(),
    listTargets: vi.fn(),
  },
}));

import { Dashboard } from "./Dashboard";
import { api } from "@/lib/api.ts";

const mockGetStats = vi.mocked(api.getStats);
const mockListAudits = vi.mocked(api.listAudits);
const mockListTargets = vi.mocked(api.listTargets);

/** A promise the test resolves by hand. No timers, so nothing can race. */
function gate<T>(): { promise: Promise<T>; open: (value: T) => void } {
  let open!: (value: T) => void;
  const promise = new Promise<T>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

let statsGate: ReturnType<typeof gate<unknown>>;
let auditsGate: ReturnType<typeof gate<unknown>>;

/** Let the audit side land, and flush the state updates it causes. */
async function releaseAuditSide() {
  await act(async () => {
    statsGate.open({ audits_run: 12, total_findings: 48, critical_issues: 5 });
    auditsGate.open([]);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // The audit side stays OPEN until the test says otherwise…
  statsGate = gate<unknown>();
  auditsGate = gate<unknown>();
  mockGetStats.mockReturnValue(statsGate.promise as never);
  mockListAudits.mockReturnValue(auditsGate.promise as never);
  // …and the target side is fast.
  mockListTargets.mockResolvedValue([
    {
      target_key: "path:/srv/one",
      display_name: "one",
      scan_count: 3,
      active_count: 4,
      unconfirmed_count: 1,
      fixed_count: 2,
      last_scan_at: "2026-09-09T10:39:00Z",
    },
  ] as never);
});

describe("Dashboard first paint", () => {
  it("paints the target list without waiting for the audit list", async () => {
    render(<Dashboard />);

    // The target rows are on screen while the audit request is still open.
    await waitFor(() => expect(screen.getAllByTestId("target-row").length).toBe(1));
    expect(mockListAudits).toHaveBeenCalled();
    // …and the audit section says it is still working, rather than the page
    // hiding everything behind one spinner. Nothing has resolved the audit
    // request yet, so this is a fact, not a race.
    expect(document.querySelector(".animate-spin")).not.toBeNull();

    await releaseAuditSide();

    await waitFor(() => expect(document.querySelector(".animate-spin")).toBeNull(), {
      timeout: 2000,
    });
    expect(screen.getAllByTestId("target-row").length).toBe(1);
  });
});
