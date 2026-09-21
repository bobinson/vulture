import { test, expect, type Page } from "@playwright/test";

/**
 * Feature 0091 P5 (RED) — the aggregate report is the default view.
 *
 * LLD §10.2 navigation contract, asserted end to end:
 *
 *   dashboard lists TARGETS (not audits)
 *     → click a target                        → the target's AGGREGATE is the landing view
 *     → "Active only" is ON by default        → fixed rows are hidden
 *     → toggle it off ("Show all")            → fixed rows appear, status=all is requested
 *     → click a finding row                   → lineage detail, timeline carries
 *                                               `confirmed_by_evidence`
 *     → click the event's scan                → /audit/{id}: the EXISTING results page,
 *                                               now with the scan-history rail
 *     → click a rail entry                    → navigates to that scan
 *
 * Plus the non-regression clause of §10.2: "`/audit/{id}` keeps working" — nothing a
 * user can reach today may become unreachable, so the deep link is asserted directly.
 */

// A realistic 0091 target key: the canonical path form, prefixed. Deliberately
// free of dots so the encoded single path segment survives the dev server's
// SPA fallback when it is used as a deep link.
const TARGET_KEY = "path:/home/user/danger/blu-simulator";
const TARGET_KEY_ENC = encodeURIComponent(TARGET_KEY);

const SCAN_NEWEST = "2281d2a2";
const SCAN_MIDDLE = "b94cfa15";
const SCAN_OLDEST = "7ec46f63";

const LINEAGE_ID = "l-92190";

const TARGETS = [
  {
    target_key: TARGET_KEY,
    display_name: "blu-simulator",
    scan_count: 3,
    active_count: 2,
    unconfirmed_count: 1,
    fixed_count: 1,
    last_scan_at: "2026-09-09T10:37:00Z",
    last_audit_id: SCAN_NEWEST,
  },
];

const SCANS = [
  {
    audit_id: SCAN_NEWEST,
    created_at: "2026-09-09T10:37:00Z",
    sub_path: ".vscode",
    git_branch: "main",
    det_count: 16,
    llm_count: 5,
    types: ["cwe"],
  },
  {
    audit_id: SCAN_MIDDLE,
    created_at: "2026-09-09T09:48:00Z",
    sub_path: ".vscode",
    git_branch: "main",
    det_count: 0,
    llm_count: 1,
    types: ["cwe"],
  },
  {
    audit_id: SCAN_OLDEST,
    created_at: "2026-09-08T20:00:00Z",
    sub_path: "",
    git_branch: "main",
    det_count: 12,
    llm_count: 0,
    types: ["cwe"],
  },
];

const ROW_ACTIVE_LLM = {
  lineage_id: LINEAGE_ID,
  ref: "VLT-92190",
  severity: "critical",
  category: "CWE-506",
  title: "VS Code task runs on folderOpen",
  rel_path: ".vscode/tasks.json",
  line_start: 7,
  tier: "llm",
  seen_count: 2,
  scan_count: 3,
  status: "open",
  first_seen_at: "2026-09-09T10:03:00Z",
  last_seen_at: "2026-09-09T10:39:00Z",
  last_event: "confirmed_by_evidence",
};

const ROW_ACTIVE_DET = {
  lineage_id: "l-90001",
  ref: "VLT-90001",
  severity: "high",
  category: "CWE-798",
  title: "Hardcoded credential in config",
  rel_path: "src/config.ts",
  line_start: 12,
  tier: "det",
  seen_count: 3,
  scan_count: 3,
  status: "regression",
  first_seen_at: "2026-09-01T08:00:00Z",
  last_seen_at: "2026-09-09T10:39:00Z",
  last_event: "regression",
};

const ROW_FIXED = {
  lineage_id: "l-88888",
  ref: "VLT-88888",
  severity: "medium",
  category: "CWE-327",
  title: "Weak hash algorithm",
  rel_path: "src/hash.go",
  line_start: 3,
  tier: "det",
  seen_count: 1,
  scan_count: 3,
  status: "fixed",
  first_seen_at: "2026-08-20T08:00:00Z",
  last_seen_at: "2026-09-08T20:04:00Z",
  last_event: "evidence_gone",
};

const TILES_ACTIVE = { unique: 2, active: 2, unconfirmed: 1, fixed: 1, critical: 1 };
const TILES_ALL = { unique: 3, active: 2, unconfirmed: 1, fixed: 1, critical: 1 };

const TIMELINE = [
  {
    id: "ev-1",
    lineage_id: LINEAGE_ID,
    event_type: "detected",
    audit_id: SCAN_MIDDLE,
    git_branch: "main",
    created_at: "2026-09-09T10:03:00Z",
  },
  {
    id: "ev-2",
    lineage_id: LINEAGE_ID,
    event_type: "confirmed_by_evidence",
    audit_id: SCAN_NEWEST,
    git_branch: "main",
    notes: "evidence quote found at .vscode/tasks.json:7",
    created_at: "2026-09-09T10:39:00Z",
  },
];

const LINEAGE_DETAIL = {
  id: LINEAGE_ID,
  fingerprint: "fp-92190",
  fingerprint_v2: "fpv2-92190",
  target_key: TARGET_KEY,
  source_path: "/home/user/danger/blu-simulator/.vscode",
  agent_type: "cwe",
  current_status: "open",
  ref: "VLT-92190",
  ref_number: 92190,
  first_audit_id: SCAN_MIDDLE,
  first_found_at: "2026-09-09T10:03:00Z",
  latest_audit_id: SCAN_NEWEST,
  latest_found_at: "2026-09-09T10:39:00Z",
  severity: "critical",
  category: "CWE-506",
  title: "VS Code task runs on folderOpen",
  file_path: ".vscode/tasks.json",
  seen_count: 2,
  created_at: "2026-09-09T10:03:00Z",
  updated_at: "2026-09-09T10:39:00Z",
  evidence: {
    last_outcome: "confirmed",
    reason: "quote found at claimed line",
    line_start: 7,
    line_end: 7,
    file_hash: "sha256:deadbeef",
    checked_at: "2026-09-09T10:39:00Z",
  },
  seen_in: [SCAN_MIDDLE, SCAN_NEWEST],
  events: TIMELINE,
};

function auditPayload(id: string, title: string) {
  const scan = SCANS.find((s) => s.audit_id === id) ?? SCANS[0];
  return {
    id,
    source_id: "src-blu",
    target_key: TARGET_KEY,
    source_path: "/home/user/danger/blu-simulator",
    status: "completed",
    types: ["cwe"],
    findings: [
      {
        id: `f-${id}`,
        severity: "critical",
        category: "CWE-506",
        title,
        description: "A folderOpen task shells out on open.",
        file_path: ".vscode/tasks.json",
        line_start: 7,
        line_end: 7,
        recommendation: "Remove runOn: folderOpen",
      },
    ],
    scores: { cwe: 40 },
    created_at: scan.created_at,
    completed_at: scan.created_at,
  };
}

const AUDIT_TITLES: Record<string, string> = {
  [SCAN_NEWEST]: "Autorun task on newest scan",
  [SCAN_MIDDLE]: "Autorun task on middle scan",
  [SCAN_OLDEST]: "Autorun task on oldest scan",
};

interface MockState {
  aggregateQueries: string[];
  targetListCalls: number;
}

/**
 * One dispatcher for every /api call. A single route keeps ordering
 * unambiguous (Playwright matches handlers in reverse registration order) and
 * lets an unmocked endpoint answer with a benign empty body rather than
 * hanging the page.
 */
async function installMocks(page: Page): Promise<MockState> {
  const state: MockState = { aggregateQueries: [], targetListCalls: 0 };

  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });

  await page.route(/\/api\//, async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({
        id: "test-user-1",
        email: "test@example.com",
        name: "Test User",
        role: "admin",
        created_at: "2026-01-01T00:00:00Z",
      });
    }

    if (path === "/api/stats") {
      return json({ audits_run: 3, total_findings: 21, critical_issues: 1, average_score: 40 });
    }

    if (path === "/api/targets") {
      state.targetListCalls += 1;
      return json(TARGETS);
    }

    if (path === `/api/targets/${TARGET_KEY_ENC}/scans`) {
      return json(SCANS);
    }

    if (path === `/api/targets/${TARGET_KEY_ENC}/aggregate`) {
      state.aggregateQueries.push(url.search);
      const showAll = url.searchParams.get("status") === "all";
      const rows = showAll
        ? [ROW_ACTIVE_LLM, ROW_ACTIVE_DET, ROW_FIXED]
        : [ROW_ACTIVE_LLM, ROW_ACTIVE_DET];
      return json({
        total: rows.length,
        page: 1,
        page_size: 50,
        tiles: showAll ? TILES_ALL : TILES_ACTIVE,
        rows,
      });
    }

    if (path === `/api/lineage/${LINEAGE_ID}`) {
      return json(LINEAGE_DETAIL);
    }

    if (path === `/api/lineage/${LINEAGE_ID}/timeline`) {
      return json(TIMELINE);
    }

    const auditMatch = /^\/api\/audits\/([0-9a-z-]+)$/.exec(path);
    if (auditMatch) {
      const id = auditMatch[1];
      return json(auditPayload(id, AUDIT_TITLES[id] ?? "Autorun task"));
    }

    if (path.endsWith("/stream")) {
      return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    }

    // Everything else the results page touches (sources, comparison, lineage,
    // llm health, …) answers empty; none of it is under test here.
    return json([]);
  });

  return state;
}

test.describe("0091 — aggregate is the default view", () => {
  test("dashboard → target → aggregate → lineage → scan → rail", async ({ page }) => {
    const state = await installMocks(page);

    // 1. The dashboard lists TARGETS, not audits.
    await page.goto("/");
    const targetRows = page.locator("[data-testid='target-row']");
    await expect(targetRows).toHaveCount(1, { timeout: 5000 });
    await expect(targetRows.first()).toContainText("blu-simulator");

    // 2. Clicking a target lands on that target's aggregate report.
    await targetRows.first().locator("[data-testid='target-row-link']").click();
    await expect(page).toHaveURL(new RegExp(`/targets/${TARGET_KEY_ENC}`));
    const report = page.locator("[data-testid='aggregate-report']");
    await expect(report).toBeVisible();

    // 3. "Active only" is ON by default; the fixed row is not shown.
    const activeOnly = page.locator("[data-testid='aggregate-active-only-toggle']");
    await expect(activeOnly).toBeVisible();
    await expect(activeOnly).toHaveAttribute("aria-checked", "true");
    await expect(activeOnly).toHaveText(/active only|show all/i);

    const rows = page.locator("[data-testid='aggregate-row']");
    await expect(rows).toHaveCount(2);
    await expect(page.getByText("VLT-92190")).toBeVisible();
    await expect(page.getByText("VLT-88888")).toHaveCount(0);
    // The default request must not have asked for the dismissed rows.
    expect(state.aggregateQueries.some((q) => q.includes("status=all"))).toBe(false);

    // 4. Toggling to "Show all" reveals the fixed row.
    await activeOnly.click();
    await expect(activeOnly).toHaveAttribute("aria-checked", "false");
    await expect(rows).toHaveCount(3);
    await expect(page.getByText("VLT-88888")).toBeVisible();
    expect(state.aggregateQueries.some((q) => q.includes("status=all"))).toBe(true);

    // 5. Clicking a finding row opens the lineage detail with the new event
    //    in its timeline.
    await page
      .locator("[data-testid='aggregate-row']", { hasText: "VLT-92190" })
      .locator("[data-testid='aggregate-row-link']")
      .click();
    await expect(page).toHaveURL(new RegExp(`/lineage/${LINEAGE_ID}`));
    await expect(page.locator("[data-testid='lineage-detail']")).toBeVisible();
    const confirmed = page.locator("[data-testid='timeline-event-confirmed_by_evidence']");
    await expect(confirmed).toBeVisible();

    // 6. Each occurrence links to its scan; following it renders the EXISTING
    //    per-scan results page.
    await confirmed.locator(`a[href$='/audit/${SCAN_NEWEST}']`).first().click();
    await expect(page).toHaveURL(new RegExp(`/audit/${SCAN_NEWEST}$`));
    await expect(page.getByText(AUDIT_TITLES[SCAN_NEWEST])).toBeVisible({ timeout: 5000 });

    // 7. …now carrying the scan-history rail: every scan of the target, the
    //    current one marked.
    const rail = page.locator("[data-testid='scan-history-rail']");
    await expect(rail).toBeVisible();
    const railEntries = rail.locator("[data-testid='rail-entry']");
    await expect(railEntries).toHaveCount(3);
    await expect(rail.locator("[data-current='true']")).toHaveCount(1);
    await expect(rail.locator("[data-current='true']")).toHaveAttribute(
      "data-audit-id",
      SCAN_NEWEST,
    );

    // 8. Clicking a rail entry navigates to that scan.
    await rail
      .locator(`[data-testid='rail-entry'][data-audit-id='${SCAN_OLDEST}']`)
      .locator("[data-testid='rail-entry-link']")
      .click();
    await expect(page).toHaveURL(new RegExp(`/audit/${SCAN_OLDEST}$`));
    await expect(page.getByText(AUDIT_TITLES[SCAN_OLDEST])).toBeVisible({ timeout: 5000 });
  });

  test("the existing /audit/{id} deep link still works on its own", async ({ page }) => {
    await installMocks(page);

    // Nothing reachable today may become unreachable: the per-scan results
    // page must still render when opened directly, with no target/aggregate
    // navigation in front of it.
    await page.goto(`/audit/${SCAN_MIDDLE}`);
    await expect(page.getByText(AUDIT_TITLES[SCAN_MIDDLE])).toBeVisible({ timeout: 5000 });
    await expect(page.locator("[data-testid='scan-history-rail']")).toBeVisible();
  });
});
