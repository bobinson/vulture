import { test, expect, type Page, type Route } from "@playwright/test";
import { readFile } from "node:fs/promises";

/**
 * Feature 0096 — OWASP Top 10 as LABELS over CWE-categorised findings.
 *
 * The OWASP agent no longer re-emits each CWE finding as a second row. It
 * answers with its edition's CWE -> category table, and each finding carries
 * `compliance_labels`. These tests pin what a reader of the results page, the
 * target aggregate and the exported report sees:
 *
 *   - a chip per OWASP label on the finding row (A07), named and dated in its tooltip
 *   - an "OWASP category" filter that narrows the table and composes with severity
 *   - the coverage card's categories set that filter
 *   - a mapping-mode audit offers no OWASP agent filter and shows each finding once
 *   - a pre-0096 audit (OWASP copy rows) still renders as it always did
 *   - a live run labels the rows it holds as soon as the OWASP result arrives
 *   - the target aggregate shows lineage labels and filters by category server-side
 *   - the exported report groups the labelled findings by category
 *
 * Every API call is mocked; nothing here needs a backend.
 */

const EDITION = "2025";

const A05 = { framework: "owasp", edition: EDITION, category_id: "A05", category_name: "Injection" };
const A07 = {
  framework: "owasp",
  edition: EDITION,
  category_id: "A07",
  category_name: "Authentication Failures",
};

function finding(over: Record<string, unknown>) {
  return {
    description: "d",
    recommendation: "r",
    line_start: 1,
    line_end: 1,
    ...over,
  };
}

// A mapping-mode audit: CWE-categorised rows from two scan agents, labelled by
// the backend; no agent_type=owasp row anywhere.
const MAPPED_FINDINGS = [
  finding({
    id: "f-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
    compliance_labels: [{ ...A07, cwe: "CWE-798" }],
  }),
  finding({
    id: "f-env", agent_type: "cwe", severity: "medium", category: "CWE-798",
    title: "Secret in env file", file_path: ".env.local",
    compliance_labels: [{ ...A07, cwe: "CWE-798" }],
  }),
  finding({
    id: "f-sqli", agent_type: "cwe", severity: "critical", category: "CWE-89",
    title: "SQL injection in query builder", file_path: "src/db.go",
    compliance_labels: [{ ...A05, cwe: "CWE-89" }],
  }),
  finding({
    id: "f-xss", agent_type: "xss", severity: "high", category: "CWE-79",
    title: "Reflected XSS in search", file_path: "src/search.tsx",
    compliance_labels: [{ ...A05, cwe: "CWE-79" }],
  }),
  finding({
    id: "f-redos", agent_type: "cwe", severity: "medium", category: "CWE-1333",
    title: "Catastrophic regex backtracking", file_path: "src/validate.ts",
  }),
];

const COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [
    { id: "A01", name: "Broken Access Control", mapped_count: 40, found_cwes: [], found_count: 0, status: "clean-or-undetected", source_url: "https://owasp.org/Top10/A01" },
    { id: "A05", name: "Injection", mapped_count: 37, found_cwes: ["CWE-79", "CWE-89"], found_count: 2, status: "found", source_url: "https://owasp.org/Top10/A05" },
    { id: "A07", name: "Authentication Failures", mapped_count: 36, found_cwes: ["CWE-798"], found_count: 1, status: "found", source_url: "https://owasp.org/Top10/A07" },
  ],
};

// A pre-0096 audit: the OWASP agent re-emitted the CWE row as its own finding.
const LEGACY_FINDINGS = [
  finding({
    id: "l-cwe", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
  }),
  finding({
    id: "l-owasp", agent_type: "owasp", severity: "high",
    category: "A07:2021-Identification_and_Authentication_Failures",
    title: "[A07] Hardcoded credential", file_path: "src/config.ts",
  }),
];

// The live run's rows, as the CWE agent streams them. They never reach the
// audit record while it runs — the backend persists findings (already
// labelled) in the step that completes the audit — so the page can only hold
// them from the stream.
const LIVE_FINDINGS = [
  finding({
    id: "v-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Live hardcoded credential", file_path: "src/config.ts",
  }),
  finding({
    id: "v-redos", agent_type: "cwe", severity: "medium", category: "CWE-1333",
    title: "Live regex backtracking", file_path: "src/validate.ts",
  }),
];

const liveFindingDelta = (f: Record<string, unknown>) => ({
  type: "StateDelta",
  agentType: "cwe",
  delta: [{ op: "add", path: "/findings/-", value: f }],
});

const CWE_RESULT_SNAPSHOT = {
  type: "StateSnapshot",
  agentType: "cwe",
  snapshot: { findings: LIVE_FINDINGS, score: 70 },
};

const OWASP_RESULT_SNAPSHOT = {
  type: "StateSnapshot",
  agentType: "owasp",
  snapshot: {
    findings: [],
    score: 83,
    summary: "Mapped 1 finding(s) into 1/10 OWASP Top 10:2025 categories.",
    mapping: {
      version: 1,
      framework: "owasp",
      edition: EDITION,
      selected: [],
      table: {
        "CWE-798": [{ id: "A07", name: "Authentication Failures" }],
        "CWE-89": [{ id: "A05", name: "Injection" }],
      },
    },
  },
};

const TARGET_KEY = "path:/home/user/work/shop";
const TARGET_KEY_ENC = encodeURIComponent(TARGET_KEY);

function aggRow(over: Record<string, unknown>) {
  return {
    severity: "high",
    tier: "det",
    seen_count: 1,
    scan_count: 1,
    status: "open",
    first_seen_at: "2026-09-28T10:00:00Z",
    last_seen_at: "2026-09-28T10:00:00Z",
    last_event: "detected",
    line_start: 3,
    ...over,
  };
}

const AGG_CRED = aggRow({
  lineage_id: "lin-1", ref: "VLT-1001", category: "CWE-798",
  title: "Hardcoded credential", rel_path: "src/config.ts",
  compliance_labels: { "owasp:2025": ["A07"], "owasp:2021": ["A07"] },
});
const AGG_SQLI = aggRow({
  lineage_id: "lin-2", ref: "VLT-1002", category: "CWE-89", severity: "critical",
  title: "SQL injection in query builder", rel_path: "src/db.go",
  compliance_labels: { "owasp:2025": ["A05"] },
});
const AGG_REDOS = aggRow({
  lineage_id: "lin-3", ref: "VLT-1003", category: "CWE-1333", severity: "medium",
  title: "Catastrophic regex backtracking", rel_path: "src/validate.ts",
});

interface MockState {
  aggregateQueries: URLSearchParams[];
  /** Every status GET /api/audits/{id} answered with, in order. */
  auditStatuses: string[];
}

function auditBody(id: string) {
  const now = new Date().toISOString();
  const base = { id, source_id: "src-1", created_at: now, completed_at: now };
  switch (id) {
    case "audit-legacy":
      return { ...base, status: "completed", types: ["cwe", "owasp"], findings: LEGACY_FINDINGS, scores: { cwe: 70, owasp: 70 } };
    case "audit-live":
    case "audit-live-unmapped":
      // Running, and holding no rows and no labels: whatever the page shows
      // while the run is live, it holds from the stream.
      return { ...base, status: "running", completed_at: undefined, types: ["cwe", "owasp"], findings: [], scores: {} };
    default:
      return {
        ...base,
        status: "completed",
        types: ["cwe", "xss", "owasp"],
        findings: MAPPED_FINDINGS,
        scores: { cwe: 60, xss: 80, owasp: 83 },
        owasp_coverage: COVERAGE,
      };
  }
}

function sseFrame(evt: Record<string, unknown>): string {
  return `event: ${String(evt.type)}\ndata: ${JSON.stringify(evt)}\n\n`;
}

// The CWE agent streams its findings and finishes; then the OWASP agent
// answers with its table. Nothing here completes the audit.
const CWE_STREAM = [
  { type: "RunStarted", runId: "run-live" },
  { type: "StepStarted", stepName: "cwe" },
  ...LIVE_FINDINGS.map(liveFindingDelta),
  CWE_RESULT_SNAPSHOT,
  { type: "StepFinished", stepName: "cwe" },
];
const LIVE_STREAMS: Record<string, Record<string, unknown>[]> = {
  "/api/audits/audit-live/stream": [
    ...CWE_STREAM,
    { type: "StepStarted", stepName: "owasp" },
    OWASP_RESULT_SNAPSHOT,
  ],
  "/api/audits/audit-live-unmapped/stream": CWE_STREAM,
};

async function installMocks(page: Page): Promise<MockState> {
  const state: MockState = { aggregateQueries: [], auditStatuses: [] };
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });

  await page.route(/\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
    }
    if (path.endsWith("/stream-token")) return json({ stream_token: "tok" });
    const liveStream = LIVE_STREAMS[path];
    if (liveStream) {
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: liveStream.map(sseFrame).join(""),
      });
    }
    if (path.endsWith("/stream")) {
      return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    }
    const auditMatch = /^\/api\/audits\/([0-9a-z-]+)$/.exec(path);
    if (auditMatch) {
      const body = auditBody(auditMatch[1]);
      state.auditStatuses.push(body.status);
      return json(body);
    }

    if (path === `/api/targets/${TARGET_KEY_ENC}/scans`) return json([]);
    if (path === `/api/targets/${TARGET_KEY_ENC}/aggregate`) {
      state.aggregateQueries.push(url.searchParams);
      const cat = url.searchParams.get("category");
      const all = [AGG_CRED, AGG_SQLI, AGG_REDOS];
      const rows = cat
        ? all.filter((r) => Object.values((r as { compliance_labels?: Record<string, string[]> }).compliance_labels ?? {}).some((ids) => ids.includes(cat)))
        : all;
      return json({
        total: rows.length,
        page: 1,
        page_size: 50,
        tiles: { unique: rows.length, active: rows.length, unconfirmed: 0, fixed: 0, critical: 0 },
        rows,
        // Target-wide label editions (0096 M8): what the category filter offers.
        label_editions: [
          { framework: "owasp", edition: "2025", categories: ["A05", "A07"] },
          { framework: "owasp", edition: "2021", categories: ["A07"] },
        ],
      });
    }
    return json([]);
  });
  return state;
}

const table = (page: Page) => page.locator("[data-testid='findings-table']");
const rows = (page: Page) => table(page).locator("[data-testid='finding-row']");
const rowFor = (page: Page, title: string) => rows(page).filter({ hasText: title });

test.describe("0096 — OWASP labels on the results page", () => {
  test("each labelled row carries its OWASP chip, named and dated in the tooltip", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-mapped");
    await expect(rows(page)).toHaveCount(5, { timeout: 5000 });

    const chip = rowFor(page, "Hardcoded credential").locator("[data-testid='owasp-chip']");
    await expect(chip).toHaveCount(1);
    await expect(chip).toHaveText("A07");
    await expect(chip).toHaveAttribute("title", /Authentication Failures/);
    await expect(chip).toHaveAttribute("title", /2025/);

    await expect(rowFor(page, "Reflected XSS in search").locator("[data-testid='owasp-chip']")).toHaveText("A05");
    // A CWE the edition does not map gets no chip — not an empty one.
    await expect(rowFor(page, "Catastrophic regex backtracking").locator("[data-testid='owasp-chip']")).toHaveCount(0);
  });

  test("the OWASP category filter narrows the table and composes with severity", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-mapped");
    await expect(rows(page)).toHaveCount(5, { timeout: 5000 });

    const select = table(page).getByLabel("OWASP category");
    // Populated from the labels present, nothing else.
    await expect(select.locator("option")).toHaveCount(3);

    await select.selectOption("A07");
    await expect(rows(page)).toHaveCount(2);
    await expect(rowFor(page, "Hardcoded credential")).toHaveCount(1);
    await expect(rowFor(page, "Secret in env file")).toHaveCount(1);

    await table(page).getByRole("button", { name: "High", exact: true }).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rowFor(page, "Hardcoded credential")).toHaveCount(1);

    await select.selectOption("all");
    // Severity still applies: the two high rows, from both scan agents.
    await expect(rows(page)).toHaveCount(2);
    await expect(rowFor(page, "Reflected XSS in search")).toHaveCount(1);
  });

  test("a coverage-card category sets the filter, and clicking it again clears it", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-mapped");
    await expect(rows(page)).toHaveCount(5, { timeout: 5000 });

    const a05 = page.locator("[data-testid='owasp-coverage-category-A05']");
    await a05.click();
    await expect(a05).toHaveAttribute("aria-pressed", "true");
    await expect(table(page).getByLabel("OWASP category")).toHaveValue("A05");
    await expect(rows(page)).toHaveCount(2);
    await expect(rowFor(page, "SQL injection in query builder")).toHaveCount(1);
    await expect(rowFor(page, "Reflected XSS in search")).toHaveCount(1);

    await a05.click();
    await expect(a05).toHaveAttribute("aria-pressed", "false");
    await expect(rows(page)).toHaveCount(5);

    // A category no finding carries is not a filter: there is nothing to show.
    await expect(page.locator("[data-testid='owasp-coverage-category-A01']")).toHaveCount(0);
  });

  test("a mapping-mode audit offers no OWASP agent filter and shows each finding once", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-mapped");
    await expect(rows(page)).toHaveCount(5, { timeout: 5000 });

    const agentRow = table(page).locator("[data-testid='agent-filter']");
    await expect(agentRow.getByRole("button", { name: "CWE", exact: true })).toBeVisible();
    await expect(agentRow.getByRole("button", { name: "XSS", exact: true })).toBeVisible();
    await expect(agentRow.getByRole("button", { name: "OWASP", exact: true })).toHaveCount(0);

    for (const f of MAPPED_FINDINGS) {
      await expect(rowFor(page, String(f.title))).toHaveCount(1);
    }
  });

  test("a pre-0096 audit still renders its OWASP rows and its OWASP agent filter", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-legacy");
    await expect(rows(page)).toHaveCount(2, { timeout: 5000 });
    await expect(rowFor(page, "[A07] Hardcoded credential")).toHaveCount(1);

    const agentRow = table(page).locator("[data-testid='agent-filter']");
    await agentRow.getByRole("button", { name: "OWASP", exact: true }).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rowFor(page, "[A07] Hardcoded credential")).toHaveCount(1);

    // The page never mixes shapes: no labels, so no label filter and no chips.
    await expect(table(page).getByLabel("OWASP category")).toHaveCount(0);
    await expect(table(page).locator("[data-testid='owasp-chip']")).toHaveCount(0);
  });

  test("a live run shows the CWE agent's streamed rows, unlabelled until a mapping arrives", async ({ page }) => {
    const state = await installMocks(page);
    await page.goto("/audit/audit-live-unmapped");
    await expect(rows(page)).toHaveCount(2, { timeout: 5000 });
    await expect(rowFor(page, "Live hardcoded credential")).toHaveCount(1);
    await expect(table(page).locator("[data-testid='owasp-chip']")).toHaveCount(0);
    await expect(page.getByText("Running", { exact: true }).first()).toBeVisible();
    expect(state.auditStatuses.length).toBeGreaterThan(0);
    expect(state.auditStatuses.every((s) => s === "running")).toBe(true);
  });

  test("a live run labels its streamed rows when the OWASP result snapshot arrives, before any terminal read", async ({ page }) => {
    const state = await installMocks(page);
    await page.goto("/audit/audit-live");
    await expect(rows(page)).toHaveCount(2, { timeout: 5000 });

    const chip = rowFor(page, "Live hardcoded credential").locator("[data-testid='owasp-chip']");
    await expect(chip).toHaveText("A07", { timeout: 5000 });
    await expect(chip).toHaveAttribute("title", /Authentication Failures/);
    await expect(chip).toHaveAttribute("title", /2025/);
    await expect(rowFor(page, "Live regex backtracking").locator("[data-testid='owasp-chip']")).toHaveCount(0);

    // Still the running layout, and every read of the audit so far said
    // running with no rows: the chip came from the stream, not from storage.
    await expect(page.getByText("Running", { exact: true }).first()).toBeVisible();
    expect(state.auditStatuses.length).toBeGreaterThan(0);
    expect(state.auditStatuses.every((s) => s === "running")).toBe(true);
  });

  test("the exported report groups labelled findings by OWASP category", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-mapped");
    await expect(rows(page)).toHaveCount(5, { timeout: 5000 });

    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export Report" }).click();
    const md = await readFile((await (await download).path())!, "utf8");

    const section = md.slice(md.indexOf("## OWASP Top 10:2025"));
    expect(md).toContain("## OWASP Top 10:2025");
    const a05 = section.indexOf("### A05 Injection");
    const a07 = section.indexOf("### A07 Authentication Failures");
    expect(a05).toBeGreaterThan(-1);
    expect(a07).toBeGreaterThan(a05);
    const a05Block = section.slice(a05, a07);
    expect(a05Block).toContain("SQL injection in query builder");
    expect(a05Block).toContain("Reflected XSS in search");
    expect(a05Block).not.toContain("Hardcoded credential");
    const a07Block = section.slice(a07, section.indexOf("\n---", a07));
    expect(a07Block).toContain("Hardcoded credential");
    expect(a07Block).toContain("Secret in env file");
    // Unlabelled findings are in the report, not in the OWASP section.
    expect(md).toContain("Catastrophic regex backtracking");
    expect(section.slice(0, section.indexOf("\n---"))).not.toContain("Catastrophic regex backtracking");
  });
});

test.describe("0096 — OWASP labels on the target aggregate", () => {
  test("rows show lineage label chips and the category filter queries the server", async ({ page }) => {
    const state = await installMocks(page);
    await page.goto(`/targets/${TARGET_KEY_ENC}`);
    const aggRows = page.locator("[data-testid='aggregate-row']");
    await expect(aggRows).toHaveCount(3, { timeout: 5000 });

    const credChips = aggRows.filter({ hasText: "VLT-1001" }).locator("[data-testid='owasp-chip']");
    // One chip per edition the lineage row carries.
    await expect(credChips).toHaveCount(2);
    await expect(credChips.first()).toHaveText("A07");
    await expect(credChips.first()).toHaveAttribute("title", /2025/);
    await expect(aggRows.filter({ hasText: "VLT-1003" }).locator("[data-testid='owasp-chip']")).toHaveCount(0);
    // The default request asks for no framework filter.
    expect(state.aggregateQueries.every((q) => !q.has("framework") && !q.has("category"))).toBe(true);

    await page.getByLabel("OWASP category").selectOption("A07");
    await expect(aggRows).toHaveCount(1);
    await expect(aggRows.first()).toContainText("VLT-1001");
    const last = state.aggregateQueries[state.aggregateQueries.length - 1];
    expect(last.get("framework")).toBe("owasp");
    expect(last.get("category")).toBe("A07");

    await page.getByLabel("OWASP category").selectOption("all");
    await expect(aggRows).toHaveCount(3);
  });
});
