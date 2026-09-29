import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Feature 0096 — OWASP category filters that cannot mislead.
 *
 *   - The target aggregate's category filter always names an EDITION. A
 *     category id means different things in different editions (A05 is
 *     Injection in 2025 and Security Misconfiguration in 2021), and one
 *     lineage row keeps its labels for every edition it was mapped under, so
 *     a category without an edition is not a question the server answers.
 *   - The results page's category filter belongs to the audit it was set on.
 *     Moving to another scan of the same codebase (the history rail) starts
 *     that audit unfiltered, so an older, unlabelled audit shows its rows.
 *
 * Every API call is mocked; nothing here needs a backend.
 */

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

const AGG_ROWS = [
  aggRow({
    lineage_id: "lin-1", ref: "VLT-2001", category: "CWE-798",
    title: "Hardcoded credential", rel_path: "src/config.ts",
    compliance_labels: { "owasp:2025": ["A07"], "owasp:2021": ["A07"] },
  }),
  aggRow({
    lineage_id: "lin-2", ref: "VLT-2002", category: "CWE-89", severity: "critical",
    title: "SQL injection in query builder", rel_path: "src/db.go",
    compliance_labels: { "owasp:2025": ["A05"], "owasp:2021": ["A03"] },
  }),
  aggRow({
    lineage_id: "lin-3", ref: "VLT-2003", category: "CWE-16", severity: "medium",
    title: "Debug mode enabled in production config", rel_path: "config/app.yaml",
    compliance_labels: { "owasp:2025": ["A02"], "owasp:2021": ["A05"] },
  }),
];

type Labels = Record<string, string[]>;

// The backend's shape: newest edition first, each with the categories its rows carry.
const LABEL_EDITIONS = [
  { framework: "owasp", edition: "2025", categories: ["A02", "A05", "A07"] },
  { framework: "owasp", edition: "2021", categories: ["A03", "A05", "A07"] },
];

/** The backend's contract: a category is matched under ONE framework:edition key. */
function aggregateBody(q: URLSearchParams): { status: number; body: unknown } {
  const framework = q.get("framework");
  const category = q.get("category");
  const edition = q.get("edition");
  if (!framework && !category && !edition) return { status: 200, body: page(AGG_ROWS) };
  if (framework !== "owasp" || !category || !edition) {
    return { status: 400, body: { error: "framework, category and edition are required together" } };
  }
  const key = `${framework}:${edition}`;
  return {
    status: 200,
    body: page(AGG_ROWS.filter((r) => ((r.compliance_labels as Labels)[key] ?? []).includes(category))),
  };
}

function page(rows: unknown[]) {
  return {
    total: rows.length,
    page: 1,
    page_size: 50,
    tiles: { unique: rows.length, active: rows.length, unconfirmed: 0, fixed: 0, critical: 0 },
    rows,
    // Target-wide, whatever the page or filter holds (0096 M8).
    label_editions: LABEL_EDITIONS,
  };
}

const A07 = { framework: "owasp", edition: "2025", category_id: "A07", category_name: "Authentication Failures" };

function finding(over: Record<string, unknown>) {
  return { description: "d", recommendation: "r", line_start: 1, line_end: 1, ...over };
}

const LABELLED = [
  finding({
    id: "n-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
    compliance_labels: [{ ...A07, cwe: "CWE-798" }],
  }),
  finding({
    id: "n-redos", agent_type: "cwe", severity: "medium", category: "CWE-1333",
    title: "Catastrophic regex backtracking", file_path: "src/validate.ts",
  }),
];

// An older scan of the same codebase: the OWASP agent re-emitted copy rows.
const LEGACY = [
  finding({
    id: "o-cwe", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Old hardcoded credential", file_path: "src/config.ts",
  }),
  finding({
    id: "o-owasp", agent_type: "owasp", severity: "high",
    category: "A07:2021-Identification_and_Authentication_Failures",
    title: "[A07] Old hardcoded credential", file_path: "src/config.ts",
  }),
];

const COVERAGE = {
  edition: "2025",
  cwe_stage_status: "completed",
  categories: [
    { id: "A07", name: "Authentication Failures", mapped_count: 36, found_cwes: ["CWE-798"], found_count: 1, status: "found", source_url: "https://owasp.org/Top10/A07" },
  ],
};

const SCANS = [
  { audit_id: "audit-new", created_at: "2026-09-28T10:00:00Z", sub_path: "", det_count: 2, llm_count: 0, types: ["cwe", "owasp"] },
  { audit_id: "audit-old", created_at: "2026-08-01T10:00:00Z", sub_path: "", det_count: 2, llm_count: 0, types: ["cwe", "owasp"] },
];

function auditBody(id: string) {
  const now = new Date().toISOString();
  const base = { id, source_id: "src-1", created_at: now, completed_at: now, status: "completed", target_key: TARGET_KEY };
  if (id === "audit-old") {
    return { ...base, types: ["cwe", "owasp"], findings: LEGACY, scores: { cwe: 70, owasp: 70 } };
  }
  return { ...base, types: ["cwe", "owasp"], findings: LABELLED, scores: { cwe: 60, owasp: 83 }, owasp_coverage: COVERAGE };
}

async function installMocks(page: Page): Promise<URLSearchParams[]> {
  const aggregateQueries: URLSearchParams[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route(/\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
    }
    if (path.endsWith("/stream-token")) return json({ stream_token: "tok" });
    if (path.endsWith("/stream")) return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    const auditMatch = /^\/api\/audits\/([0-9a-z-]+)$/.exec(path);
    if (auditMatch) return json(auditBody(auditMatch[1]));
    if (path === `/api/targets/${TARGET_KEY_ENC}/scans`) return json(SCANS);
    if (path === `/api/targets/${TARGET_KEY_ENC}/aggregate`) {
      aggregateQueries.push(url.searchParams);
      const { status, body } = aggregateBody(url.searchParams);
      return json(body, status);
    }
    return json([]);
  });
  return aggregateQueries;
}

const aggRows = (page: Page) => page.locator("[data-testid='aggregate-row']");

function expectEveryCategoryQueryNamesAnEdition(queries: URLSearchParams[]) {
  for (const q of queries) {
    if (q.has("category")) expect(q.get("edition"), `query ${q.toString()}`).toMatch(/^\d{4}$/);
  }
}

test.describe("0096 — the aggregate OWASP filter names its edition", () => {
  test("a category filters under the newest edition the rows carry, and the edition can be changed", async ({ page }) => {
    const queries = await installMocks(page);
    await page.goto(`/targets/${TARGET_KEY_ENC}`);
    await expect(aggRows(page)).toHaveCount(3, { timeout: 5000 });

    const edition = page.getByLabel("OWASP edition");
    await expect(edition).toHaveValue("2025");

    // A05 in 2025 is Injection: the SQL injection row, not the misconfiguration.
    await page.getByLabel("OWASP category").selectOption("A05");
    await expect(aggRows(page)).toHaveCount(1);
    await expect(aggRows(page).first()).toContainText("VLT-2002");
    const last = queries[queries.length - 1];
    expect(last.get("framework")).toBe("owasp");
    expect(last.get("category")).toBe("A05");
    expect(last.get("edition")).toBe("2025");

    // A05 in 2021 is Security Misconfiguration: a different row entirely.
    await edition.selectOption("2021");
    await expect(aggRows(page)).toHaveCount(1);
    await expect(aggRows(page).first()).toContainText("VLT-2003");
    expect(queries[queries.length - 1].get("edition")).toBe("2021");
    await expect(page).toHaveURL(/owasp=A05/);
    await expect(page).toHaveURL(/owasp_edition=2021/);

    expectEveryCategoryQueryNamesAnEdition(queries);
  });

  test("a deep link naming the category and edition asks for exactly that", async ({ page }) => {
    const queries = await installMocks(page);
    await page.goto(`/targets/${TARGET_KEY_ENC}?owasp=A05&owasp_edition=2021`);
    await expect(aggRows(page)).toHaveCount(1, { timeout: 5000 });
    await expect(aggRows(page).first()).toContainText("VLT-2003");
    await expect(page.getByLabel("OWASP edition")).toHaveValue("2021");
    await expect(page.getByLabel("OWASP category")).toHaveValue("A05");
    expect(queries[0].get("edition")).toBe("2021");
    expectEveryCategoryQueryNamesAnEdition(queries);
  });
});

test.describe("0096 — the aggregate OWASP filter comes from label_editions", () => {
  test("is offered when the target has labels even though no row on the page carries one", async ({ page: p }) => {
    await p.addInitScript(() => {
      localStorage.setItem("vulture_token", "test-token-for-e2e");
    });
    const unlabelled = aggRow({
      lineage_id: "lin-9", ref: "VLT-2009", category: "CWE-1333",
      title: "Catastrophic regex backtracking", rel_path: "src/validate.ts",
    });
    await p.route(/\/api\//, async (route: Route) => {
      const path = new URL(route.request().url()).pathname;
      const json = (body: unknown) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      if (path === "/api/auth/me") {
        return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
      }
      if (path === `/api/targets/${TARGET_KEY_ENC}/aggregate`) return json(page([unlabelled]));
      return json([]);
    });
    await p.goto(`/targets/${TARGET_KEY_ENC}`);
    await expect(aggRows(p)).toHaveCount(1, { timeout: 5000 });
    const edition = p.getByLabel("OWASP edition");
    await expect(edition).toHaveValue("2025");
    await expect(edition.locator("option")).toHaveText(["2025", "2021"]);
    // Only the categories the chosen edition's rows carry are offered.
    const category = p.getByLabel("OWASP category");
    await expect(category.locator("option:not([value='all'])")).toHaveText(["A02", "A05", "A07"]);
    await edition.selectOption("2021");
    await expect(category.locator("option:not([value='all'])")).toHaveText(["A03", "A05", "A07"]);
  });
});

test.describe("0096 — the results-page OWASP filter belongs to its audit", () => {
  test("moving to an older scan from the history rail starts it unfiltered", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-new");
    const table = page.locator("[data-testid='findings-table']");
    const rows = table.locator("[data-testid='finding-row']");
    await expect(rows).toHaveCount(2, { timeout: 5000 });

    await page.locator("[data-testid='owasp-coverage-category-A07']").click();
    await expect(rows).toHaveCount(1);

    await page.locator("[data-testid='rail-entry'][data-audit-id='audit-old'] [data-testid='rail-entry-link']").click();
    await expect(page).toHaveURL(/\/audit\/audit-old$/);
    await expect(rows).toHaveCount(2, { timeout: 5000 });
    await expect(rows.filter({ hasText: "[A07] Old hardcoded credential" })).toHaveCount(1);
    await expect(table.getByLabel("OWASP category")).toHaveCount(0);
  });
});
