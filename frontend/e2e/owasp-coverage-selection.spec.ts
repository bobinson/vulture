import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Feature 0096 — an audit run with an OWASP `categories` subset.
 *
 * The backend recounts the stored coverage manifest from the labels the
 * persisted findings carry, and labels only the selected categories. Every
 * category outside the subset therefore has nothing found BY CHOICE, and the
 * backend marks it `selected: false`. Once the audit completes the card must
 * say so: an unselected category must not read as a checked-and-clean "0 / N",
 * and must not count towards the categories the audit covered.
 *
 * Every API call is mocked; nothing here needs a backend.
 */

const EDITION = "2025";

const A07 = { framework: "owasp", edition: EDITION, category_id: "A07", category_name: "Authentication Failures" };

function finding(over: Record<string, unknown>) {
  return { description: "d", recommendation: "r", line_start: 1, line_end: 1, ...over };
}

const RUNNING_FINDINGS = [
  finding({
    id: "t-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
  }),
  finding({
    id: "t-sqli", agent_type: "cwe", severity: "high", category: "CWE-89",
    title: "SQL injection", file_path: "src/db.ts",
  }),
];

// Only A07 was selected, so only the credential row carries a label.
const LABELLED_FINDINGS = [
  finding({
    id: "t-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
    compliance_labels: [{ ...A07, cwe: "CWE-798" }],
  }),
  RUNNING_FINDINGS[1],
];

function category(id: string, name: string, found: string[], extra: Record<string, unknown> = {}) {
  return {
    id,
    name,
    mapped_count: 37,
    found_cwes: found,
    found_count: found.length,
    status: found.length > 0 ? "found" : "clean-or-undetected",
    source_url: `https://owasp.org/Top10/${id}`,
    ...extra,
  };
}

// The agent counts every category whatever the selection.
const STREAMED_COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [
    category("A01", "Broken Access Control", []),
    category("A05", "Injection", ["CWE-89"]),
    category("A07", "Authentication Failures", ["CWE-798"]),
  ],
};

// The backend's recount: A05 and A01 were outside the subset.
const STORED_COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [
    category("A01", "Broken Access Control", [], { selected: false }),
    category("A05", "Injection", [], { selected: false }),
    category("A07", "Authentication Failures", ["CWE-798"]),
  ],
};

const OWASP_RESULT_SNAPSHOT = {
  type: "StateSnapshot",
  agentType: "owasp",
  snapshot: {
    findings: [],
    score: 83,
    summary: "Mapped 2 finding(s) into 2/10 OWASP Top 10:2025 categories.",
    owasp_coverage: STREAMED_COVERAGE,
    mapping: {
      version: 1,
      framework: "owasp",
      edition: EDITION,
      selected: ["A07"],
      table: {
        "CWE-798": [{ id: "A07", name: "Authentication Failures" }],
        "CWE-89": [{ id: "A05", name: "Injection" }],
      },
    },
  },
};

function sseFrame(evt: Record<string, unknown>): string {
  return `event: ${String(evt.type)}\ndata: ${JSON.stringify(evt)}\n\n`;
}

/**
 * The audit reads as running until the page has received the OWASP result
 * over the stream; every read after that finds it completed, with the
 * backend's stored manifest.
 */
async function installMocks(page: Page) {
  let streamed = false;
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route(/\/api\//, async (route: Route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
    }
    if (path.endsWith("/stream-token")) return json({ stream_token: "tok" });
    if (/^\/api\/audits\/[0-9a-z-]+\/stream$/.test(path)) {
      streamed = true;
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: sseFrame({ type: "StepStarted", stepName: "owasp" }) + sseFrame(OWASP_RESULT_SNAPSHOT),
      });
    }
    const auditMatch = /^\/api\/audits\/([0-9a-z-]+)$/.exec(path);
    if (auditMatch) {
      const now = new Date().toISOString();
      const base = { id: auditMatch[1], source_id: "src-1", created_at: now, types: ["cwe", "owasp"] };
      if (!streamed) {
        return json({ ...base, status: "running", findings: RUNNING_FINDINGS, scores: {} });
      }
      return json({
        ...base,
        status: "completed",
        completed_at: now,
        scores: { cwe: 60, owasp: 83 },
        config: { owasp: { edition: EDITION, categories: ["A07"] } },
        findings: LABELLED_FINDINGS,
        owasp_coverage: STORED_COVERAGE,
      });
    }
    return json([]);
  });
}

const card = (page: Page) => page.locator("[data-testid='owasp-coverage']");
const categoryRow = (page: Page, id: string) => card(page).locator("li").filter({ hasText: id });

test.describe("0096 — categories outside the audit's selection", () => {
  test("an unselected category reads 'not selected', not a clean zero, once the audit completes", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-subset");

    // Live, the card shows the agent's count for every category.
    await expect(categoryRow(page, "A05")).toContainText("1 / 37", { timeout: 5000 });

    await expect(page.getByText("Completed", { exact: true }).first()).toBeVisible({ timeout: 10000 });
    for (const id of ["A01", "A05"]) {
      await expect(categoryRow(page, id)).toContainText(/not selected/i);
      await expect(categoryRow(page, id)).not.toContainText("0 / 37");
    }
    await expect(categoryRow(page, "A07")).toContainText("1 / 37");
    // One of the one category the audit covered.
    await expect(card(page)).toContainText("1/1");
    await expect(card(page)).not.toContainText("1/3");
    await expect(page.locator("[data-testid='owasp-coverage-category-A05']")).toHaveCount(0);
    await expect(page.locator("[data-testid='owasp-coverage-category-A07']")).toHaveCount(1);
  });
});
