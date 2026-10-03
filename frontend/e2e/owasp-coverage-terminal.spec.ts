import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Feature 0096 — once an audit is finished, the OWASP coverage card shows the
 * manifest the backend recounted and stored, not the one the OWASP agent
 * streamed while the run was live.
 *
 * The agent's streamed counts are taken before the backend's cross-agent
 * dedup and before it decides whether the mapping is usable. The stored
 * manifest is recounted from the labels the persisted findings carry, so it is
 * the one whose categories lead to rows that exist. A reader who watched the
 * run live must end up looking at the same card as a reader who opens the
 * finished audit later.
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
];

const LABELLED_FINDINGS = [
  finding({
    id: "t-cred", agent_type: "cwe", severity: "high", category: "CWE-798",
    title: "Hardcoded credential", file_path: "src/config.ts",
    compliance_labels: [{ ...A07, cwe: "CWE-798" }],
  }),
];

function category(id: string, name: string, found: string[]) {
  return {
    id,
    name,
    mapped_count: 37,
    found_cwes: found,
    found_count: found.length,
    status: found.length > 0 ? "found" : "clean-or-undetected",
    source_url: `https://owasp.org/Top10/${id}`,
  };
}

// What the OWASP agent streamed: its pre-dedup view, with an injection row
// the backend's dedup later dropped.
const STREAMED_COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [category("A05", "Injection", ["CWE-89"]), category("A07", "Authentication Failures", ["CWE-798"])],
};

// What the backend recounted from the persisted labels.
const RECOUNTED_COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [category("A05", "Injection", []), category("A07", "Authentication Failures", ["CWE-798"])],
};

// A mapping the backend rejected: no finding carries a label, so nothing was found.
const CLEARED_COVERAGE = {
  edition: EDITION,
  cwe_stage_status: "completed",
  categories: [category("A05", "Injection", []), category("A07", "Authentication Failures", [])],
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
      selected: [],
      table: {
        "CWE-798": [{ id: "A07", name: "Authentication Failures" }],
        "CWE-89": [{ id: "A05", name: "Injection" }],
      },
    },
  },
};

interface Finished {
  findings: unknown[];
  owasp_coverage: unknown;
}

const FINISHED: Record<string, Finished> = {
  "audit-recounted": { findings: LABELLED_FINDINGS, owasp_coverage: RECOUNTED_COVERAGE },
  "audit-rejected": { findings: RUNNING_FINDINGS, owasp_coverage: CLEARED_COVERAGE },
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
  const streamed = new Set<string>();
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
    const streamMatch = /^\/api\/audits\/([0-9a-z-]+)\/stream$/.exec(path);
    if (streamMatch) {
      streamed.add(streamMatch[1]);
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: sseFrame({ type: "StepStarted", stepName: "owasp" }) + sseFrame(OWASP_RESULT_SNAPSHOT),
      });
    }
    const auditMatch = /^\/api\/audits\/([0-9a-z-]+)$/.exec(path);
    if (auditMatch) {
      const id = auditMatch[1];
      const now = new Date().toISOString();
      const base = { id, source_id: "src-1", created_at: now, types: ["cwe", "owasp"] };
      if (!streamed.has(id)) {
        return json({ ...base, status: "running", findings: RUNNING_FINDINGS, scores: {} });
      }
      return json({ ...base, status: "completed", completed_at: now, scores: { cwe: 60, owasp: 83 }, ...FINISHED[id] });
    }
    return json([]);
  });
}

const card = (page: Page) => page.locator("[data-testid='owasp-coverage']");
const categoryRow = (page: Page, id: string) => card(page).locator("li").filter({ hasText: id });

test.describe("0096 — the coverage card of a finished audit is the stored one", () => {
  test("a category the backend recounted to zero reads zero once the audit completes", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-recounted");

    // Live, the card shows what the agent streamed.
    await expect(categoryRow(page, "A05")).toContainText("1 / 37", { timeout: 5000 });

    // Completed: the stored manifest replaces it.
    await expect(page.getByText("Completed", { exact: true }).first()).toBeVisible({ timeout: 10000 });
    await expect(categoryRow(page, "A05")).toContainText("0 / 37");
    await expect(categoryRow(page, "A07")).toContainText("1 / 37");
    await expect(card(page)).toContainText("1/2");
    // A07 leads to the row labelled with it; A05 leads nowhere, because no row carries it.
    await expect(page.locator("[data-testid='owasp-coverage-category-A07']")).toHaveCount(1);
    await expect(page.locator("[data-testid='owasp-coverage-category-A05']")).toHaveCount(0);
  });

  test("a rejected mapping leaves no category found once the audit completes", async ({ page }) => {
    await installMocks(page);
    await page.goto("/audit/audit-rejected");

    await expect(categoryRow(page, "A07")).toContainText("1 / 37", { timeout: 5000 });

    await expect(page.getByText("Completed", { exact: true }).first()).toBeVisible({ timeout: 10000 });
    await expect(categoryRow(page, "A05")).toContainText("0 / 37");
    await expect(categoryRow(page, "A07")).toContainText("0 / 37");
    await expect(card(page)).toContainText("0/2");
    await expect(page.locator("[data-testid^='owasp-coverage-category-']")).toHaveCount(0);
  });
});
