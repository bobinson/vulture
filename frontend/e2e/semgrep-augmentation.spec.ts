import { test, expect, type Page } from "@playwright/test";

// Feature 0058 — Semgrep CWE augmentation UI (LLD R6 / R9).
// Runs in the E2E phase against a live stack: gated on
// VULTURE_E2E_BASE_URL (skipped when unset, mirroring env-gated specs).
//
// Pinned UI contract (matches the vitest RED suite):
//   - each finding with a non-empty `provenance` renders a chip with
//     data-testid="provenance-chip" labeled with the provenance value
//   - the findings table exposes a provenance filter with buttons
//     data-testid="provenance-filter-all" and
//     data-testid="provenance-filter-<value>" (e.g. provenance-filter-semgrep)
//   - when the audit stream reports "Semgrep tier not active", the
//     results page shows a banner with data-testid="semgrep-tier-notice"

const BASE = process.env.VULTURE_E2E_BASE_URL ?? "";

async function mockAuth(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route("**/api/auth/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "test-user-1",
        email: "test@example.com",
        name: "Test User",
        role: "admin",
        created_at: new Date().toISOString(),
      }),
    });
  });
}

const AUDIT_ID = "audit-semgrep-1";

// Two semgrep-provenance findings + one untagged skill finding.
const FINDINGS = [
  {
    id: "f-sg-1", severity: "critical", category: "injection",
    title: "Tainted SQL Sink", description: "source→sink dataflow", file_path: "db.py",
    line_start: 42, line_end: 44, recommendation: "parameterize",
    provenance: "semgrep",
  },
  {
    id: "f-sg-2", severity: "high", category: "injection",
    title: "Command Injection Flow", description: "tainted exec", file_path: "run.py",
    line_start: 7, line_end: 9, recommendation: "sanitize",
    provenance: "semgrep",
  },
  {
    id: "f-skill", severity: "medium", category: "crypto",
    title: "Hardcoded Secret", description: "skill finding", file_path: "cfg.py",
    line_start: 3, line_end: 3, recommendation: "rotate",
  },
];

async function mockCompletedAudit(page: Page) {
  await page.route(`**/api/audits/${AUDIT_ID}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: AUDIT_ID,
        source_id: "src-1",
        status: "completed",
        types: ["cwe", "semgrep"],
        findings: FINDINGS,
        scores: { cwe: 55 },
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      }),
    });
  });
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
}

const NOTICE_AUDIT_ID = "audit-semgrep-notice";

async function mockRunningAuditWithNoticeStream(page: Page) {
  await page.route(`**/api/audits/${NOTICE_AUDIT_ID}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: NOTICE_AUDIT_ID,
        source_id: "src-1",
        status: "running",
        types: ["cwe", "semgrep"],
        findings: [],
        created_at: new Date().toISOString(),
      }),
    });
  });
  await page.route(`**/api/audits/${NOTICE_AUDIT_ID}/lineage`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
  await page.route(`**/api/audits/${NOTICE_AUDIT_ID}/stream-token`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ stream_token: "tok-e2e" }),
    });
  });
  // Replayed SSE stream carrying the R9 graceful-absence notice.
  const sse = [
    'event: RunStarted\ndata: {"runId":"run-notice-1"}\n\n',
    'event: TextMessageContent\ndata: {"delta":"Semgrep tier not active — running skills + signatures only"}\n\n',
    'event: RunFinished\ndata: {}\n\n',
  ].join("");
  await page.route(`**/api/audits/${NOTICE_AUDIT_ID}/stream*`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: sse,
    });
  });
}

test.describe("Semgrep augmentation UI (0058)", () => {
  test.skip(
    !BASE,
    "VULTURE_E2E_BASE_URL unset — runs in the E2E phase against a live stack",
  );

  test.beforeEach(async ({ page }) => {
    await mockAuth(page);
  });

  test("provenance chips are visible on semgrep findings only", async ({ page }) => {
    await mockCompletedAudit(page);
    await page.goto(`${BASE}/audit/${AUDIT_ID}`);
    await expect(page.locator("text=Tainted SQL Sink")).toBeVisible({ timeout: 5000 });

    const chips = page.getByTestId("provenance-chip");
    await expect(chips).toHaveCount(2);
    await expect(chips.first()).toContainText("semgrep");
  });

  test("provenance filter narrows the table to semgrep findings and 'all' resets", async ({ page }) => {
    await mockCompletedAudit(page);
    await page.goto(`${BASE}/audit/${AUDIT_ID}`);
    await expect(page.locator("text=Hardcoded Secret")).toBeVisible({ timeout: 5000 });

    await page.getByTestId("provenance-filter-semgrep").click();
    await expect(page.locator("text=Hardcoded Secret")).toHaveCount(0);
    await expect(page.locator("text=Tainted SQL Sink")).toBeVisible();
    await expect(page.locator("text=Command Injection Flow")).toBeVisible();

    await page.getByTestId("provenance-filter-all").click();
    await expect(page.locator("text=Hardcoded Secret")).toBeVisible();
  });

  test("notice banner appears when the semgrep tier is not active", async ({ page }) => {
    await mockRunningAuditWithNoticeStream(page);
    await page.goto(`${BASE}/audit/${NOTICE_AUDIT_ID}`);

    await expect(page.getByTestId("semgrep-tier-notice")).toBeVisible({ timeout: 10000 });
  });
});
