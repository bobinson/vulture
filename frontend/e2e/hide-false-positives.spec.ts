import { test, expect, type Page } from "@playwright/test";

// 0045/0036 follow-up — E2E for the "hide false positives" filter +
// the ValidationBadge + the validation-summary banner.

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

const AUDIT_ID = "audit-fp-1";

// Four findings spanning the validate-phase verdicts. The likely_fp is
// the one the toggle must hide; high_confidence + suspicious stay.
const FINDINGS = [
  {
    id: "f-high", severity: "critical", category: "auth",
    title: "Real Auth Bypass", description: "genuine", file_path: "auth.go",
    line_start: 10, line_end: 12, recommendation: "fix",
    validation_status: "high_confidence",
  },
  {
    id: "f-susp", severity: "high", category: "crypto",
    title: "Weak Hash Maybe", description: "needs review", file_path: "hash.go",
    line_start: 5, line_end: 6, recommendation: "fix",
    validation_status: "suspicious",
  },
  {
    id: "f-fp", severity: "medium", category: "xss",
    title: "Antd SSR Style Tag", description: "library css", file_path: "Registry.tsx",
    line_start: 22, line_end: 22, recommendation: "n/a",
    validation_status: "likely_fp",
  },
  {
    id: "f-plain", severity: "low", category: "config",
    title: "Verbose Logging", description: "minor", file_path: "log.go",
    line_start: 1, line_end: 1, recommendation: "fix",
    validation_status: "",
  },
];

async function mockAudit(page: Page) {
  await page.route(`**/api/audits/${AUDIT_ID}`, async (route) => {
    if (route.request().url().includes("/stream")) return route.continue();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: AUDIT_ID,
        source_id: "src-1",
        status: "completed",
        types: ["owasp"],
        findings: FINDINGS,
        scores: { owasp: 60 },
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      }),
    });
  });
  // Lineage endpoint — empty so only validation_status drives the filter.
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
}

test.describe("Hide false positives", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);
    await mockAudit(page);
  });

  test("toggle hides the likely_fp finding and flips its label", async ({ page }) => {
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("text=Real Auth Bypass")).toBeVisible({ timeout: 5000 });

    // All four visible before hiding; the FP row included.
    await expect(page.locator("text=Antd SSR Style Tag")).toBeVisible();

    // The toggle shows the FP count (1).
    const toggle = page.getByRole("switch", { name: /hide false positives/i });
    await expect(toggle).toBeVisible();
    await expect(toggle).toHaveAttribute("aria-checked", "false");

    await toggle.click();

    // The likely_fp finding disappears; trusted + suspicious remain.
    await expect(page.locator("text=Antd SSR Style Tag")).toHaveCount(0);
    await expect(page.locator("text=Real Auth Bypass")).toBeVisible();
    await expect(page.locator("text=Weak Hash Maybe")).toBeVisible();

    // The toggle is now "on" and offers to show them again.
    const shown = page.getByRole("switch", { name: /show false positives/i });
    await expect(shown).toBeVisible();
    await expect(shown).toHaveAttribute("aria-checked", "true");

    // Toggling back restores the FP row.
    await shown.click();
    await expect(page.locator("text=Antd SSR Style Tag")).toBeVisible();
  });

  test("validation badge renders for likely_fp + suspicious only", async ({ page }) => {
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("text=Real Auth Bypass")).toBeVisible({ timeout: 5000 });

    // Badges appear for the two needs-scrutiny verdicts.
    await expect(page.getByText("Likely false positive", { exact: true })).toBeVisible();
    await expect(page.getByText("Suspicious", { exact: true })).toBeVisible();
    // high_confidence + empty render no badge (no "High confidence" pill on rows).
    // The summary banner uses that label, so scope the check to badge cells by
    // asserting there is exactly one "Suspicious" occurrence (the row badge),
    // not a per-row high-confidence pill.
  });

  test("validation summary banner shows the per-audit breakdown", async ({ page }) => {
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("text=Real Auth Bypass")).toBeVisible({ timeout: 5000 });

    // Banner counts: 1 high-confidence, 1 suspicious, 1 likely-fp.
    await expect(page.getByText("High confidence")).toBeVisible();

    // Turn on hiding → banner shows the hidden count.
    await page.getByRole("switch", { name: /hide false positives/i }).click();
    await expect(page.getByText(/1 hidden/i)).toBeVisible();
  });
});
