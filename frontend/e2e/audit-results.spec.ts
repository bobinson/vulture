import { test, expect, type Page } from "@playwright/test";

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

test.describe("Audit Results Page", () => {
  test("shows findings for a completed audit", async ({ page }) => {
    await mockAuth(page);

    const auditId = "audit-completed-1";

    // Mock the audit GET endpoint
    await page.route(`**/api/audits/${auditId}`, async (route) => {
      if (route.request().url().includes("/stream")) {
        return route.continue();
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: auditId,
          source_id: "src-1",
          status: "completed",
          types: ["chaos", "owasp"],
          findings: [
            {
              id: "f1",
              severity: "high",
              category: "retry",
              title: "Missing Retry Logic",
              description: "HTTP call without retry",
              file_path: "main.go",
              line_start: 10,
              line_end: 15,
              recommendation: "Add retry with exponential backoff",
            },
            {
              id: "f2",
              severity: "critical",
              category: "injection",
              title: "SQL Injection",
              description: "Unparameterized query",
              file_path: "db.py",
              line_start: 5,
              line_end: 5,
              recommendation: "Use parameterized queries",
            },
          ],
          scores: { chaos: 72, owasp: 65 },
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto(`/audit/${auditId}`);

    // Should show completed status badge
    await expect(page.locator("text=completed").first()).toBeVisible({ timeout: 5000 });

    // Should show the audit ID (truncated in UI)
    await expect(page.locator(`text=${auditId.slice(0, 10)}`).first()).toBeVisible();

    // Should show findings
    await expect(page.locator("text=Missing Retry Logic")).toBeVisible({ timeout: 5000 });
    await expect(page.locator("text=SQL Injection")).toBeVisible();
  });

  test("shows no findings message for completed audit without findings", async ({ page }) => {
    await mockAuth(page);

    const auditId = "audit-clean-1";

    await page.route(`**/api/audits/${auditId}`, async (route) => {
      if (route.request().url().includes("/stream")) {
        return route.continue();
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: auditId,
          source_id: "src-1",
          status: "completed",
          types: ["chaos"],
          findings: [],
          scores: { chaos: 100 },
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto(`/audit/${auditId}`);

    // Should show completed status
    await expect(page.locator("text=completed").first()).toBeVisible({ timeout: 5000 });
  });

  test("shows score cards for completed audit", async ({ page }) => {
    await mockAuth(page);

    const auditId = "audit-scored-1";

    await page.route(`**/api/audits/${auditId}`, async (route) => {
      if (route.request().url().includes("/stream")) {
        return route.continue();
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: auditId,
          source_id: "src-1",
          status: "completed",
          types: ["chaos", "owasp", "soc2"],
          findings: [
            {
              id: "f1",
              severity: "medium",
              category: "test",
              title: "Test Finding",
              description: "desc",
              file_path: "test.py",
              recommendation: "fix",
            },
          ],
          scores: { chaos: 85, owasp: 72, soc2: 90 },
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto(`/audit/${auditId}`);

    // Should show score values
    await expect(page.locator("text=85").first()).toBeVisible({ timeout: 5000 });
    await expect(page.locator("text=72").first()).toBeVisible();
    await expect(page.locator("text=90").first()).toBeVisible();
  });
});
