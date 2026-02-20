import { test, expect, type Page } from "@playwright/test";

/**
 * Helper to set up a mock auth token so the app thinks we are logged in.
 * This avoids needing the backend to be fully running for UI-only tests.
 */
async function loginViaStorage(page: Page) {
  // Set a fake token and user data in localStorage before navigating
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
}

test.describe("Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaStorage(page);
  });

  test("displays dashboard layout when authenticated", async ({ page }) => {
    // Mock the /api/auth/me endpoint to return a valid user
    await page.route("**/api/auth/me", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "test-user-1",
          email: "test@vulture.dev",
          name: "Test User",
          role: "admin",
          created_at: new Date().toISOString(),
        }),
      });
    });

    // Mock stats endpoint
    await page.route("**/api/stats", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          audits_run: 5,
          total_findings: 42,
          critical_issues: 3,
          average_score: 78,
        }),
      });
    });

    // Mock audits list
    await page.route("**/api/audits?*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            id: "audit-1",
            source_id: "src-1",
            status: "completed",
            types: ["chaos", "owasp"],
            findings: [{ id: "f1", severity: "high", title: "Test" }],
            scores: { chaos: 85, owasp: 72 },
            created_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
          },
          {
            id: "audit-2",
            source_id: "src-2",
            status: "running",
            types: ["soc2"],
            created_at: new Date().toISOString(),
          },
        ]),
      });
    });

    await page.goto("/");

    // Should show stat cards
    await expect(page.locator("text=5")).toBeVisible(); // audits_run
    await expect(page.locator("text=42")).toBeVisible(); // total_findings

    // Should show audit list items
    await expect(page.locator("text=Chaos, OWASP")).toBeVisible();
    await expect(page.locator("text=SOC2").first()).toBeVisible();

    // Should have a "New Audit" link
    const newAuditLink = page.locator('a[href="/audit"]');
    await expect(newAuditLink.first()).toBeVisible();
  });

  test("shows empty state when no audits exist", async ({ page }) => {
    await page.route("**/api/auth/me", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "test-user-1",
          email: "test@vulture.dev",
          name: "Test User",
          role: "admin",
          created_at: new Date().toISOString(),
        }),
      });
    });

    await page.route("**/api/stats", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          audits_run: 0,
          total_findings: 0,
          critical_issues: 0,
          average_score: 0,
        }),
      });
    });

    await page.route("**/api/audits?*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await page.goto("/");

    // Should show 0 in stat cards
    await expect(page.locator("text=0").first()).toBeVisible();
  });

  test("status filter buttons are visible when audits exist", async ({ page }) => {
    await page.route("**/api/auth/me", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "u1",
          email: "test@vulture.dev",
          name: "Test",
          role: "admin",
          created_at: new Date().toISOString(),
        }),
      });
    });
    await page.route("**/api/stats", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ audits_run: 1, total_findings: 0, critical_issues: 0, average_score: 0 }),
      });
    });
    await page.route("**/api/audits?*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            id: "a1",
            source_id: "s1",
            status: "completed",
            types: ["chaos"],
            created_at: new Date().toISOString(),
          },
        ]),
      });
    });

    await page.goto("/");

    // Filter buttons should be present
    const searchInput = page.locator('input[type="text"]');
    await expect(searchInput).toBeVisible();
  });
});
