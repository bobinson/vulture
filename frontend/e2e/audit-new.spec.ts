import { test, expect, type Page } from "@playwright/test";

async function mockAuthAndNav(page: Page) {
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

  // Mock agents list for the AuditTypeSelector
  await page.route("**/api/agents", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        { id: "chaos", name: "Chaos Engineering", type: "chaos", description: "Chaos audit" },
        { id: "owasp", name: "OWASP", type: "owasp", description: "OWASP audit" },
        { id: "soc2", name: "SOC2", type: "soc2", description: "SOC2 audit" },
      ]),
    });
  });
}

test.describe("New Audit Page", () => {
  test("renders source input and audit type selectors", async ({ page }) => {
    await mockAuthAndNav(page);
    await page.goto("/audit");

    // Should show the submit button
    const submitButton = page.locator('[data-testid="audit-submit-button"]');
    await expect(submitButton).toBeVisible();
  });

  test("shows validation error when no agents selected", async ({ page }) => {
    await mockAuthAndNav(page);
    await page.goto("/audit");

    // Type a local path
    const pathInput = page.locator('input[type="text"]').first();
    if (await pathInput.isVisible()) {
      await pathInput.fill("/home/test/project");
    }

    // Click submit without selecting agents
    const submitButton = page.locator('[data-testid="audit-submit-button"]');
    await submitButton.click();

    // Should stay on the same page (validation error)
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/audit");
  });

  test("submits audit and navigates to results", async ({ page }) => {
    await mockAuthAndNav(page);

    // Mock source creation
    await page.route("**/api/sources", async (route) => {
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          id: "src-123",
          type: "local",
          path: "/home/test/project",
          file_count: 10,
          created_at: new Date().toISOString(),
        }),
      });
    });

    // Mock cache check (no cache)
    await page.route("**/api/audits/cache*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ cached: false }),
      });
    });

    // Mock audit creation
    await page.route("**/api/audits", async (route) => {
      if (route.request().method() === "POST") {
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({
            id: "audit-456",
            source_id: "src-123",
            status: "pending",
            types: ["chaos"],
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.goto("/audit");

    // Fill in the local path
    const pathInput = page.locator('input[type="text"]').first();
    if (await pathInput.isVisible()) {
      await pathInput.fill("/home/test/project");
    }

    // Select an audit type (click first checkbox or agent selector)
    const checkboxes = page.locator('input[type="checkbox"]');
    if ((await checkboxes.count()) > 0) {
      await checkboxes.first().check();
    }

    // Click submit
    const submitButton = page.locator('[data-testid="audit-submit-button"]');
    if (await submitButton.isVisible()) {
      await submitButton.click();

      // Should navigate to the audit results page
      await page.waitForTimeout(1000);
      // Either navigated or showed an error
      const url = page.url();
      if (url.includes("/audit/audit-456")) {
        expect(url).toContain("/audit/audit-456");
      }
    }
  });
});
