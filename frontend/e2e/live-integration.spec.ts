import { test, expect } from "@playwright/test";

/**
 * Live integration tests that run against the real backend.
 * Requires: vulture localstart (backend + agents + frontend on ports 8080, 8001-8003, 3001)
 * Uses the seeded local dev user: admin@vulture.local / REDACTED-DEV-PW
 */

async function login(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.locator('input[type="email"]').fill("admin@vulture.local");
  await page.locator('input[type="password"]').fill("REDACTED-DEV-PW");
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL("/", { timeout: 10000 });
}

test.describe.configure({ mode: "serial" });

test.describe("Live Integration", () => {
  test("login with local dev credentials", async ({ page }) => {
    await login(page);
    await expect(
      page.getByRole("heading", { name: "Dashboard" })
    ).toBeVisible();
  });

  test("full audit flow: login, create audit, view findings", async ({
    page,
  }) => {
    await login(page);

    // Navigate to New Audit
    await page.locator('a[href="/audit"]').first().click();
    await expect(page).toHaveURL("/audit");

    // Fill in the audit form - wait for input to be ready
    const pathInput = page.locator('input[type="text"]').first();
    await expect(pathInput).toBeVisible();
    await pathInput.click();
    await pathInput.fill("/home/user/src/vulture/cli");
    await expect(pathInput).toHaveValue("/home/user/src/vulture/cli");

    // Select OWASP audit type by clicking the card
    await page.locator("text=OWASP").first().click();

    // Submit the audit
    await page.locator("text=Start Audit").click();

    // After clicking Start Audit, the app either:
    // 1. Navigates directly to /audit/<id> (no cache), or
    // 2. Shows "Previous results found" with "Run Fresh Audit" / "View Cached Results"
    // Wait for either outcome.
    const navigated = page.waitForURL(/\/audit\/[a-f0-9]+/, { timeout: 5000 }).then(() => true).catch(() => false);
    const cachedBanner = page.getByText("Run Fresh Audit").waitFor({ timeout: 5000 }).then(() => true).catch(() => false);
    await Promise.race([navigated, cachedBanner]);

    // If cached results banner appeared, click through it
    const freshBtn = page.getByText("Run Fresh Audit");
    if (await freshBtn.isVisible().catch(() => false)) {
      await freshBtn.click();
    }

    // Should now be on audit results page
    await expect(page).toHaveURL(/\/audit\/[a-f0-9]+/, { timeout: 15000 });

    // Wait for audit to complete
    await expect(page.locator("text=Completed").first()).toBeVisible({
      timeout: 30000,
    });

    // Verify score cards are shown
    await expect(page.locator("text=OWASP").first()).toBeVisible();
  });

  test("dashboard shows real audit data after scan", async ({ page }) => {
    await login(page);

    // Dashboard should show stats
    await expect(page.locator("text=AUDITS RUN")).toBeVisible();
    await expect(page.locator("text=TOTAL FINDINGS")).toBeVisible();

    // Should show Recent Audits section
    await expect(page.locator("text=Recent Audits")).toBeVisible();
  });

  test("audit results page shows findings or clean message", async ({
    page,
  }) => {
    await login(page);

    // Click on the first audit in the list
    const auditLink = page.locator("a[href^='/audit/']").first();
    if (await auditLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await auditLink.click();

      // Should show Audit Results page
      await expect(page.locator("text=Audit Results")).toBeVisible({
        timeout: 5000,
      });

      // Wait for content to load
      await page.waitForTimeout(2000);

      // Should show either findings table or clean code message
      const hasFindings = await page
        .locator("text=SEVERITY")
        .isVisible()
        .catch(() => false);
      const noFindings = await page
        .getByText("No findings detected")
        .isVisible()
        .catch(() => false);
      expect(hasFindings || noFindings).toBeTruthy();
    }
  });

  test("logout and redirect to login", async ({ page }) => {
    await login(page);

    // Click sign out
    await page.locator("text=Sign out").click();

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/, { timeout: 5000 });
  });
});
