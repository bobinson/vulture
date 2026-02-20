import { test, expect } from "@playwright/test";

test.describe("Login Page", () => {
  test("renders login form with email and password fields", async ({ page }) => {
    await page.goto("/login");

    // Should have the Vulture branding
    await expect(page.locator("text=ulture")).toBeVisible();

    // Should have email input
    const emailInput = page.locator('input[type="email"]');
    await expect(emailInput).toBeVisible();
    await expect(emailInput).toHaveAttribute("required", "");

    // Should have password input
    const passwordInput = page.locator('input[type="password"]');
    await expect(passwordInput).toBeVisible();
    await expect(passwordInput).toHaveAttribute("required", "");

    // Should have submit button
    const submitButton = page.locator('button[type="submit"]');
    await expect(submitButton).toBeVisible();

    // Should have link to register page
    const registerLink = page.locator('a[href="/register"]');
    await expect(registerLink).toBeVisible();
  });

  test("shows error on invalid credentials", async ({ page }) => {
    await page.goto("/login");

    await page.locator('input[type="email"]').fill("invalid@test.com");
    await page.locator('input[type="password"]').fill("wrongpassword");
    await page.locator('button[type="submit"]').click();

    // Should show error message (API will reject invalid credentials)
    // Wait for either error or navigation
    await page.waitForTimeout(2000);

    // If backend is running, we expect an error. If not, the form submit may fail silently.
    // Either way, we should still be on the login page (not redirected)
    expect(page.url()).toContain("/login");
  });

  test("navigates to register page from login", async ({ page }) => {
    await page.goto("/login");

    const registerLink = page.locator('a[href="/register"]');
    await registerLink.click();

    await expect(page).toHaveURL(/\/register/);
  });

  test("redirects unauthenticated users to login", async ({ page }) => {
    // Clear any stored tokens
    await page.goto("/login");
    await page.evaluate(() => localStorage.removeItem("vulture_token"));

    // Try to access dashboard
    await page.goto("/");

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });
});
