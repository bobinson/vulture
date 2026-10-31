import { test, expect, type Page } from "@playwright/test";

// Feature 0102: nothing in the product reads an API key back from the
// browser, so a key typed on the Settings page must never reach Web Storage,
// where any script running on the origin could read it. Save keeps the model
// choice and drops the key; a key stored by an earlier version is stripped
// when the page loads and is never shown again.

const SETTINGS_KEY = "vulture_settings";
const TYPED_KEY = "sk-e2e-typed-0102-never-stored";
const LEGACY_KEY = "sk-e2e-legacy-0102-stripped-on-load";
const USER = {
  id: "test-user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};

async function openSettings(page: Page) {
  await page.route("**/api/auth/me", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(USER) }),
  );
  await page.goto("/settings");
}

function apiKeyField(page: Page) {
  return page.locator('input[type="password"]');
}

function modelSelect(page: Page) {
  return page.locator("select");
}

// Types a key, picks a non-default model and saves.
async function saveWithKey(page: Page) {
  await openSettings(page);
  await modelSelect(page).selectOption("claude-sonnet");
  await apiKeyField(page).fill(TYPED_KEY);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Settings saved", { exact: true })).toBeVisible();
}

function storedSettings(page: Page): Promise<Record<string, unknown> | null> {
  return page.evaluate((key) => JSON.parse(localStorage.getItem(key) ?? "null"), SETTINGS_KEY);
}

// The Web Storage entries, in either area, whose value contains the secret.
function storageHolding(page: Page, secret: string): Promise<string[]> {
  return page.evaluate((s) => {
    const holding = (area: Storage, name: string) =>
      Object.keys(area)
        .filter((k) => (area.getItem(k) ?? "").includes(s))
        .map((k) => `${name}:${k}`);
    return [...holding(localStorage, "localStorage"), ...holding(sessionStorage, "sessionStorage")];
  }, secret);
}

test.describe("Settings API key is not persisted (0102)", () => {
  test("Save keeps the model and writes no API key to Web Storage", async ({ page }) => {
    await saveWithKey(page);

    const stored = await storedSettings(page);
    expect(stored).toMatchObject({ model: "claude-sonnet" });
    expect(stored).not.toHaveProperty("apiKey");
    expect(await storageHolding(page, TYPED_KEY)).toEqual([]);
  });

  test("after a reload the API key field is empty and Web Storage holds no key", async ({ page }) => {
    await saveWithKey(page);
    await page.reload();

    await expect(modelSelect(page)).toHaveValue("claude-sonnet");
    await expect(apiKeyField(page)).toHaveValue("");
    expect(await storedSettings(page)).not.toHaveProperty("apiKey");
    expect(await storageHolding(page, TYPED_KEY)).toEqual([]);
  });

  test("a key stored by an earlier version is stripped on load and never shown", async ({ page }) => {
    await page.addInitScript(
      ([key, value]) => localStorage.setItem(key, value),
      [SETTINGS_KEY, JSON.stringify({ model: "gemini-pro", apiKey: LEGACY_KEY })] as const,
    );
    await openSettings(page);

    await expect(modelSelect(page)).toHaveValue("gemini-pro");
    await expect.poll(() => storageHolding(page, LEGACY_KEY)).toEqual([]);
    const stored = await storedSettings(page);
    expect(stored).toMatchObject({ model: "gemini-pro" });
    expect(stored).not.toHaveProperty("apiKey");
    await expect(apiKeyField(page)).toHaveValue("");
  });

  test("the model choice still survives a reload", async ({ page }) => {
    await saveWithKey(page);
    await page.reload();

    await expect(modelSelect(page)).toHaveValue("claude-sonnet");
    expect(await storedSettings(page)).toMatchObject({ model: "claude-sonnet" });
  });
});
