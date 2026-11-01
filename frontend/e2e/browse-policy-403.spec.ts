import { test, expect, type Page } from "@playwright/test";

// Feature 0102: in centralized and read-only modes the server refuses every
// folder browse with a 403. The folder browser must absorb that refusal: it
// shows its generic load error (never the server's text), still closes, and
// leaves the source path input usable.

const DISABLED_TEXT =
  "local paths are disabled on this server: set VULTURE_SOURCE_ROOT to allow them in centralized mode";

async function mockSessionAndAgents(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route("**/api/auth/me", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "test-user-1",
        email: "test@example.com",
        name: "Test User",
        role: "member",
        created_at: new Date().toISOString(),
      }),
    }),
  );
  await page.route("**/api/agents", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        { id: "chaos", name: "Chaos Engineering", type: "chaos", description: "Chaos audit" },
      ]),
    }),
  );
}

test.describe("Folder browse refused by the server", () => {
  test("shows the generic load error, closes, and keeps the typed path", async ({ page }) => {
    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));
    await mockSessionAndAgents(page);
    let browseCalls = 0;
    await page.route("**/api/filesystem/browse**", (route) => {
      browseCalls += 1;
      return route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({ error: DISABLED_TEXT }),
      });
    });

    await page.goto("/audit");
    await page.getByTestId("source-type-local").click();
    const pathInput = page.getByTestId("source-url-input");
    await pathInput.fill("/srv/project");
    await page.getByTestId("browse-folder-btn").click();

    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Could not load directory contents")).toBeVisible();
    expect(browseCalls).toBeGreaterThan(0);
    await expect(page.getByText("VULTURE_SOURCE_ROOT")).toHaveCount(0);
    await expect(page.getByText("local paths are disabled")).toHaveCount(0);

    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
    await expect(pathInput).toHaveValue("/srv/project");
    await pathInput.fill("/srv/other");
    await expect(pathInput).toHaveValue("/srv/other");
    expect(pageErrors).toHaveLength(0);
  });
});
