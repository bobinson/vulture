import { test, expect, type Page } from "@playwright/test";

// "Copy All as Issues" exports exactly the findings the table shows: every
// filter the reader has set (hide false positives, severity, ...) applies to
// the export, across all pages, in the table's order. Before, the button
// exported the audit's unfiltered finding list, so a reader who had hidden
// the triaged false positives still pasted them as issues.

async function mockAuth(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route("**/api/auth/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "test-user-1", email: "test@example.com", name: "Test User",
        role: "admin", created_at: new Date().toISOString(),
      }),
    });
  });
}

async function captureClipboard(page: Page) {
  await page.addInitScript(() => {
    (window as unknown as Record<string, unknown>).__clipboardTexts = [];
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: (text: string) => {
          (window as unknown as Record<string, string[]>).__clipboardTexts.push(text);
          return Promise.resolve();
        },
      },
      writable: true,
    });
  });
}

async function copiedText(page: Page): Promise<string> {
  await expect.poll(async () =>
    page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts.length),
  ).toBe(1);
  return page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts[0]);
}

const AUDIT_ID = "audit-copy-filtered";

function finding(id: string, severity: string, title: string, fingerprint: string) {
  return {
    id, agent_type: "cwe", severity, category: "CWE-209", title,
    description: title, file_path: `src/${id}.ts`, line_start: 10, line_end: 10,
    recommendation: "fix", validation_status: "high_confidence", fingerprint,
  };
}

const TRIAGED = [
  finding("f-real", "critical", "Real Critical Leak", "fp-real"),
  finding("f-dismissed", "critical", "Dismissed Critical Noise", "fp-dismissed"),
  finding("f-high", "high", "Real High Issue", "fp-high"),
];

const LINEAGE = [
  {
    id: "l-dismissed", ref_number: 7001, agent_type: "cwe", current_status: "false_positive",
    fingerprint: "fp-dismissed", source_path: "/work/app", first_audit_id: "audit-earlier",
    first_found_at: "2026-09-01T00:00:00Z", severity: "critical", category: "CWE-209",
    title: "t", file_path: "f", notes: "", created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-09-02T00:00:00Z",
  },
];

async function mockAudit(page: Page, findings: unknown[], lineage: unknown[] = []) {
  await page.route(`**/api/audits/${AUDIT_ID}`, async (route) => {
    if (route.request().url().includes("/stream")) return route.continue();
    await route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        id: AUDIT_ID, source_id: "src-1", status: "completed", types: ["cwe"],
        findings, scores: { cwe: 60 },
        created_at: new Date().toISOString(), completed_at: new Date().toISOString(),
      }),
    });
  });
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lineage) });
  });
}

const copyAll = (page: Page) => page.getByRole("button", { name: /copy all as issues/i });

test.describe("Copy All as Issues follows the table's filters", () => {
  test("hidden false positives are not exported", async ({ page }) => {
    await mockAuth(page);
    await captureClipboard(page);
    await mockAudit(page, TRIAGED, LINEAGE);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("tbody tr", { hasText: "Real Critical Leak" })).toBeVisible({ timeout: 5000 });

    await page.getByRole("switch", { name: /hide false positives \(1\)/i }).click();
    await expect(page.locator("tbody tr", { hasText: "Dismissed Critical Noise" })).toHaveCount(0);
    await copyAll(page).click();

    const md = await copiedText(page);
    expect(md).toContain("Real Critical Leak");
    expect(md).toContain("Real High Issue");
    expect(md).not.toContain("Dismissed Critical Noise");
  });

  test("with no filter set, every finding is exported", async ({ page }) => {
    await mockAuth(page);
    await captureClipboard(page);
    await mockAudit(page, TRIAGED, LINEAGE);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("tbody tr", { hasText: "Real Critical Leak" })).toBeVisible({ timeout: 5000 });

    await copyAll(page).click();
    const md = await copiedText(page);
    expect(md).toContain("Real Critical Leak");
    expect(md).toContain("Dismissed Critical Noise");
    expect(md).toContain("Real High Issue");
  });

  test("the severity filter applies to the export", async ({ page }) => {
    await mockAuth(page);
    await captureClipboard(page);
    await mockAudit(page, TRIAGED, LINEAGE);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("tbody tr", { hasText: "Real High Issue" })).toBeVisible({ timeout: 5000 });

    await page.getByRole("button", { name: /^high$/i }).click();
    await expect(page.locator("tbody tr", { hasText: "Real Critical Leak" })).toHaveCount(0);
    await copyAll(page).click();

    const md = await copiedText(page);
    expect(md).toContain("Real High Issue");
    expect(md).not.toContain("Real Critical Leak");
    expect(md).not.toContain("Dismissed Critical Noise");
  });

  test("the button names how many findings it will copy", async ({ page }) => {
    await mockAuth(page);
    await mockAudit(page, TRIAGED, LINEAGE);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("tbody tr", { hasText: "Real Critical Leak" })).toBeVisible({ timeout: 5000 });

    await expect(copyAll(page)).toContainText("(3)");
    await page.getByRole("switch", { name: /hide false positives \(1\)/i }).click();
    await expect(copyAll(page)).toContainText("(2)");
  });

  test("every filtered finding is exported, not just the current page", async ({ page }) => {
    await mockAuth(page);
    await captureClipboard(page);
    const many = Array.from({ length: 30 }, (_, i) =>
      finding(`f-${i}`, "medium", `Paged Finding ${String(i).padStart(2, "0")}`, `fp-${i}`));
    await mockAudit(page, many);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(page.locator("tbody tr").first()).toBeVisible({ timeout: 5000 });

    await copyAll(page).click();
    const md = await copiedText(page);
    for (let i = 0; i < 30; i++) {
      expect(md).toContain(`Paged Finding ${String(i).padStart(2, "0")}`);
    }
  });
});
