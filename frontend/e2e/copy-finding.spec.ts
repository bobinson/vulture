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

const findingWithCode = {
  id: "f1",
  audit_id: "audit-copy-1",
  agent_type: "owasp",
  severity: "critical",
  category: "injection",
  title: "SQL Injection Vulnerability",
  description: "Unparameterized query allows SQL injection",
  file_path: "db.py",
  line_start: 5,
  line_end: 10,
  code_snippet: "SELECT * FROM users WHERE id = ' + input",
  recommendation: "Use parameterized queries",
  compliance_ref: "CC6.1",
};

const findingWithoutOptionals = {
  id: "f2",
  severity: "high",
  category: "retry",
  title: "Missing Retry Logic",
  description: "HTTP call without retry",
  file_path: "main.go",
  recommendation: "Add retry with exponential backoff",
};

function mockAudit(page: Page, auditId: string) {
  return page.route(`**/api/audits/${auditId}`, async (route) => {
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
        types: ["owasp"],
        findings: [findingWithCode, findingWithoutOptionals],
        scores: { owasp: 65 },
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      }),
    });
  });
}

test.describe("Copy Finding as Issue", () => {
  test("Copy as Issue button appears in expanded finding row", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-1";
    await mockAudit(page, auditId);

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=SQL Injection Vulnerability")).toBeVisible({ timeout: 5000 });

    // Expand the first finding row
    await page.locator("text=SQL Injection Vulnerability").click();

    // The copy button should appear in the expanded row
    await expect(page.getByRole("button", { name: /copy as issue/i })).toBeVisible();
  });

  test("Copy as Issue generates correct markdown", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-1";
    await mockAudit(page, auditId);

    // Mock clipboard API. The captured texts live in page context as
    // window.__clipboardTexts (Node-side mirror not needed — assertions
    // read via page.evaluate).
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

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=SQL Injection Vulnerability")).toBeVisible({ timeout: 5000 });

    // Expand finding and click copy
    await page.locator("text=SQL Injection Vulnerability").click();
    await page.getByRole("button", { name: /copy as issue/i }).click();

    // Retrieve clipboard content
    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    expect(texts.length).toBe(1);
    const md = texts[0];

    // Verify markdown structure
    expect(md).toContain("## [CRITICAL] SQL Injection Vulnerability");
    expect(md).toContain("| Severity | critical |");
    expect(md).toContain("| Category | injection |");
    expect(md).toContain("| File | `db.py:5-10` |");
    expect(md).toContain("| Agent | OWASP |");
    expect(md).toContain("| Audit | audit-copy-1 |");
    expect(md).toContain("| Compliance | CC6.1 |");
    expect(md).toContain("### Description");
    expect(md).toContain("Unparameterized query allows SQL injection");
    expect(md).toContain("### Recommendation");
    expect(md).toContain("Use parameterized queries");
  });

  test("Copy as Issue shows copied feedback", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-1";
    await mockAudit(page, auditId);

    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: () => Promise.resolve() },
        writable: true,
      });
    });

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=SQL Injection Vulnerability")).toBeVisible({ timeout: 5000 });

    // Expand and copy
    await page.locator("text=SQL Injection Vulnerability").click();
    await page.getByRole("button", { name: /copy as issue/i }).click();

    // Should show "Copied!" feedback
    await expect(page.getByText("Copied!")).toBeVisible();
  });

  test("Copy All button copies all findings", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-1";
    await mockAudit(page, auditId);

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

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=SQL Injection Vulnerability")).toBeVisible({ timeout: 5000 });

    // Click Copy All button
    await page.getByRole("button", { name: /copy all as issues/i }).click();

    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    expect(texts.length).toBe(1);
    const md = texts[0];

    // Should contain both findings separated by ---
    expect(md).toContain("## [CRITICAL] SQL Injection Vulnerability");
    expect(md).toContain("## [HIGH] Missing Retry Logic");
    expect(md).toContain("\n---\n");
  });

  test("Copy as Issue includes code snippet when present", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-1";
    await mockAudit(page, auditId);

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

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=SQL Injection Vulnerability")).toBeVisible({ timeout: 5000 });

    // Expand finding with code snippet and copy
    await page.locator("text=SQL Injection Vulnerability").click();
    await page.getByRole("button", { name: /copy as issue/i }).click();

    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    const md = texts[0];

    expect(md).toContain("### Code");
    expect(md).toContain("```");
    expect(md).toContain("SELECT * FROM users WHERE id = ' + input");
  });

  test("Copy as Issue omits optional fields when absent", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-copy-2";

    // Audit with only the minimal finding
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
          findings: [findingWithoutOptionals],
          scores: { chaos: 80 },
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        }),
      });
    });

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

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Missing Retry Logic")).toBeVisible({ timeout: 5000 });

    // Expand finding and copy
    await page.locator("text=Missing Retry Logic").click();
    await page.getByRole("button", { name: /copy as issue/i }).click();

    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    const md = texts[0];

    // Should NOT have code section or compliance (audit ID comes from page URL, always present)
    expect(md).not.toContain("### Code");
    expect(md).not.toContain("Compliance");
    // Should have the basics
    expect(md).toContain("## [HIGH] Missing Retry Logic");
    expect(md).toContain("| File | `main.go` |");
    expect(md).toContain("### Description");
    expect(md).toContain("### Recommendation");
  });
});
