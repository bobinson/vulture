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
        email: "test@vulture.dev",
        name: "Test User",
        role: "admin",
        created_at: new Date().toISOString(),
      }),
    });
  });
}

const baseFinding = {
  id: "f-prove-1",
  audit_id: "audit-prove-1",
  agent_type: "owasp",
  severity: "high",
  category: "injection",
  title: "SQL Injection in Login",
  description: "User input is concatenated directly into SQL query without parameterization",
  file_path: "src/db/queries.py",
  line_start: 42,
  line_end: 48,
  code_snippet: "query = 'SELECT * FROM users WHERE name = ' + user_input",
  recommendation: "Use parameterized queries with prepared statements",
  compliance_ref: "CC6.1",
  fingerprint: "fp-abc123",
};

const baseProveResult = {
  id: "pr-1",
  audit_id: "audit-prove-1",
  finding_id: "f-prove-1",
  status: "verified",
  evidence: "Successfully exploited via payload: ' OR 1=1 --",
  iterations_used: 3,
  staging_url: "http://staging.example.com:8080",
  created_at: new Date().toISOString(),
};

const lineageData = {
  id: "lin-1",
  fingerprint: "fp-abc123",
  source_path: "/src/project",
  agent_type: "owasp",
  current_status: "open",
  notes: "",
  ticket_url: "",
  first_audit_id: "audit-prev-1",
  first_found_at: "2025-12-01T10:00:00Z",
  first_commit: "abc1234567890",
  latest_audit_id: "audit-prove-1",
  latest_found_at: new Date().toISOString(),
  latest_commit: "def4567890123",
  severity: "high",
  category: "injection",
  title: "SQL Injection in Login",
  file_path: "src/db/queries.py",
  created_at: "2025-12-01T10:00:00Z",
  updated_at: new Date().toISOString(),
};

const timelineEvents = [
  {
    id: "evt-1",
    lineage_id: "lin-1",
    event_type: "detected",
    audit_id: "audit-prev-1",
    git_commit: "abc1234567890",
    created_at: "2025-12-01T10:00:00Z",
  },
  {
    id: "evt-2",
    lineage_id: "lin-1",
    event_type: "detected",
    audit_id: "audit-prove-1",
    git_commit: "def4567890123",
    created_at: new Date().toISOString(),
  },
];

function mockAuditEndpoints(page: Page, auditId: string, lineage: unknown[] = [lineageData]) {
  // Mock lineage endpoint (register first — more specific path)
  const lineagePromise = page.route(`**/api/audits/${auditId}/lineage`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(lineage),
    });
  });

  // Mock audit endpoint
  const auditPromise = page.route(`**/api/audits/${auditId}`, async (route) => {
    const url = route.request().url();
    if (url.includes("/stream")) return route.continue();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: auditId,
        source_id: "src-1",
        status: "completed",
        types: ["owasp"],
        findings: [baseFinding],
        prove_results: [baseProveResult],
        scores: { owasp: 65 },
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      }),
    });
  });

  return Promise.all([lineagePromise, auditPromise]);
}

function mockClipboard(page: Page) {
  return page.addInitScript(() => {
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

test.describe("Prove Results — Enhanced UI", () => {
  test("renders lineage badges when data exists", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);

    await page.goto(`/audit/${auditId}`);

    // ProveResults section should appear
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // The prove status badge should be visible
    await expect(page.locator("text=Verified").first()).toBeVisible();

    // Finding title should be visible in the prove results
    await expect(page.locator("text=SQL Injection in Login").first()).toBeVisible();
  });

  test("expanding result shows finding description and evidence", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Click "Show evidence" to expand the prove result
    await page.getByText("Show evidence").click();

    // Should show the evidence text
    await expect(page.getByText("Successfully exploited via payload")).toBeVisible();

    // Should show finding description section
    await expect(page.getByText("User input is concatenated directly")).toBeVisible();

    // Should show recommendation
    await expect(page.getByText("Use parameterized queries with prepared statements")).toBeVisible();
  });

  test("copy button generates markdown with description, evidence, prove status", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);
    await mockClipboard(page);

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Click the row copy button (inline copy icon)
    const copyBtn = page.locator("[data-testid='prove-copy-btn']").first();
    await copyBtn.click();

    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    expect(texts.length).toBe(1);
    const md = texts[0];

    // Should include finding metadata
    expect(md).toContain("## [HIGH] SQL Injection in Login");
    expect(md).toContain("| Severity | high |");
    expect(md).toContain("| Category | injection |");

    // Should include prove-specific info
    expect(md).toContain("| Verification | verified |");
    expect(md).toContain("| Iterations | 3 |");

    // Should include description and evidence
    expect(md).toContain("### Description");
    expect(md).toContain("User input is concatenated directly");
    expect(md).toContain("### Reproduction Steps");
    expect(md).toContain("Successfully exploited via payload");
  });

  test("copy all button copies all prove results as markdown", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);
    await mockClipboard(page);

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Click Copy All button specifically in the ProveResults section (near "Verification Results" heading)
    const proveSection = page.locator("text=Verification Results").locator("..");
    await proveSection.getByRole("button", { name: /copy all/i }).click();

    const texts = await page.evaluate(() => (window as unknown as Record<string, string[]>).__clipboardTexts);
    expect(texts.length).toBeGreaterThanOrEqual(1);
    const md = texts[texts.length - 1];

    expect(md).toContain("## [HIGH] SQL Injection in Login");
    expect(md).toContain("### Reproduction Steps");
  });

  test("expanded result shows lineage commit history", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Expand the result
    await page.getByText("Show evidence").click();

    // Lineage section should show commit info
    await expect(page.getByText("abc1234").first()).toBeVisible({ timeout: 5000 });
  });

  test("lineage status can be changed and saved", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-1";
    await mockAuditEndpoints(page, auditId);

    // Mock the update endpoint
    await page.route("**/api/lineage/lin-1", async (route) => {
      if (route.request().method() === "PATCH") {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...lineageData, current_status: body.status }),
        });
        return;
      }
      await route.continue();
    });

    // Mock timeline
    await page.route("**/api/lineage/lin-1/timeline", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(timelineEvents),
      });
    });

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Expand the result
    await page.getByText("Show evidence").click();

    // Should see the status dropdown in lineage section
    const statusSelect = page.locator("select").first();
    await expect(statusSelect).toBeVisible({ timeout: 5000 });

    // Change status
    await statusSelect.selectOption("in_progress");

    // Click save
    await page.getByRole("button", { name: /save/i }).first().click();

    // Should show saved feedback
    await expect(page.getByText("Saved").first()).toBeVisible({ timeout: 5000 });
  });

  test("fixed findings show commit and date data", async ({ page }) => {
    await mockAuth(page);
    const auditId = "audit-prove-fixed";

    const fixedLineage = {
      ...lineageData,
      current_status: "fixed",
      fixed_commit: "fix9876543210",
      fixed_at: "2026-01-15T12:00:00Z",
      fixed_audit_id: "audit-fix-1",
    };

    // Mock lineage endpoint (register first — more specific path)
    await page.route(`**/api/audits/${auditId}/lineage`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([fixedLineage]),
      });
    });

    // Mock audit endpoint
    await page.route(`**/api/audits/${auditId}`, async (route) => {
      const url = route.request().url();
      if (url.includes("/stream")) return route.continue();
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: auditId,
          source_id: "src-1",
          status: "completed",
          types: ["owasp"],
          findings: [baseFinding],
          prove_results: [{ ...baseProveResult, audit_id: auditId, status: "not_reproduced" }],
          scores: { owasp: 85 },
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto(`/audit/${auditId}`);
    await expect(page.locator("text=Verification Results")).toBeVisible({ timeout: 5000 });

    // Expand to see lineage
    await page.getByText("Show evidence").click();

    // Should show fixed commit
    await expect(page.getByText("fix9876").first()).toBeVisible({ timeout: 5000 });
  });
});
