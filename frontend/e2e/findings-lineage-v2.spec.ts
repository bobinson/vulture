import { test, expect, type Page } from "@playwright/test";

// The findings table resolves each finding to its lineage row the way the
// backend lineage writer does: fingerprint_v2 first (within the agent type),
// the v1 fingerprint as the fallback. Before this, the table matched on v1
// alone, so a finding the backend had matched through v2 — an OWASP
// re-mapping, a rescan under a new mount — showed "—" for its ref and status,
// and its triage (false_positive, accepted_risk) was invisible and ignored by
// the "hide false positives" toggle.

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

const AUDIT_ID = "audit-lineage-v2";

function finding(id: string, title: string, agent: string, fingerprint: string, fingerprintV2?: string) {
  return {
    id, agent_type: agent, severity: "high", category: "secrets", title,
    description: title, file_path: `src/${id}.ts`, line_start: 10, line_end: 10,
    recommendation: "fix", validation_status: "high_confidence",
    fingerprint, ...(fingerprintV2 ? { fingerprint_v2: fingerprintV2 } : {}),
  };
}

const FINDINGS = [
  // Reached only through v2: its v1 is not the row's v1.
  finding("f-remap", "OWASP Remapped Secret", "owasp", "v1-new-remap", "v2-remap"),
  // Two findings sharing one v1 but resolving through v2 to DIFFERENT rows —
  // one dismissed, one still open. A v1-keyed lookup conflates them.
  finding("f-shared-a", "Shared V1 Dismissed", "owasp", "v1-shared", "v2-shared-a"),
  finding("f-shared-b", "Shared V1 Still Open", "owasp", "v1-shared", "v2-shared-b"),
  // A row that predates v2: the v1 fallback must keep working.
  finding("f-legacy", "Legacy V1 Only", "cwe", "v1-legacy"),
  // Same v2 as the OWASP row, different agent: not that row's finding.
  finding("f-twin", "CWE Twin Of Remap", "cwe", "v1-cwe-twin", "v2-remap"),
];

function lineage(id: string, ref: number, agent: string, status: string, fingerprint: string, fingerprintV2?: string) {
  return {
    id, ref_number: ref, agent_type: agent, current_status: status, fingerprint,
    ...(fingerprintV2 ? { fingerprint_v2: fingerprintV2 } : {}),
    source_path: "/work/app", first_audit_id: "audit-earlier", first_found_at: "2026-09-01T00:00:00Z",
    severity: "high", category: "secrets", title: "t", file_path: "f", notes: "",
    created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
  };
}

const LINEAGE = [
  lineage("l-remap", 4242, "owasp", "false_positive", "v1-old-remap", "v2-remap"),
  lineage("l-shared-a", 5001, "owasp", "false_positive", "v1-old-a", "v2-shared-a"),
  lineage("l-shared-b", 5002, "owasp", "open", "v1-shared", "v2-shared-b"),
  lineage("l-legacy", 6001, "cwe", "accepted_risk", "v1-legacy"),
];

async function mockAudit(page: Page) {
  await page.route(`**/api/audits/${AUDIT_ID}`, async (route) => {
    if (route.request().url().includes("/stream")) return route.continue();
    await route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        id: AUDIT_ID, source_id: "src-1", status: "completed", types: ["owasp", "cwe"],
        findings: FINDINGS, scores: { owasp: 60, cwe: 70 },
        created_at: new Date().toISOString(), completed_at: new Date().toISOString(),
      }),
    });
  });
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(LINEAGE) });
  });
}

const row = (page: Page, title: string) => page.locator("tbody tr", { hasText: title });

test.describe("Findings table resolves lineage by fingerprint_v2", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);
    await mockAudit(page);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(row(page, "OWASP Remapped Secret")).toBeVisible({ timeout: 5000 });
  });

  test("a finding matched only through v2 shows its ref and triage status", async ({ page }) => {
    const r = row(page, "OWASP Remapped Secret");
    await expect(r).toContainText("VLT-4242");
    await expect(r).toContainText("False Positive");
  });

  test("v2 decides between rows when findings share a v1", async ({ page }) => {
    await expect(row(page, "Shared V1 Dismissed")).toContainText("VLT-5001");
    await expect(row(page, "Shared V1 Dismissed")).toContainText("False Positive");
    await expect(row(page, "Shared V1 Still Open")).toContainText("VLT-5002");
    await expect(row(page, "Shared V1 Still Open")).toContainText("Open");
  });

  test("a row without v2 still resolves through v1", async ({ page }) => {
    await expect(row(page, "Legacy V1 Only")).toContainText("VLT-6001");
    await expect(row(page, "Legacy V1 Only")).toContainText("Accepted Risk");
  });

  test("a v2 match under another agent type is not the finding's row", async ({ page }) => {
    const r = row(page, "CWE Twin Of Remap");
    await expect(r).not.toContainText("VLT-");
    await expect(r).not.toContainText("False Positive");
  });

  test("hide false positives hides exactly the findings whose OWN row is dismissed", async ({ page }) => {
    const toggle = page.getByRole("switch", { name: /hide false positives \(2\)/i });
    await expect(toggle).toBeVisible();
    await toggle.click();

    await expect(row(page, "OWASP Remapped Secret")).toHaveCount(0);
    await expect(row(page, "Shared V1 Dismissed")).toHaveCount(0);
    // Shares Dismissed's v1 but its own row is open: it must stay.
    await expect(row(page, "Shared V1 Still Open")).toBeVisible();
    await expect(row(page, "Legacy V1 Only")).toBeVisible();
    await expect(row(page, "CWE Twin Of Remap")).toBeVisible();
  });

  test("the detail panel shows the v2-matched row's traceability", async ({ page }) => {
    await row(page, "OWASP Remapped Secret").click();
    await expect(page.getByText("Finding Traceability")).toBeVisible();
    await expect(page.getByText("No traceability data")).toHaveCount(0);
  });
});
