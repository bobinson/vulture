import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Feature 0096 follow-up — OWASP coverage does not count findings a person
 * triaged as false positives.
 *
 * On a mapping-mode audit the backend serves the EFFECTIVE coverage manifest,
 * computed when the audit is read: per category, found_cwes / found_count leave
 * out the findings whose own lineage row is `false_positive`, and an additive
 * `false_positive_count` says how many distinct findings of the category were
 * triaged so. The card must:
 *
 *   - note, on a category with false_positive_count > 0, how many findings were
 *     marked false positive;
 *   - read a category found ONLY through false positives as not found, with
 *     that note — never as a green hit;
 *   - update without a page reload when a status is saved in the findings
 *     table, because the backend recounts on the next read.
 *
 * Every API call is mocked; nothing here needs a backend.
 */

const AUDIT_ID = "audit-0096-fpcov";
const EDITION = "2025";

const label = (id: string, name: string, cwe: string) => ({
  framework: "owasp", edition: EDITION, category_id: id, category_name: name, cwe,
});

function finding(id: string, title: string, category: string, labels: unknown[]) {
  return {
    id, agent_type: "cwe", severity: "high", category, title,
    description: title, recommendation: "fix", file_path: `src/${id}.ts`,
    line_start: 3, line_end: 3, fingerprint: `v1-${id}`, fingerprint_v2: `v2-${id}`,
    compliance_labels: labels,
  };
}

const FINDINGS = [
  finding("cred", "Hardcoded credential", "CWE-798", [label("A07", "Authentication Failures", "CWE-798")]),
  finding("sqli", "SQL injection", "CWE-89", [label("A05", "Injection", "CWE-89")]),
  finding("sqli2", "SQL injection in report", "CWE-89", [label("A05", "Injection", "CWE-89")]),
];

function lineageRow(findingId: string, status: string) {
  return {
    id: `l-${findingId}`, ref_number: 100, agent_type: "cwe", current_status: status,
    fingerprint: `v1-${findingId}`, fingerprint_v2: `v2-${findingId}`,
    source_path: "/work/fpcov", first_audit_id: AUDIT_ID, first_found_at: "2026-09-01T00:00:00Z",
    severity: "high", category: "CWE", title: "t", file_path: "f", notes: "",
    created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
  };
}

function category(id: string, name: string, found: string[], falsePositives: number, extra: Record<string, unknown> = {}) {
  return {
    id, name, mapped_count: 36, found_cwes: found, found_count: found.length,
    status: found.length > 0 ? "found" : "clean-or-undetected",
    source_url: `https://owasp.org/Top10/${id}`, false_positive_count: falsePositives, ...extra,
  };
}

/** The manifest the backend serves for a given set of triaged finding ids. */
function effectiveCoverage(triaged: ReadonlySet<string>) {
  const a05Live = ["sqli", "sqli2"].filter((f) => !triaged.has(f));
  const a05Fp = 2 - a05Live.length;
  return {
    edition: EDITION,
    cwe_stage_status: "completed",
    categories: [
      category("A01", "Broken Access Control", [], 0),
      category("A05", "Injection", a05Live.length > 0 ? ["CWE-89"] : [], a05Fp),
      category("A07", "Authentication Failures", triaged.has("cred") ? [] : ["CWE-798"], triaged.has("cred") ? 1 : 0),
    ],
  };
}

interface Mocks {
  auditReads: () => number;
  patches: () => { id: string; status: string }[];
}

/**
 * `initial` is the set of findings triaged false positive when the page opens.
 * A PATCH of a lineage row changes it, and every later audit read serves the
 * recount — as the backend does.
 */
async function installMocks(page: Page, initial: string[]): Promise<Mocks> {
  const triaged = new Set(initial);
  let reads = 0;
  const patches: { id: string; status: string }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await page.route(/\/api\//, async (route: Route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const json = (body: unknown) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
    }
    if (path.endsWith("/stream-token")) return json({ stream_token: "tok" });
    if (path.endsWith("/stream")) {
      return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    }
    if (path === `/api/audits/${AUDIT_ID}/lineage`) {
      return json(FINDINGS.map((f) => lineageRow(f.id, triaged.has(f.id) ? "false_positive" : "open")));
    }
    const patch = /^\/api\/lineage\/l-([a-z0-9]+)$/.exec(path);
    if (patch && req.method() === "PATCH") {
      const { status } = JSON.parse(req.postData() ?? "{}") as { status: string };
      patches.push({ id: patch[1], status });
      if (status === "false_positive") triaged.add(patch[1]);
      else triaged.delete(patch[1]);
      return json(lineageRow(patch[1], status));
    }
    if (path === `/api/audits/${AUDIT_ID}`) {
      reads++;
      const now = new Date().toISOString();
      return json({
        id: AUDIT_ID, source_id: "src-1", status: "completed", types: ["cwe", "owasp"],
        created_at: now, completed_at: now, scores: { cwe: 60, owasp: 80 },
        config: { owasp: { edition: EDITION } },
        findings: FINDINGS,
        owasp_coverage: effectiveCoverage(triaged),
      });
    }
    return json([]);
  });
  return { auditReads: () => reads, patches: () => patches };
}

const card = (page: Page) => page.locator("[data-testid='owasp-coverage']");
const categoryRow = (page: Page, id: string) => card(page).locator("li").filter({ hasText: `${id} ` });
const fpNote = (page: Page, id: string) => page.locator(`[data-testid='owasp-coverage-fp-${id}']`);
const findingRow = (page: Page, title: string) =>
  page.locator("[data-testid='findings-table'] tbody tr").filter({ hasText: title }).first();

async function triage(page: Page, title: string, status: string) {
  await findingRow(page, title).click();
  const panel = page.locator("[data-testid='findings-table'] tbody tr").filter({ hasText: "Finding Traceability" }).first();
  await panel.locator("select").first().selectOption(status);
  await panel.getByRole("button", { name: "Save", exact: true }).click();
}

test.describe("0096 follow-up — OWASP coverage leaves out triaged false positives", () => {
  test("a category shows how many of its findings were marked false positive", async ({ page }) => {
    await installMocks(page, ["sqli", "cred"]);
    await page.goto(`/audit/${AUDIT_ID}`);

    // A05 keeps one untriaged finding: still found, with a note for the other.
    await expect(categoryRow(page, "A05")).toContainText("1 / 36", { timeout: 10000 });
    await expect(fpNote(page, "A05")).toHaveText("1 marked false positive");
    await expect(categoryRow(page, "A05")).toContainText("1 marked false positive");

    // A07's only finding is triaged: not found, and the note says why.
    await expect(categoryRow(page, "A07")).toContainText("0 / 36");
    await expect(fpNote(page, "A07")).toHaveText("1 marked false positive");

    // No note where nothing was triaged.
    await expect(fpNote(page, "A01")).toHaveCount(0);
    // One of three categories found.
    await expect(card(page)).toContainText("1/3");
  });

  test("the note counts every triaged finding of the category", async ({ page }) => {
    await installMocks(page, ["sqli", "sqli2"]);
    await page.goto(`/audit/${AUDIT_ID}`);

    await expect(categoryRow(page, "A05")).toContainText("0 / 36", { timeout: 10000 });
    await expect(fpNote(page, "A05")).toHaveText("2 marked false positive");
    await expect(fpNote(page, "A07")).toHaveCount(0);
    await expect(categoryRow(page, "A07")).toContainText("1 / 36");
  });

  test("marking a finding false positive updates the card without a reload", async ({ page }) => {
    const mocks = await installMocks(page, []);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(categoryRow(page, "A07")).toContainText("1 / 36", { timeout: 10000 });
    await expect(fpNote(page, "A07")).toHaveCount(0);
    await expect(card(page)).toContainText("2/3");

    // A reload would drop this marker.
    await page.evaluate(() => { (window as unknown as { __noReload: boolean }).__noReload = true; });
    const readsBefore = mocks.auditReads();

    await triage(page, "Hardcoded credential", "false_positive");

    // The click resolves before the PATCH reaches the route handler: poll the log.
    await expect.poll(() => mocks.patches()).toEqual([{ id: "cred", status: "false_positive" }]);
    await expect(categoryRow(page, "A07")).toContainText("0 / 36");
    await expect(fpNote(page, "A07")).toHaveText("1 marked false positive");
    await expect(card(page)).toContainText("1/3");
    expect(mocks.auditReads()).toBeGreaterThan(readsBefore);
    expect(await page.evaluate(() => (window as unknown as { __noReload?: boolean }).__noReload)).toBe(true);
  });

  test("un-marking a false positive restores the count", async ({ page }) => {
    await installMocks(page, ["cred"]);
    await page.goto(`/audit/${AUDIT_ID}`);
    await expect(categoryRow(page, "A07")).toContainText("0 / 36", { timeout: 10000 });
    await expect(fpNote(page, "A07")).toHaveText("1 marked false positive");

    await triage(page, "Hardcoded credential", "open");

    await expect(categoryRow(page, "A07")).toContainText("1 / 36");
    await expect(fpNote(page, "A07")).toHaveCount(0);
  });
});
