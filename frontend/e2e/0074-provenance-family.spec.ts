import { test, expect, type Locator, type Page, type TestInfo } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Feature 0074 (RED) — tier-family provenance filter and read-only anchor
// result (plan §5.6, P2a T2.1/T2.2, P2b T2.5; AC10, AC39).
//
// Business contract pinned here:
//   (a) "LLM (all)" (llm_family) shows exactly the llm + llm_l5_verified rows.
//   (b) "Both tiers" (both) shows the rows whose validation.provenance_origins
//       spans the deterministic and the LLM families.
//   (c) AC10: a row's validation verdict renders identically whichever filter
//       reached it, and the per-audit false-positive count does not move.
//   (d) the finding detail shows 0076's anchor verdict and the claimed line
//       range read-only (no control); a deterministic row has no anchor row.
//   (e) the new labels exist in all six locales.
//   (f) pixel-perfect: the filter control and the anchor row match
//       frontend/designs/0074-provenance-family.html, rendered in the SAME
//       browser as the reference (never a screenshot of the implementation).
//   (g) speed: with 10,000 findings, switching to llm_family re-renders within
//       100 ms (measured in the page) and issues no network request.
//
// Every /api request is mocked; a catch-all answers anything unlisted with a
// 404 so no test can reach a live backend. Web fonts are blocked in both the
// mockup and the app, so both render with the same (fallback) face.

const AUDIT_ID = "audit-0074-family";
const DESIGNS = fileURLToPath(new URL("../designs/", import.meta.url));
const LOCALES_DIR = fileURLToPath(new URL("../src/i18n/locales/", import.meta.url));
const DESIGN_ORIGIN = "http://design.vulture.test";
const LOCALES = ["en", "es", "de", "fr", "ja", "pt"] as const;
const TITLE_CELLS = '[data-testid="findings-table"] tbody tr > td p[title]';
const SHOT = { animations: "disabled", caret: "hide" } as const;

type Json = Record<string, unknown>;

// ── fixtures (synthetic) ──────────────────────────────────────────────────

function finding(id: string, title: string, extra: Json): Json {
  return {
    id, agent_type: "cwe", severity: "medium", category: "CWE-78", title,
    description: `${title} description`, file_path: `src/${id}.py`,
    line_start: 10, line_end: 10, recommendation: "fix", fingerprint: `fp-${id}`,
    ...extra,
  };
}

function tiered(provenance: string | undefined, origins: string[] | undefined, status: string): Json {
  const validation = origins ? { provenance_origins: origins } : undefined;
  return { provenance, validation, validation_status: status };
}

const ANCHOR_VALIDATION = {
  provenance_origins: ["llm"],
  checks: [
    { id: "anchor", result: "reanchored", weight: 0, reason: "evidence quote: reanchored",
      extras: { claimed_line: 60, delta: -20, candidates: 1, claimed_line_range: "past_eof" } },
  ],
};

const UI_FINDINGS: Json[] = [
  finding("f1", "Skill only row", { severity: "critical", ...tiered("skill", ["skill"], "high_confidence") }),
  finding("f2", "LLM only row", { severity: "high", line_start: 40, line_end: 40,
    ...tiered("llm", undefined, "suspicious"), validation: ANCHOR_VALIDATION }),
  finding("f3", "L5 only row", tiered("llm_l5_verified", ["llm_l5_verified"], "likely_fp")),
  finding("f4", "Skill won merge row", { severity: "high", ...tiered("skill", ["skill", "llm"], "high_confidence") }),
  finding("f5", "LLM won merge row", { severity: "critical", ...tiered("llm", ["llm", "skill"], "suspicious") }),
  finding("f6", "L5 merged with skill row", { severity: "low", ...tiered("llm_l5_verified", ["skill", "llm_l5_verified"], "") }),
  finding("f7", "Same-agent LLM pair row", tiered("llm", ["llm", "llm_l5_verified"], "suspicious")),
  finding("f8", "Untagged legacy row", { severity: "low" }),
];

const LLM_FAMILY_TITLES = ["L5 merged with skill row", "L5 only row", "LLM only row", "LLM won merge row", "Same-agent LLM pair row"];
const BOTH_TITLES = ["L5 merged with skill row", "LLM won merge row", "Skill won merge row"];

function bigFindings(n: number): Json[] {
  const tiers = ["skill", "llm", "llm_l5_verified"];
  const severities = ["critical", "high", "medium", "low"];
  return Array.from({ length: n }, (_, i) => {
    const tier = tiers[i % 3];
    return finding(`b${i}`, `${tier} finding ${i}`, {
      severity: severities[i % 4], ...tiered(tier, i % 2 ? [tier, "skill"] : [tier], "high_confidence"),
    });
  });
}

// ── mocks ─────────────────────────────────────────────────────────────────

function json(body: unknown, status = 200) {
  return { status, contentType: "application/json", body: JSON.stringify(body) };
}

function auditBody(findings: Json[]): Json {
  const now = new Date().toISOString();
  return {
    id: AUDIT_ID, source_id: "src-0074", status: "completed", types: ["cwe"],
    findings, scores: { cwe: 70 }, created_at: now, completed_at: now,
  };
}

async function mockApi(page: Page, findings: Json[]) {
  // Registered first, so every specific route below takes precedence.
  await page.route("**/api/**", (route) => route.fulfill(json({ error: "not mocked" }, 404)));
  await page.route("**/api/auth/local-session", (route) => route.fulfill(json({ error: "not local mode" }, 404)));
  await page.route("**/api/auth/me", (route) => route.fulfill(json({
    id: "test-user-1", email: "test@example.com", name: "Test User", role: "admin",
    created_at: new Date().toISOString(),
  })));
  await page.route(`**/api/audits/${AUDIT_ID}`, (route) => route.fulfill(json(auditBody(findings))));
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, (route) => route.fulfill(json([])));
}

async function blockWebFonts(page: Page) {
  await page.route(/fonts\.(googleapis|gstatic)\.com/, (route) => route.abort());
}

async function openAudit(page: Page, findings: Json[], lng = "en") {
  await page.addInitScript((l) => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
    localStorage.setItem("i18nextLng", l);
  }, lng);
  await blockWebFonts(page);
  await mockApi(page, findings);
  await page.goto(`/audit/${AUDIT_ID}`);
  await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });
}

// ── page helpers ──────────────────────────────────────────────────────────

const chip = (page: Page, value: string) => page.getByTestId(`provenance-filter-${value}`);
const rowFor = (page: Page, title: string) =>
  page.locator('[data-testid="findings-table"] tbody tr').filter({ has: page.getByTitle(title, { exact: true }) });

async function visibleTitles(page: Page): Promise<string[]> {
  return (await page.locator(TITLE_CELLS).allTextContents()).sort();
}

async function selectFilter(page: Page, value: string) {
  await chip(page, value).click();
  await expect(chip(page, value)).toHaveAttribute("aria-pressed", "true");
}

async function rowTexts(page: Page, titles: string[]): Promise<string[]> {
  return Promise.all(titles.map((t) => rowFor(page, t).innerText()));
}

// ── pixel helpers ─────────────────────────────────────────────────────────

function designContentType(path: string): string {
  return path.endsWith(".css") ? "text/css" : "text/html";
}

// The mockup opens in a second page of the SAME browser context, so the
// reference is rendered by the same engine as the implementation.
async function openDesign(app: Page): Promise<Page> {
  const page = await app.context().newPage();
  await blockWebFonts(page);
  await page.route(`${DESIGN_ORIGIN}/**`, (route) => {
    const name = new URL(route.request().url()).pathname.replace(/^\//, "");
    return route.fulfill({ status: 200, contentType: designContentType(name), body: readFileSync(DESIGNS + name) });
  });
  await page.goto(`${DESIGN_ORIGIN}/0074-provenance-family.html`);
  return page;
}

async function settle(page: Page) {
  await page.mouse.move(0, 0);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
}

async function shot(locator: Locator): Promise<Buffer> {
  await expect(locator).toBeVisible();
  return locator.screenshot(SHOT);
}

async function subpixel(locator: Locator): Promise<{ x: number; y: number }> {
  const box = (await locator.boundingBox())!;
  return { x: box.x % 1, y: box.y % 1 };
}

// Firefox and WebKit rasterise at the element's fractional offset, so the same
// 20.5px-high box clips to 21 or 22 rows depending on where the page put it.
// Shift the REFERENCE by the phase difference so both are rasterised at the
// same sub-pixel phase; the implementation is never touched.
async function alignPhase(reference: Locator, actual: Locator) {
  const [r, a] = await Promise.all([subpixel(reference), subpixel(actual)]);
  await reference.evaluate((el, d) => {
    Object.assign((el as HTMLElement).style, { position: "relative", left: `${d.x}px`, top: `${d.y}px` });
  }, { x: a.x - r.x, y: a.y - r.y });
}

async function expectElementMatchesDesign(app: Page, testInfo: TestInfo, name: string, reference: Locator, actual: Locator) {
  await expect(actual).toBeVisible();
  await settle(app);
  await alignPhase(reference, actual);
  await expectMatchesDesign(app, testInfo, name, await shot(reference), await shot(actual));
}

function pngSize(png: Buffer): string {
  return `${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`;
}

// Fraction of pixels whose largest channel difference exceeds 24/255, computed
// in the page so no image library is needed. Same-size images only.
async function diffRatio(page: Page, a: Buffer, b: Buffer): Promise<number> {
  return page.evaluate(async ([a64, b64]) => {
    const pixels = async (b64png: string) => {
      const img = new Image();
      img.src = `data:image/png;base64,${b64png}`;
      await img.decode();
      const canvas = Object.assign(document.createElement("canvas"), { width: img.width, height: img.height });
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0);
      return ctx.getImageData(0, 0, img.width, img.height).data;
    };
    const [pa, pb] = await Promise.all([pixels(a64), pixels(b64)]);
    let off = 0;
    for (let i = 0; i < pa.length; i += 4) {
      const d = Math.max(Math.abs(pa[i] - pb[i]), Math.abs(pa[i + 1] - pb[i + 1]), Math.abs(pa[i + 2] - pb[i + 2]));
      off += d > 24 ? 1 : 0;
    }
    return off / (pa.length / 4);
  }, [a.toString("base64"), b.toString("base64")] as const);
}

async function expectMatchesDesign(page: Page, testInfo: TestInfo, name: string, design: Buffer, actual: Buffer) {
  await testInfo.attach(`${name}-design.png`, { body: design, contentType: "image/png" });
  await testInfo.attach(`${name}-app.png`, { body: actual, contentType: "image/png" });
  expect(pngSize(actual), `${name}: element size differs from the design`).toBe(pngSize(design));
  expect(await diffRatio(page, design, actual), `${name}: pixel diff ratio`).toBeLessThanOrEqual(0.01);
}

// ── locale helpers ────────────────────────────────────────────────────────

function localeValue(lng: string, path: string): string {
  const tree = JSON.parse(readFileSync(`${LOCALES_DIR}${lng}.json`, "utf8")) as unknown;
  const value = path.split(".").reduce<unknown>((n, k) => (n && typeof n === "object" ? (n as Json)[k] : undefined), tree);
  return typeof value === "string" && value.trim() ? value : `<missing ${path} in ${lng}.json>`;
}

// ═══════════════════════════════════════════════════════════════════════════

test.describe("0074 tier-family provenance filter", () => {
  test("(a) LLM (all) shows exactly the llm and llm_l5_verified rows — AC39", async ({ page }) => {
    await openAudit(page, UI_FINDINGS);
    await expect(chip(page, "llm_family")).toHaveText("LLM (all)");
    await selectFilter(page, "llm_family");
    await expect.poll(() => visibleTitles(page)).toEqual(LLM_FAMILY_TITLES);
    // The exact tiers keep their exact meaning (0058).
    await selectFilter(page, "llm");
    await expect.poll(() => visibleTitles(page)).toEqual(["LLM only row", "LLM won merge row", "Same-agent LLM pair row"]);
    await selectFilter(page, "all");
    await expect.poll(async () => (await visibleTitles(page)).length).toBe(UI_FINDINGS.length);
  });

  test("(b) Both tiers shows the rows whose provenance_origins spans both families — AC39", async ({ page }) => {
    await openAudit(page, UI_FINDINGS);
    await expect(chip(page, "both")).toHaveText("Both tiers");
    await selectFilter(page, "both");
    await expect.poll(() => visibleTitles(page)).toEqual(BOTH_TITLES);
  });

  for (const value of ["llm_family", "both"] as const) {
    test(`(c) ${value} leaves every row's validation verdict and the FP count unchanged — AC10`, async ({ page }) => {
      await openAudit(page, UI_FINDINGS);
      const kept = value === "both" ? BOTH_TITLES : LLM_FAMILY_TITLES;
      const fpSwitch = page.getByRole("switch", { name: /hide false positives/i });
      const before = await rowTexts(page, kept);
      const fpBefore = await fpSwitch.innerText();
      await selectFilter(page, value);
      await expect.poll(() => visibleTitles(page)).toEqual(kept);
      expect(await rowTexts(page, kept)).toEqual(before);
      expect(await fpSwitch.innerText()).toBe(fpBefore);
      await expect(rowFor(page, "LLM won merge row")).toContainText("Suspicious");
    });
  }

  test("(d) the finding detail shows the anchor result read-only — T2.2", async ({ page }) => {
    await openAudit(page, UI_FINDINGS);
    await page.getByTitle("LLM only row", { exact: true }).click();
    const anchor = page.getByTestId("anchor-result");
    await expect(anchor).toBeVisible();
    await expect(anchor).toContainText("Anchor:");
    await expect(anchor.getByTestId("anchor-status")).toHaveText("Re-anchored");
    await expect(anchor.getByTestId("anchor-range")).toHaveText("Past end of file");
    await expect(anchor.getByTestId("anchor-line")).toHaveText("L60 → L40");
    await expect(anchor.locator("button, input, select, textarea, a[href], [role=button]")).toHaveCount(0);
    // A deterministic row carries no anchor check, so no anchor row at all.
    await page.getByTitle("Skill only row", { exact: true }).click();
    await expect(page.getByTestId("anchor-result")).toHaveCount(0);
  });

  for (const lng of LOCALES) {
    test(`(e) the 0074 labels are translated in ${lng} — T2.2`, async ({ page }) => {
      await openAudit(page, UI_FINDINGS, lng);
      await expect(chip(page, "llm_family")).toHaveText(localeValue(lng, "results.provenanceFamily.llm_family"));
      await expect(chip(page, "both")).toHaveText(localeValue(lng, "results.provenanceFamily.both"));
      await page.getByTitle("LLM only row", { exact: true }).click();
      const anchor = page.getByTestId("anchor-result");
      await expect(anchor).toContainText(localeValue(lng, "results.anchor.title"));
      await expect(anchor.getByTestId("anchor-status")).toHaveText(localeValue(lng, "results.anchor.status.reanchored"));
      await expect(anchor.getByTestId("anchor-range")).toHaveText(localeValue(lng, "results.anchor.range.past_eof"));
    });
  }
});

test.describe("0074 pixel parity with the design mockup", () => {
  for (const state of ["all", "llm_family", "both"] as const) {
    test(`(f) the provenance filter (${state} selected) matches the design`, async ({ page }, testInfo) => {
      await openAudit(page, UI_FINDINGS);
      await selectFilter(page, state);
      const design = await openDesign(page);
      const reference = design.locator(`[data-testid="provenance-filter"][data-state="${state}"]`);
      await expectElementMatchesDesign(page, testInfo, `provenance-filter-${state}`, reference, page.getByTestId("provenance-filter"));
    });
  }

  test("(f) the anchor result row matches the design", async ({ page }, testInfo) => {
    await openAudit(page, UI_FINDINGS);
    await page.getByTitle("LLM only row", { exact: true }).click();
    const design = await openDesign(page);
    await expectElementMatchesDesign(page, testInfo, "anchor-result", design.getByTestId("anchor-result"), page.getByTestId("anchor-result"));
  });
});

test.describe("0074 filter speed", () => {
  test("(g) switching 10,000 findings to LLM (all) re-renders within 100 ms with no request", async ({ page }) => {
    const requests: string[] = [];
    page.on("request", (r) => requests.push(r.url()));
    await openAudit(page, bigFindings(10_000));
    await expect(chip(page, "llm_family")).toBeVisible();
    // Warm the path once (JIT, lazy chunks) so the budget measures the filter.
    await selectFilter(page, "skill");
    await selectFilter(page, "all");
    await page.waitForLoadState("networkidle");
    const sent = requests.length;

    const run = await page.evaluate(async (sel) => {
      const btn = document.querySelector<HTMLButtonElement>('[data-testid="provenance-filter-llm_family"]');
      performance.mark("0074-llm-family-start");
      btn?.click();
      await new Promise((r) => requestAnimationFrame(() => r(null)));
      performance.mark("0074-llm-family-end");
      const titles = Array.from(document.querySelectorAll(sel), (p) => p.textContent ?? "");
      return {
        ms: performance.measure("0074-llm-family", "0074-llm-family-start", "0074-llm-family-end").duration,
        pressed: btn?.getAttribute("aria-pressed") === "true",
        rows: titles.length,
        onlyLlm: titles.every((t) => t.startsWith("llm")),
      };
    }, TITLE_CELLS);

    expect(run.pressed, "the llm_family chip exists and is selected").toBe(true);
    expect(run.rows, "a page of rows rendered").toBeGreaterThan(0);
    expect(run.onlyLlm, "the re-render is complete inside the measured window").toBe(true);
    expect(run.ms, "llm_family re-render budget (ms)").toBeLessThan(100);
    await page.waitForLoadState("networkidle");
    expect(requests.slice(sent), "filtering is client-side: no request").toEqual([]);
  });
});
