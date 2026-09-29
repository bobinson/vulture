import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Feature 0096 — a target-report link that names an OWASP category but no
 * edition (a hand-typed `?owasp=A05`) never asks the server for a category
 * without an edition.
 *
 * A category id means different things in different editions, so the server
 * refuses a category query that does not name one. The page must first learn
 * which editions the rows carry, from an unfiltered request, and then filter
 * under the newest of them. A first request that sends the category alone is
 * refused, and the page never learns an edition to recover with.
 *
 * Every API call is mocked; nothing here needs a backend.
 */

const TARGET_KEY = "path:/home/user/work/shop";
const TARGET_KEY_ENC = encodeURIComponent(TARGET_KEY);

type Labels = Record<string, string[]>;

// The backend's shape: newest edition first, each with the categories its rows carry.
const LABEL_EDITIONS = [
  { framework: "owasp", edition: "2025", categories: ["A02", "A05", "A07"] },
  { framework: "owasp", edition: "2021", categories: ["A03", "A05", "A07"] },
];

function aggRow(over: Record<string, unknown>) {
  return {
    severity: "high",
    tier: "det",
    seen_count: 1,
    scan_count: 1,
    status: "open",
    first_seen_at: "2026-09-28T10:00:00Z",
    last_seen_at: "2026-09-28T10:00:00Z",
    last_event: "detected",
    line_start: 3,
    ...over,
  };
}

// A05 is Injection in 2025 and Security Misconfiguration in 2021: which row a
// bare `A05` selects depends entirely on the edition it is read under.
const AGG_ROWS = [
  aggRow({
    lineage_id: "lin-1", ref: "VLT-2001", category: "CWE-798",
    title: "Hardcoded credential", rel_path: "src/config.ts",
    compliance_labels: { "owasp:2025": ["A07"], "owasp:2021": ["A07"] },
  }),
  aggRow({
    lineage_id: "lin-2", ref: "VLT-2002", category: "CWE-89", severity: "critical",
    title: "SQL injection in query builder", rel_path: "src/db.go",
    compliance_labels: { "owasp:2025": ["A05"], "owasp:2021": ["A03"] },
  }),
  aggRow({
    lineage_id: "lin-3", ref: "VLT-2003", category: "CWE-16", severity: "medium",
    title: "Debug mode enabled in production config", rel_path: "config/app.yaml",
    compliance_labels: { "owasp:2025": ["A02"], "owasp:2021": ["A05"] },
  }),
];

function page(rows: unknown[]) {
  return {
    total: rows.length,
    page: 1,
    page_size: 50,
    tiles: { unique: rows.length, active: rows.length, unconfirmed: 0, fixed: 0, critical: 0 },
    rows,
    // Target-wide, whatever the page or filter holds (0096 M8).
    label_editions: LABEL_EDITIONS,
  };
}

/** The backend's contract: a category is matched under ONE framework:edition key. */
function aggregateBody(q: URLSearchParams): { status: number; body: unknown } {
  const framework = q.get("framework");
  const category = q.get("category");
  const edition = q.get("edition");
  if (!framework && !category && !edition) return { status: 200, body: page(AGG_ROWS) };
  if (framework !== "owasp" || !category || !edition) {
    return { status: 400, body: { error: "framework, category and edition are required together" } };
  }
  const key = `${framework}:${edition}`;
  return {
    status: 200,
    body: page(AGG_ROWS.filter((r) => ((r.compliance_labels as Labels)[key] ?? []).includes(category))),
  };
}

async function installMocks(p: Page): Promise<URLSearchParams[]> {
  const aggregateQueries: URLSearchParams[] = [];
  await p.addInitScript(() => {
    localStorage.setItem("vulture_token", "test-token-for-e2e");
  });
  await p.route(/\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

    if (path === "/api/auth/me") {
      return json({ id: "u1", email: "t@example.com", name: "T", role: "admin", created_at: "2026-01-01T00:00:00Z" });
    }
    if (path === `/api/targets/${TARGET_KEY_ENC}/aggregate`) {
      aggregateQueries.push(url.searchParams);
      const { status, body } = aggregateBody(url.searchParams);
      return json(body, status);
    }
    return json([]);
  });
  return aggregateQueries;
}

test.describe("0096 — a category deep link without an edition", () => {
  test("filters under the newest edition the rows carry, and never sends a category alone", async ({ page: p }) => {
    const queries = await installMocks(p);
    await p.goto(`/targets/${TARGET_KEY_ENC}?owasp=A05`);

    const aggRows = p.locator("[data-testid='aggregate-row']");
    // A05 under 2025 is Injection: the SQL injection row only.
    await expect(aggRows).toHaveCount(1, { timeout: 5000 });
    await expect(aggRows.first()).toContainText("VLT-2002");
    await expect(p.getByLabel("OWASP edition")).toHaveValue("2025");
    await expect(p.getByLabel("OWASP category")).toHaveValue("A05");

    expect(queries.length).toBeGreaterThan(0);
    for (const q of queries) {
      if (q.has("category")) expect(q.get("edition"), `query ${q.toString()}`).toBe("2025");
    }
    const last = queries[queries.length - 1];
    expect(last.get("framework")).toBe("owasp");
    expect(last.get("category")).toBe("A05");
    expect(last.get("edition")).toBe("2025");
  });
});
