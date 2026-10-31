import { test, expect, type Page, type Request, type Route } from "@playwright/test";

// Feature 0102: the browser session is an HttpOnly cookie set by the server.
// The SPA keeps no credential in Web Storage, sends X-Vulture-CSRF on every
// fetch (never an Authorization header), boots with me() and only then a local
// session, and signs out only once the server has confirmed it: the SPA cannot
// delete an HttpOnly cookie, so a failed logout must keep the session visible
// and offer a retry instead of showing /login over a cookie that still works.

const CSRF = "x-vulture-csrf";
const LEGACY_KEY = "vulture_token";
// A JWT-shaped legacy value, so a test can prove it never leaves the browser.
const LEGACY_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWdhY3ktdXNlciJ9.bGVnYWN5LXNpZ25hdHVyZQ";
const USER = {
  id: "test-user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};
const AUDIT_ID = "audit-session-cookie";
const STREAM_TOKEN = "stream-token-session-e2e";
const STREAM_URL = new RegExp(`/api/audits/${AUDIT_ID}/stream\\?`);
const LOGOUT_URL = "**/api/auth/logout";
const CREDENTIAL_KEY = /token|jwt|session/i;

type Answer = (route: Route) => Promise<void>;

function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

// 200 answers with the body, anything else with an error object.
function fulfillStatus(route: Route, status: number, body: unknown, error: string): Promise<void> {
  return status === 200 ? fulfillJson(route, body) : fulfillJson(route, { error }, status);
}

const answer204: Answer = (route) => route.fulfill({ status: 204 });
const answer500: Answer = (route) => fulfillJson(route, { error: "internal error" }, 500);
const answerAbort: Answer = (route) => route.abort("failed");
// Never answers: the SPA has to give up on its own (3 s cap).
const answerStall: Answer = () => new Promise<void>(() => {});

// The 19 pre-cookie specs seed this key; an upgraded SPA must purge it.
async function seedLegacyToken(page: Page) {
  await page.addInitScript(
    ([key, value]) => localStorage.setItem(key, value),
    [LEGACY_KEY, LEGACY_JWT] as const,
  );
}

// Mocks the two boot endpoints and returns the order in which they were hit.
async function mockBoot(page: Page, meStatus: number, localStatus = 404): Promise<string[]> {
  const calls: string[] = [];
  await page.route("**/api/auth/me", (route) => {
    calls.push("me");
    return fulfillStatus(route, meStatus, USER, "not authenticated");
  });
  await page.route("**/api/auth/local-session", (route) => {
    calls.push("local-session");
    // Cookie mode: the session travels in Set-Cookie, the body has no token.
    return fulfillStatus(route, localStatus, { user: USER }, "not found");
  });
  return calls;
}

// A running audit whose page mints a stream token (POST) and opens the SSE stream.
async function mockRunningAudit(page: Page) {
  await page.route(`**/api/audits/${AUDIT_ID}`, (route) =>
    fulfillJson(route, {
      id: AUDIT_ID,
      source_id: "src-1",
      status: "running",
      types: ["cwe"],
      findings: [],
      created_at: "2026-01-01T00:00:00Z",
    }),
  );
  await page.route(`**/api/audits/${AUDIT_ID}/lineage`, (route) => fulfillJson(route, []));
  await page.route(`**/api/audits/${AUDIT_ID}/stream-token`, (route) =>
    fulfillJson(route, { stream_token: STREAM_TOKEN }),
  );
  await page.route(STREAM_URL, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: 'event: RunStarted\ndata: {"runId":"run-session-1"}\n\nevent: RunFinished\ndata: {}\n\n',
    }),
  );
}

// Answers successive logout calls in order; the last answer repeats.
async function routeLogout(page: Page, answers: Answer[]): Promise<Request[]> {
  const seen: Request[] = [];
  await page.route(LOGOUT_URL, (route) => {
    seen.push(route.request());
    return answers[Math.min(seen.length, answers.length) - 1](route);
  });
  return seen;
}

function recordApiRequests(page: Page): Request[] {
  const seen: Request[] = [];
  page.on("request", (req) => {
    if (new URL(req.url()).pathname.startsWith("/api/")) seen.push(req);
  });
  return seen;
}

function endpoint(req: Request): string {
  return `${req.method()} ${new URL(req.url()).pathname}`;
}

function isScriptFetch(req: Request): boolean {
  return ["fetch", "xhr"].includes(req.resourceType()) && !STREAM_URL.test(req.url());
}

async function headerViolation(req: Request): Promise<string | null> {
  const headers = await req.allHeaders();
  if (headers[CSRF] === "1" && headers.authorization === undefined) return null;
  return `${endpoint(req)}: ${CSRF}=${headers[CSRF]} authorization=${headers.authorization}`;
}

async function expectLogoutCalls(seen: Request[], count: number) {
  expect(seen).toHaveLength(count);
  for (const req of seen) {
    expect(req.method()).toBe("POST");
    expect(await headerViolation(req)).toBeNull();
  }
}

function storedCredentialKeys(page: Page): Promise<string[]> {
  return page.evaluate((pattern) => {
    const credential = new RegExp(pattern, "i");
    return [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((k) => credential.test(k));
  }, CREDENTIAL_KEY.source);
}

function sidebar(page: Page) {
  return page.getByTestId("sidebar");
}

function signOutButton(page: Page) {
  return sidebar(page).getByRole("button", { name: "Sign out" });
}

async function openSignedIn(page: Page) {
  await page.goto("/");
  await expect(sidebar(page).getByText(USER.name)).toBeVisible();
}

// Signed in both before and after the cookie change: the pre-cookie SPA
// validates the seeded key with me(), the cookie SPA asks me() directly.
async function mockSignedIn(page: Page) {
  await seedLegacyToken(page);
  await mockBoot(page, 200);
}

test.describe("Cookie session (0102)", () => {
  test("purges the legacy vulture_token and keeps no credential in Web Storage", async ({ page }) => {
    await mockSignedIn(page);

    await openSignedIn(page);

    expect(await storedCredentialKeys(page)).toEqual([]);
  });

  test("every fetch to /api carries the CSRF header and no Authorization", async ({ page }) => {
    await mockSignedIn(page);
    await mockRunningAudit(page);
    const seen = recordApiRequests(page);

    await Promise.all([page.waitForRequest(STREAM_URL), page.goto(`/audit/${AUDIT_ID}`)]);

    const fetches = seen.filter(isScriptFetch);
    // The set must hold the boot GET and an unsafe POST, or it proves nothing.
    expect(fetches.map(endpoint)).toEqual(
      expect.arrayContaining(["GET /api/auth/me", `POST /api/audits/${AUDIT_ID}/stream-token`]),
    );
    const violations = (await Promise.all(fetches.map(headerViolation))).filter((v) => v !== null);
    expect(violations).toEqual([]);
  });

  test("the EventSource stream request carries only the stream token", async ({ page }) => {
    await mockSignedIn(page);
    await mockRunningAudit(page);

    const [stream] = await Promise.all([page.waitForRequest(STREAM_URL), page.goto(`/audit/${AUDIT_ID}`)]);

    expect(new URL(stream.url()).searchParams.get("stream_token")).toBe(STREAM_TOKEN);
    const headers = await stream.allHeaders();
    expect(headers.authorization).toBeUndefined();
    expect(stream.url()).not.toContain(LEGACY_JWT);
    expect(Object.values(headers).join("\n")).not.toContain(LEGACY_JWT);
  });

  test("boot asks me() first, then makes exactly one local-session call when it is 401", async ({ page }) => {
    const calls = await mockBoot(page, 401, 200);

    await openSignedIn(page);

    expect(calls).toEqual(["me", "local-session"]);
    expect(await storedCredentialKeys(page)).toEqual([]);
  });

  test("boot makes no local-session call when me() is 200", async ({ page }) => {
    const calls = await mockBoot(page, 200, 200);

    await openSignedIn(page);

    expect(calls).toEqual(["me"]);
  });

  test("logout POSTs /api/auth/logout and lands on /login only after the answer", async ({ page }) => {
    await mockSignedIn(page);
    let release!: () => void;
    const answered = new Promise<void>((resolve) => (release = resolve));
    const seen = await routeLogout(page, [
      async (route) => {
        await answered;
        await answer204(route);
      },
    ]);
    await openSignedIn(page);

    await signOutButton(page).click();
    await expect.poll(() => seen.length, { message: "no POST /api/auth/logout was sent" }).toBe(1);
    // Held response: nothing may move until the server has answered.
    await page.waitForTimeout(300);
    await expect(page).not.toHaveURL(/\/login/);
    await expect(sidebar(page).getByText(USER.name)).toBeVisible();

    release();
    await expect(page).toHaveURL(/\/login$/);
    await expectLogoutCalls(seen, 1);
  });

  const failures: [string, Answer][] = [
    ["answers 500", answer500],
    ["fails at the network", answerAbort],
    ["stalls past 3 s", answerStall],
  ];
  for (const [name, firstAnswer] of failures) {
    test(`a logout that ${name} keeps the session and offers a retry`, async ({ page }) => {
      await mockSignedIn(page);
      const seen = await routeLogout(page, [firstAnswer, answer204]);
      await openSignedIn(page);

      await signOutButton(page).click();

      await expect(sidebar(page).getByText("An error occurred")).toBeVisible({ timeout: 10_000 });
      const retry = sidebar(page).getByRole("button", { name: "Retry" });
      await expect(retry).toBeVisible();
      await expect(signOutButton(page)).toBeVisible();
      await expect(sidebar(page).getByText(USER.name)).toBeVisible();
      await expect(page).not.toHaveURL(/\/login/);

      await retry.click();
      await expect(page).toHaveURL(/\/login$/);
      await expectLogoutCalls(seen, 2);
    });
  }
});

// Runs only against a started stack (never the mocked run): the real backend
// sets the cookie, so this is where HttpOnly and SameSite are observable.
const LIVE_BASE = process.env.VULTURE_E2E_BASE_URL ?? "";
const LIVE_PASSWORD = process.env.VULTURE_LOCAL_DEV_PASSWORD ?? "";
const SESSION_COOKIES = ["vulture_session", "__Host-vulture_session"];

// Local mode signs in by itself and /login redirects to the dashboard, so
// sign out first (a real server logout) to reach the form; Mode B shows it.
async function reachLoginForm(page: Page) {
  const email = page.locator('input[type="email"]');
  const signOut = signOutButton(page);
  await expect(email.or(signOut)).toBeVisible();
  if (await signOut.isVisible()) await signOut.click();
  await expect(email).toBeVisible();
  return email;
}

test.describe("Live Integration: session cookie (0102)", () => {
  test.skip(
    !LIVE_BASE || !LIVE_PASSWORD,
    "VULTURE_E2E_BASE_URL and VULTURE_LOCAL_DEV_PASSWORD unset: runs against a started stack",
  );

  test("a real login sets an HttpOnly SameSite=Strict cookie that scripts cannot read", async ({ page, context }) => {
    await page.goto(`${LIVE_BASE}/login`);
    const email = await reachLoginForm(page);
    await email.fill("admin@vulture.local");
    await page.locator('input[type="password"]').fill(LIVE_PASSWORD);
    await page.locator('button[type="submit"]').click();
    await expect(signOutButton(page)).toBeVisible({ timeout: 10_000 });

    const session = (await context.cookies(LIVE_BASE)).filter((c) => SESSION_COOKIES.includes(c.name));
    expect(session).toHaveLength(1);
    expect(session[0]).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/" });
    expect(await page.evaluate(() => document.cookie)).not.toContain("vulture_session");
    expect(await storedCredentialKeys(page)).toEqual([]);
  });
});
