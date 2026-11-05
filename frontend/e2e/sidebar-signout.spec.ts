import { test, expect, type Page, type Request, type Route } from "@playwright/test";

// Feature 0102: the sidebar's sign-out controls, in a real browser on every
// engine. One sign-out request runs at a time and shows it is busy; a retry
// keeps keyboard focus on Retry; a failed sign-out keeps an unpinned sidebar
// open, so its retry is never hidden in the collapsed rail; the collapsed
// rail keeps its hidden controls out of the keyboard order; and the Retry
// focus ring is not cut off by the clipping user block.

const USER = {
  id: "test-user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};
const PINNED_KEY = "vulture_sidebar_pinned";
// Sidebar.tsx: the rail collapses this long after the pointer leaves, then
// animates for 300 ms. Waiting past both shows where it settled.
const COLLAPSE_SETTLED_MS = 2_000 + 300 + 400;
const EXPANDED_WIDTH = 220;

type Answer = (route: Route) => Promise<void>;

const answer204: Answer = (route) => route.fulfill({ status: 204 });
const answer500: Answer = (route) =>
  route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "internal error" }) });

// An answer the test releases by hand, so it can look at the page in flight.
function heldAnswer(answer: Answer): { answer: Answer; release: () => void } {
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  return {
    answer: async (route) => {
      await released;
      await answer(route);
    },
    release,
  };
}

async function mockSignedIn(page: Page, pinned = true) {
  await page.addInitScript(([key, value]) => localStorage.setItem(key, value), [PINNED_KEY, String(pinned)] as const);
  await page.route("**/api/auth/me", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(USER) }),
  );
}

// Answers successive logout calls in order; the last answer repeats.
async function routeLogout(page: Page, answers: Answer[]): Promise<Request[]> {
  const seen: Request[] = [];
  await page.route("**/api/auth/logout", (route) => {
    seen.push(route.request());
    return answers[Math.min(seen.length, answers.length) - 1](route);
  });
  return seen;
}

function sidebar(page: Page) {
  return page.getByTestId("sidebar");
}

function signOutButton(page: Page) {
  return sidebar(page).getByRole("button", { name: "Sign out" });
}

function retryButton(page: Page) {
  return sidebar(page).getByRole("button", { name: "Retry" });
}

// The pointer enters the collapsed rail from the page, as a user's does (a
// pointer that starts over the rail never fires the enter that opens it).
async function openRail(page: Page) {
  await page.mouse.move(800, 400);
  await sidebar(page).hover();
  await expect(signOutButton(page)).toBeVisible();
}

async function openSignedIn(page: Page) {
  await page.goto("/");
  await expect(sidebar(page).getByText(USER.name)).toBeVisible();
}

// Signs out from the keyboard, so a later programmatic focus is :focus-visible.
async function failSignOutFromKeyboard(page: Page) {
  await signOutButton(page).focus();
  await page.keyboard.press("Enter");
  await expect(retryButton(page)).toBeVisible();
}

// How far, in px, the focused element's outline reaches past the nearest
// ancestor that clips its overflow (0 on a side means nothing is cut off).
function outlineOverflow(el: Element) {
  const style = getComputedStyle(el);
  const reach = parseFloat(style.outlineWidth) + parseFloat(style.outlineOffset);
  let clip = el.parentElement;
  while (clip && getComputedStyle(clip).overflow === "visible") clip = clip.parentElement;
  const box = el.getBoundingClientRect();
  const frame = (clip ?? document.documentElement).getBoundingClientRect();
  // Whole px: a sub-pixel rounding difference is not a cut-off ring.
  const past = (n: number) => Math.max(0, Math.round(n));
  return {
    outline: `${style.outlineStyle} ${style.outlineWidth}`,
    top: past(frame.top - (box.top - reach)),
    right: past(box.right + reach - frame.right),
    bottom: past(box.bottom + reach - frame.bottom),
    left: past(frame.left - (box.left - reach)),
  };
}

test.describe("Sidebar sign-out (0102)", () => {
  test("Sign out shows it is busy and a double click sends one request", async ({ page }) => {
    await mockSignedIn(page);
    const held = heldAnswer(answer204);
    const seen = await routeLogout(page, [held.answer]);
    await openSignedIn(page);

    await signOutButton(page).dblclick();
    await signOutButton(page).focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => seen.length, { message: "no POST /api/auth/logout was sent" }).toBeGreaterThan(0);
    // Room for a second POST to reach the route if the page sent one.
    await page.waitForTimeout(300);

    expect(seen).toHaveLength(1);
    await expect(signOutButton(page)).toHaveAttribute("aria-busy", "true");
    await expect(signOutButton(page)).toHaveAttribute("aria-disabled", "true");
    held.release();
    await expect(page).toHaveURL(/\/login$/);
    expect(seen).toHaveLength(1);
  });

  test("a keyboard retry keeps focus on Retry while it runs and after it fails again", async ({ page }) => {
    await mockSignedIn(page);
    const held = heldAnswer(answer500);
    const seen = await routeLogout(page, [answer500, held.answer, answer204]);
    await openSignedIn(page);
    await failSignOutFromKeyboard(page);

    await retryButton(page).focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => seen.length).toBe(2);

    await expect(retryButton(page)).toBeFocused();
    await expect(retryButton(page)).toHaveAttribute("aria-busy", "true");
    await expect(signOutButton(page)).toHaveAttribute("aria-busy", "true");
    held.release();
    await expect(retryButton(page)).not.toHaveAttribute("aria-busy", "true");
    await expect(retryButton(page)).toBeFocused();

    // The kept focus still works: Enter retries, and the confirmed sign-out leaves.
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/login$/);
    expect(seen).toHaveLength(3);
  });

  test("a failed sign-out keeps an unpinned sidebar open with its retry", async ({ page }) => {
    await mockSignedIn(page, false);
    const seen = await routeLogout(page, [answer500, answer204]);
    await page.goto("/");
    await openRail(page);
    await signOutButton(page).click();
    await expect(retryButton(page)).toBeVisible();

    await page.mouse.move(800, 400);
    await page.waitForTimeout(COLLAPSE_SETTLED_MS);

    expect((await sidebar(page).boundingBox())?.width).toBeCloseTo(EXPANDED_WIDTH, 0);
    await expect(sidebar(page).getByText("An error occurred")).toBeVisible();
    await expect(retryButton(page)).toBeVisible();
    await expect(sidebar(page).getByText(USER.name)).toBeVisible();
    await retryButton(page).click();
    await expect(page).toHaveURL(/\/login$/);
    expect(seen).toHaveLength(2);
  });

  test("a collapsed sidebar keeps its hidden sign-out control out of the keyboard order", async ({ page }) => {
    await mockSignedIn(page, false);
    await page.goto("/");
    await page.mouse.move(800, 400);
    const hiddenSignOut = sidebar(page).getByRole("button", { name: "Sign out", includeHidden: true });
    await expect(hiddenSignOut).toBeAttached();

    await expect(hiddenSignOut).toBeHidden();
    await hiddenSignOut.focus();
    await expect(hiddenSignOut).not.toBeFocused();

    // Expanding the rail brings the control back.
    await openRail(page);
  });

  test("the Retry focus ring is drawn whole inside the clipping user block", async ({ page }) => {
    await mockSignedIn(page);
    await routeLogout(page, [answer500]);
    await openSignedIn(page);
    await failSignOutFromKeyboard(page);
    await page.mouse.move(800, 400);

    await retryButton(page).focus();

    expect(await retryButton(page).evaluate((el) => el.matches(":focus-visible"))).toBe(true);
    expect(await retryButton(page).evaluate(outlineOverflow)).toEqual({
      outline: "solid 2px",
      top: 0,
      right: 0,
      bottom: 0,
      left: 0,
    });
  });
});
