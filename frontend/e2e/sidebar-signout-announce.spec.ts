import { test, expect, type Page, type Route } from "@playwright/test";

// Feature 0102: a sign-out that fails again is announced again, in a real
// browser on every engine. The failure line keeps the same text, so a screen
// reader is told about a repeat failure only if the alert's content changes
// (WCAG 4.1.3). The Retry button stays the same element, with the focus,
// while that happens.

const USER = {
  id: "test-user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};
const PINNED_KEY = "vulture_sidebar_pinned";
const FAILURE_TEXT = "An error occurred";

type Answer = (route: Route) => Promise<void>;
type Watched = Window & { announced: string[]; retryAtStart: Element };

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

// Signed in with the sidebar pinned open; successive sign-outs get the given
// answers in order (the last repeats). Returns the sign-out requests seen.
async function signInWithLogoutAnswers(page: Page, answers: Answer[]): Promise<unknown[]> {
  await page.addInitScript((key) => localStorage.setItem(key, "true"), PINNED_KEY);
  await page.route("**/api/auth/me", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(USER) }),
  );
  const seen: unknown[] = [];
  await page.route("**/api/auth/logout", (route) => {
    seen.push(route.request());
    return answers[Math.min(seen.length, answers.length) - 1](route);
  });
  return seen;
}

function retryButton(page: Page) {
  return page.getByTestId("sidebar").getByRole("button", { name: "Retry" });
}

// From here on, records in the page the text added to the sidebar's alert or
// changed in place (what its live region announces again), and remembers the
// Retry element so the test can tell whether it was replaced.
async function watchFailureLine(page: Page) {
  await page
    .getByTestId("sidebar")
    .getByRole("alert")
    .evaluate((region) => {
      const watched = window as unknown as Watched;
      watched.announced = [];
      new MutationObserver((records) => {
        for (const record of records) {
          const nodes = record.type === "characterData" ? [record.target] : Array.from(record.addedNodes);
          watched.announced.push(...nodes.map((node) => node.textContent ?? ""));
        }
      }).observe(region, { childList: true, characterData: true, subtree: true });
    });
  await retryButton(page).evaluate((el) => ((window as unknown as Watched).retryAtStart = el));
  return () => page.evaluate(() => (window as unknown as Watched).announced);
}

test.describe("Sidebar sign-out: a repeat failure is announced (0102)", () => {
  test("each failed retry re-announces the failure while Retry keeps its identity and focus", async ({ page }) => {
    const held = heldAnswer(answer500);
    const seen = await signInWithLogoutAnswers(page, [answer500, held.answer, answer500]);
    await page.goto("/");
    await page.getByTestId("sidebar").getByRole("button", { name: "Sign out" }).focus();
    await page.keyboard.press("Enter");
    await expect(retryButton(page)).toBeVisible();
    const announced = await watchFailureLine(page);

    await retryButton(page).focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => seen.length).toBe(2);
    await expect(retryButton(page)).toHaveAttribute("aria-busy", "true");
    expect(await announced(), "announced while the retry was still in flight").toEqual([]);
    held.release();

    await expect.poll(announced).toEqual([FAILURE_TEXT]);
    await expect(retryButton(page)).not.toHaveAttribute("aria-busy", "true");
    expect(await retryButton(page).evaluate((el) => el === (window as unknown as Watched).retryAtStart)).toBe(true);
    await expect(retryButton(page)).toBeFocused();

    await page.keyboard.press("Enter");
    await expect.poll(announced).toEqual([FAILURE_TEXT, FAILURE_TEXT]);
    expect(seen).toHaveLength(3);
    await expect(retryButton(page)).toBeFocused();
  });
});
