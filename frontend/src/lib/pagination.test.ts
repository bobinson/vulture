import { describe, expect, it } from "vitest";

import { ELLIPSIS, PAGER_SLOTS, type PageItem, pageItems } from "./pagination";

const show = (items: PageItem[]) =>
  items.map((i) => (i === ELLIPSIS ? "…" : String(i + 1))).join(" ");

describe("pageItems", () => {
  it("shows every page when they all fit", () => {
    expect(show(pageItems(0, 7))).toBe("1 2 3 4 5 6 7");
    expect(show(pageItems(0, PAGER_SLOTS))).toBe(
      Array.from({ length: PAGER_SLOTS }, (_, i) => i + 1).join(" "),
    );
  });

  it("keeps at least twenty pages one click away", () => {
    // The footer was measured to hold this many comfortably; fewer makes a
    // 62-page result set tedious to walk, which is what prompted the change.
    // The window is symmetric so the count is odd -- 21, not exactly 20.
    expect(PAGER_SLOTS).toBeGreaterThanOrEqual(20);
    for (const page of [0, 5, 33, 61]) {
      expect(pageItems(page, 62)).toHaveLength(PAGER_SLOTS);
    }
  });

  it("elides the middle for a large page count", () => {
    // 1530 findings at 25 per page = 62 pages. Rendering all 62 buttons is what
    // overflowed the footer and pushed the next arrow out of view.
    expect(show(pageItems(33, 62))).toBe(
      "1 … 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 … 62",
    );
  });

  it("always offers the last page, so it is reachable in one click", () => {
    for (const page of [0, 1, 20, 33, 61]) {
      expect(pageItems(page, 62)).toContain(61);
    }
  });

  it("always offers the first page", () => {
    for (const page of [0, 1, 20, 33, 61]) {
      expect(pageItems(page, 62)).toContain(0);
    }
  });

  it("keeps a constant width at both ends", () => {
    const widths = new Set(
      Array.from({ length: 62 }, (_, p) => pageItems(p, 62).length),
    );
    expect([...widths]).toEqual([PAGER_SLOTS]);
  });

  it("never emits two ellipses in a row, or one at an edge", () => {
    for (let page = 0; page < 62; page += 1) {
      const items = pageItems(page, 62);
      expect(items[0]).toBe(0);
      expect(items[items.length - 1]).toBe(61);
      for (let i = 1; i < items.length; i += 1) {
        expect(items[i] === ELLIPSIS && items[i - 1] === ELLIPSIS).toBe(false);
      }
    }
  });

  it("keeps page numbers ascending with no duplicates", () => {
    for (const total of [1, 2, 7, 8, 25, 62, 500]) {
      for (const page of [0, Math.floor(total / 2), total - 1]) {
        const nums = pageItems(page, total).filter(
          (i): i is number => i !== ELLIPSIS,
        );
        expect(nums).toEqual([...new Set(nums)]);
        expect(nums).toEqual([...nums].sort((a, b) => a - b));
      }
    }
  });

  it("always includes the current page", () => {
    for (const total of [1, 5, 8, 62, 500]) {
      for (let page = 0; page < total; page += 1) {
        expect(pageItems(page, total)).toContain(page);
      }
    }
  });

  it("clamps an out-of-range page instead of producing junk", () => {
    expect(pageItems(-5, 10)).toContain(0);
    expect(pageItems(999, 10)).toContain(9);
  });

  it("returns nothing for a non-positive page count", () => {
    expect(pageItems(0, 0)).toEqual([]);
  });
});
