/** Page-number windowing for table footers.
 *
 * Rendering one button per page does not scale: a 1530-row result set at 25
 * rows per page is 62 buttons, which overflowed the footer row and pushed the
 * "next" arrow out of view entirely, leaving no way to page past whatever
 * happened to fit. The control must stay a bounded width regardless of how
 * many pages there are.
 */

export const ELLIPSIS = "ellipsis" as const;

/** Pages either side of the current one.
 *
 * The window is symmetric, so the slot count is always odd: 8 siblings gives
 * 21 slots, the nearest value at or above the twenty the footer was measured
 * to hold comfortably. At 28px a slot that is ~590px of numbers plus the two
 * arrows, against a footer that is around 1000px at the observed width.
 */
export const DEFAULT_SIBLINGS = 8;

/** Slots the control always renders: first + ellipsis + window + ellipsis + last. */
export const PAGER_SLOTS = DEFAULT_SIBLINGS * 2 + 5;

export type PageItem = number | typeof ELLIPSIS;

/**
 * Build the page items to render, always including the first page, the last
 * page, and a window around the current one.
 *
 * @param page 0-based current page
 * @param totalPages total number of pages
 * @param siblings pages to show either side of the current page. The default
 *   yields {@link PAGER_SLOTS} slots -- first, ellipsis, the window, ellipsis,
 *   last -- keeping that many pages reachable in one click without the row
 *   growing wide enough to clip the arrows.
 * @returns 0-based page indices, with {@link ELLIPSIS} marking elided runs
 */
export function pageItems(
  page: number,
  totalPages: number,
  siblings = DEFAULT_SIBLINGS,
): PageItem[] {
  if (totalPages <= 0) return [];
  const current = Math.min(Math.max(page, 0), totalPages - 1);

  // Widest form is: first + ellipsis + window + ellipsis + last. Below that
  // threshold every page fits, so show them all rather than eliding a single
  // page behind an ellipsis that is the same width as the button it replaces.
  const windowSize = siblings * 2 + 1;
  if (totalPages <= windowSize + 4) {
    return Array.from({ length: totalPages }, (_, i) => i);
  }

  const first = 0;
  const last = totalPages - 1;

  // The control must not change width as the user pages through it, or the
  // arrows shift under the cursor. The widest form is
  //   first + ellipsis + window + ellipsis + last
  // so every form gets that many slots. Near an edge one ellipsis is not
  // needed, and the slot it would have taken goes to an extra page number
  // instead of being dropped.
  const slots = windowSize + 4;
  const nearStart = current - siblings <= first + 1;
  const nearEnd = current + siblings >= last - 1;

  let start: number;
  let end: number;
  if (nearStart) {
    start = first + 1;
    end = start + (slots - 3) - 1; // first, ellipsis, last
  } else if (nearEnd) {
    end = last - 1;
    start = end - (slots - 3) + 1;
  } else {
    start = current - siblings;
    end = current + siblings;
  }
  start = Math.max(start, first + 1);
  end = Math.min(end, last - 1);

  const items: PageItem[] = [first];
  if (start > first + 1) items.push(ELLIPSIS);
  for (let p = start; p <= end; p += 1) items.push(p);
  if (end < last - 1) items.push(ELLIPSIS);
  items.push(last);
  return items;
}
