import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, act, waitFor, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useNavigate } from "react-router";
import { useEffect } from "react";

/**
 * Feature 0096 (M8): the target report's OWASP filter.
 *
 *   - It is offered whenever the aggregate response's `label_editions` names
 *     an OWASP edition — not only once a fetched ROW happens to carry a label
 *     (a page of unlabelled rows used to hide the filter entirely).
 *   - Its editions come from `label_editions`; an absent field means none.
 *   - `?owasp=A07` without an edition filters under the newest edition the
 *     target has, instead of being silently ignored, and never asks the
 *     server for a category without an edition.
 *   - The page is remounted per target, so nothing one target's report holds
 *     leaks into another's.
 */

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

import { TargetReport } from "./TargetReport";

const KEY_A = "path:/work/a";
const KEY_B = "path:/work/b";
const enc = encodeURIComponent;

function json(data: unknown) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

const ROW = {
  lineage_id: "l-1",
  ref: "VLT-1",
  severity: "high",
  category: "CWE-1333",
  title: "Unlabelled row",
  rel_path: "src/a.ts",
  line_start: 1,
  tier: "det",
  seen_count: 1,
  scan_count: 1,
  status: "open",
  first_seen_at: "2026-09-01T10:00:00Z",
  last_seen_at: "2026-09-01T10:00:00Z",
  last_event: "detected",
};

type LabelEditions = { framework: string; edition: string; categories: string[] }[] | undefined;
let editionsByKey: Record<string, LabelEditions> = {};

function aggregate(labelEditions: LabelEditions) {
  return {
    total: 1,
    page: 1,
    page_size: 50,
    tiles: { unique: 1, active: 1, unconfirmed: 0, fixed: 0, critical: 0 },
    rows: [ROW],
    ...(labelEditions === undefined ? {} : { label_editions: labelEditions }),
  };
}

beforeEach(() => {
  mockFetch.mockReset();
  editionsByKey = {
    [KEY_A]: [
      { framework: "owasp", edition: "2025", categories: ["A05", "A07", "A09"] },
      { framework: "owasp", edition: "2021", categories: ["A03", "A07"] },
    ],
  };
  mockFetch.mockImplementation((url: string) => {
    if (url.includes("/scans")) return json([]);
    if (url.includes("/aggregate")) {
      const key = decodeURIComponent(url.split("/targets/")[1].split("/aggregate")[0]);
      return json(aggregate(editionsByKey[key]));
    }
    return json([]);
  });
});

const aggregateUrls = () =>
  mockFetch.mock.calls.map((c) => String(c[0])).filter((u) => u.includes("/aggregate"));

let navigateTo: (to: string) => void = () => {};
function NavProbe() {
  const navigate = useNavigate();
  useEffect(() => {
    navigateTo = navigate;
  }, [navigate]);
  return null;
}

function renderReport(initial: string) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <NavProbe />
      <Routes>
        <Route path="/targets/:key" element={<TargetReport />} />
      </Routes>
    </MemoryRouter>,
  );
}

const rowsShown = () => waitFor(() => expect(screen.getAllByTestId("aggregate-row").length).toBe(1));

describe("TargetReport OWASP filter (0096 M8)", () => {
  it("is offered from label_editions even when no fetched row carries a label", async () => {
    renderReport(`/targets/${enc(KEY_A)}`);
    await rowsShown();
    const edition = await screen.findByTestId("aggregate-owasp-edition");
    const options = [...edition.querySelectorAll("option")].map((o) => o.getAttribute("value"));
    expect(options).toEqual(["2025", "2021"]);
    expect((edition as HTMLSelectElement).value).toBe("2025");
    expect(screen.getByTestId("aggregate-owasp-category")).toBeInTheDocument();
  });

  it("offers only the categories the chosen edition's rows carry", async () => {
    renderReport(`/targets/${enc(KEY_A)}`);
    await rowsShown();
    const category = await screen.findByTestId("aggregate-owasp-category");
    const values = () => [...category.querySelectorAll("option")].map((o) => o.getAttribute("value"));
    expect(values()).toEqual(["all", "A05", "A07", "A09"]);

    await act(async () => {
      const edition = screen.getByTestId("aggregate-owasp-edition") as HTMLSelectElement;
      edition.value = "2021";
      edition.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await waitFor(() => expect(values()).toEqual(["all", "A03", "A07"]));
  });

  it("keeps a deep link's category selectable even when the edition lists no rows for it", async () => {
    renderReport(`/targets/${enc(KEY_A)}?owasp=A01&owasp_edition=2025`);
    await rowsShown();
    const category = screen.getByTestId("aggregate-owasp-category") as HTMLSelectElement;
    expect(category.value).toBe("A01");
    expect([...category.querySelectorAll("option")].map((o) => o.getAttribute("value"))).toEqual(["all", "A01", "A05", "A07", "A09"]);
  });

  it("is not offered when label_editions is absent or names no OWASP edition", async () => {
    editionsByKey[KEY_A] = undefined;
    const { unmount } = renderReport(`/targets/${enc(KEY_A)}`);
    await rowsShown();
    expect(screen.queryByTestId("aggregate-owasp-category")).toBeNull();
    unmount();

    editionsByKey[KEY_A] = [{ framework: "asvs", edition: "5000", categories: ["V2"] }];
    renderReport(`/targets/${enc(KEY_A)}`);
    await rowsShown();
    expect(screen.queryByTestId("aggregate-owasp-category")).toBeNull();
  });

  it("?owasp=A07 without an edition filters under the newest edition, never sending a category alone", async () => {
    renderReport(`/targets/${enc(KEY_A)}?owasp=A07`);
    await waitFor(() => {
      const last = aggregateUrls().at(-1) ?? "";
      expect(last).toContain("category=A07");
      expect(last).toContain("edition=2025");
    });
    for (const u of aggregateUrls()) {
      if (u.includes("category=")) expect(u).toMatch(/edition=\d{4}/);
    }
    expect((screen.getByTestId("aggregate-owasp-category") as HTMLSelectElement).value).toBe("A07");
  });

  it("?owasp=A07 picks the only edition the target has", async () => {
    editionsByKey[KEY_A] = [{ framework: "owasp", edition: "2021", categories: ["A07"] }];
    renderReport(`/targets/${enc(KEY_A)}?owasp=A07`);
    await waitFor(() => expect(aggregateUrls().at(-1)).toContain("edition=2021"));
    expect(aggregateUrls().at(-1)).toContain("category=A07");
  });

  it("a deep link naming category and edition asks for exactly that, first time", async () => {
    renderReport(`/targets/${enc(KEY_A)}?owasp=A05&owasp_edition=2021`);
    await rowsShown();
    const first = aggregateUrls()[0];
    expect(first).toContain("category=A05");
    expect(first).toContain("edition=2021");
  });

  it("remounts per target, so one target's report state never carries into another's", async () => {
    editionsByKey[KEY_B] = [];
    renderReport(`/targets/${enc(KEY_A)}`);
    await rowsShown();
    await screen.findByTestId("aggregate-owasp-edition");
    const before = screen.getByTestId("aggregate-report");

    await act(async () => navigateTo(`/targets/${enc(KEY_B)}`));
    await rowsShown();
    expect(screen.getByTestId("aggregate-report")).not.toBe(before);
    expect(screen.queryByTestId("aggregate-owasp-category")).toBeNull();
  });
});
