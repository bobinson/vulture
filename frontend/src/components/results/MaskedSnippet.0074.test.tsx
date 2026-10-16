import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

// 0074 verification item 1b: a masked snippet can be verified in place. The
// toggle appears only when the snippet masks something, fetches only when
// switched on, and the values leave the DOM when it is switched off or the
// detail closes. Synthetic values.

vi.mock("@/lib/api.ts", () => ({ api: { maskedValues: vi.fn() } }));

import { api } from "@/lib/api.ts";
import { MaskedSnippet } from "./MaskedSnippet.tsx";

const mockMasked = vi.mocked(api.maskedValues);
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl";
const SNIPPET = '1: const a = 1;\n2: const token = "***REDACTED***";';

function verified(over: Record<string, unknown> = {}) {
  return {
    source_available: true, matches_scan: true, values_included: true, rows_checked: 2,
    file: "config.ts", ui_path: "/audit/a1?finding=f1",
    spans: [{ line: 2, ordinal: 0, column: 16, kind: "jwt", length: JWT.length, value: JWT }],
    ...over,
  };
}

function toggle() {
  return screen.getByRole("switch");
}

describe("MaskedSnippet", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders a snippet without placeholders as before, with no toggle", () => {
    render(<MaskedSnippet auditId="a1" findingId="f1" snippet="1: const a = 1;" />);
    expect(screen.getByText("1: const a = 1;")).toBeTruthy();
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it("does not fetch until the toggle is switched on", () => {
    render(<MaskedSnippet auditId="a1" findingId="f1" snippet={SNIPPET} />);
    expect(toggle().getAttribute("aria-checked")).toBe("false");
    expect(mockMasked).not.toHaveBeenCalled();
  });

  it("shows the value in its row and removes it when switched off", async () => {
    mockMasked.mockResolvedValue(verified());
    const { container } = render(<MaskedSnippet auditId="a1" findingId="f1" snippet={SNIPPET} />);
    fireEvent.click(toggle());
    await waitFor(() => expect(container.textContent).toContain(`const token = "${JWT}";`));
    expect(mockMasked).toHaveBeenCalledWith("a1", "f1");
    fireEvent.click(toggle());
    expect(container.textContent).not.toContain(JWT);
    expect(container.textContent).toContain("***REDACTED***");
  });

  it("clears the value when the detail closes", async () => {
    mockMasked.mockResolvedValue(verified());
    const { container, unmount } = render(<MaskedSnippet auditId="a1" findingId="f1" snippet={SNIPPET} />);
    fireEvent.click(toggle());
    await waitFor(() => expect(container.textContent).toContain(JWT));
    unmount();
    expect(document.body.textContent).not.toContain(JWT);
  });

  it.each([
    [{ matches_scan: false, values_included: false, reason: "changed_since_scan", spans: [] }, "results.reveal.changed"],
    [{ source_available: false, matches_scan: false, values_included: false, reason: "source_unavailable", spans: [] }, "results.reveal.unavailable"],
    [{ values_included: false, spans: [{ line: 2, ordinal: 0, column: 16, kind: "jwt", length: 54 }] }, "results.reveal.notPermitted"],
  ])("explains why no value is shown (%#)", async (over, text) => {
    mockMasked.mockResolvedValue(verified(over));
    const { container } = render(<MaskedSnippet auditId="a1" findingId="f1" snippet={SNIPPET} />);
    fireEvent.click(toggle());
    await waitFor(() => expect(container.textContent).toContain(text));
    expect(container.textContent).not.toContain(JWT);
  });
});
