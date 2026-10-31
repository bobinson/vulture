import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "@/lib/auth.tsx";
import { Sidebar } from "./Sidebar";
import { watchAnnouncements } from "@/test/liveRegion";

// The sidebar with the real auth provider. A retry of a failed sign-out keeps
// keyboard focus on a sidebar control: the Retry button stays mounted while
// the retry runs and after it fails again. While a sign-out is in flight both
// controls are marked busy and disabled (aria only, so they keep focus). The
// test i18n mock renders keys, so the names below are i18n keys.

vi.mock("@/lib/api.ts", () => ({
  api: { me: vi.fn(), localSession: vi.fn(), logout: vi.fn() },
}));

import { api } from "@/lib/api.ts";

const mockLogout = vi.mocked(api.logout);
const NETWORK_ERROR = new TypeError("Failed to fetch");

// A logout the test fails by hand, so it can look at the sidebar in flight.
function heldFailingLogout() {
  let fail!: () => void;
  mockLogout.mockReturnValueOnce(new Promise<void>((_resolve, reject) => (fail = () => reject(NETWORK_ERROR))));
  return () => act(async () => fail());
}

async function renderFailedSignOut() {
  vi.mocked(api.me).mockResolvedValue({ id: "u1", name: "Alice", email: "a@test.com", role: "admin", created_at: "" });
  mockLogout.mockRejectedValueOnce(NETWORK_ERROR);
  render(
    <AuthProvider>
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    </AuthProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "auth.logout" }));
  return screen.findByRole("button", { name: "common.retry" });
}

function signOutButton() {
  return screen.getByRole("button", { name: "auth.logout" });
}

beforeEach(() => {
  vi.mocked(api.me).mockReset();
  mockLogout.mockReset();
  localStorage.clear();
});

describe("Sidebar sign-out retry (0102)", () => {
  it("keeps focus on Retry while the retry runs and after it fails again", async () => {
    const retry = await renderFailedSignOut();
    const failAgain = heldFailingLogout();

    retry.focus();
    fireEvent.click(retry);

    expect(mockLogout).toHaveBeenCalledTimes(2);
    expect(document.activeElement).toBe(retry);
    await failAgain();
    expect(screen.getByRole("button", { name: "common.retry" })).toBe(retry);
    expect(document.activeElement).toBe(retry);
  });

  it("marks Sign out and Retry busy and disabled while a sign-out is in flight", async () => {
    const retry = await renderFailedSignOut();
    expect(retry).not.toHaveAttribute("aria-busy", "true");
    expect(signOutButton()).not.toHaveAttribute("aria-disabled", "true");
    const failAgain = heldFailingLogout();

    fireEvent.click(retry);

    for (const control of [signOutButton(), retry]) {
      expect(control).toHaveAttribute("aria-busy", "true");
      expect(control).toHaveAttribute("aria-disabled", "true");
      expect(control).not.toBeDisabled();
    }
    await failAgain();
    for (const control of [signOutButton(), retry]) {
      expect(control).not.toHaveAttribute("aria-busy", "true");
      expect(control).not.toHaveAttribute("aria-disabled", "true");
    }
  });

  // The failure line already shows the same text, so only a change to the
  // alert's content makes a screen reader say it again (WCAG 4.1.3).
  it("announces each repeat failure once it is known, while Retry keeps its identity and focus", async () => {
    const retry = await renderFailedSignOut();
    const announced = watchAnnouncements(screen.getByRole("alert"));
    const failAgain = heldFailingLogout();

    retry.focus();
    fireEvent.click(retry);

    expect(announced()).toEqual([]);
    await failAgain();
    expect(announced()).toEqual(["common.error"]);
    expect(screen.getByRole("button", { name: "common.retry" })).toBe(retry);
    expect(document.activeElement).toBe(retry);

    mockLogout.mockRejectedValueOnce(NETWORK_ERROR);
    await act(async () => fireEvent.click(retry));
    expect(mockLogout).toHaveBeenCalledTimes(3);
    expect(announced()).toEqual(["common.error"]);
  });

  it("sends no second request when Sign out is pressed again while the retry runs", async () => {
    const retry = await renderFailedSignOut();
    heldFailingLogout();

    fireEvent.click(retry);
    fireEvent.click(signOutButton());
    fireEvent.click(retry);

    expect(mockLogout).toHaveBeenCalledTimes(2);
  });
});
