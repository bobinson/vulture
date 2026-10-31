import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { Sidebar } from "./Sidebar";

// Feature 0102: a sign-out the server did not confirm keeps the session. The
// sidebar says so with the EXISTING common.error text and a common.retry
// button beside the sign-out control; no i18n key is added. (The test i18n
// mock renders keys, so these assertions pin the exact keys.)

const auth = vi.hoisted(() => ({
  user: { id: "u1", name: "Alice", email: "alice@test.com", role: "admin", created_at: "" },
  logout: vi.fn(),
  login: vi.fn(),
  register: vi.fn(),
  loading: false,
  logoutFailed: false,
}));

vi.mock("@/lib/auth.tsx", () => ({ useAuth: () => auth }));

function renderSidebar(logoutFailed: boolean) {
  auth.logoutFailed = logoutFailed;
  render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  auth.logout.mockReset();
  localStorage.clear();
});

describe("Sidebar sign-out failure (0102)", () => {
  it("shows no error and no retry while the last sign-out has not failed", () => {
    renderSidebar(false);
    expect(screen.getByRole("button", { name: "auth.logout" })).toBeInTheDocument();
    expect(screen.queryByText("common.error")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "common.retry" })).not.toBeInTheDocument();
  });

  it("shows the existing error text and a retry button beside sign-out after a failed sign-out", () => {
    renderSidebar(true);
    expect(screen.getByText("common.error")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "common.retry" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "auth.logout" })).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
  });

  it("retries the sign-out from the retry button", () => {
    renderSidebar(true);
    fireEvent.click(screen.getByRole("button", { name: "common.retry" }));
    expect(auth.logout).toHaveBeenCalledTimes(1);
  });
});
