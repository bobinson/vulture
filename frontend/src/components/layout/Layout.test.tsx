import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { Layout } from "./Layout";

vi.mock("react-router-dom", () => ({
  Outlet: () => <div data-testid="outlet">outlet content</div>,
  NavLink: ({ children }: { children: React.ReactNode }) => <a>{children}</a>,
  useLocation: vi.fn(() => ({ pathname: "/" })),
}));

vi.mock("./Sidebar.tsx", () => ({
  Sidebar: () => <aside data-testid="sidebar">sidebar</aside>,
}));

vi.mock("./Header.tsx", () => ({
  Header: () => <header data-testid="header">header</header>,
}));

vi.mock("@/lib/auth.tsx", () => ({
  useAuth: () => ({
    user: { id: "u1", name: "Alice", email: "a@b.com", role: "admin", created_at: "" },
    logout: vi.fn(),
    login: vi.fn(),
    register: vi.fn(),
    token: "tok",
    loading: false,
  }),
}));

describe("Layout", () => {
  it("renders sidebar", () => {
    render(<Layout />);
    expect(screen.getByTestId("sidebar")).toBeInTheDocument();
  });

  it("renders main content area", () => {
    render(<Layout />);
    expect(screen.getByTestId("main-content")).toBeInTheDocument();
  });

  it("renders header", () => {
    render(<Layout />);
    expect(screen.getByTestId("header")).toBeInTheDocument();
  });

  it("renders outlet", () => {
    render(<Layout />);
    expect(screen.getByTestId("outlet")).toBeInTheDocument();
  });

  it("main content has proper margin when sidebar pinned", () => {
    localStorage.setItem("vulture_sidebar_pinned", "true");
    render(<Layout />);
    const main = screen.getByTestId("main-content");
    expect(main.className).toContain("ml-[220px]");
  });

  it("main content has smaller margin when sidebar unpinned", () => {
    localStorage.setItem("vulture_sidebar_pinned", "false");
    render(<Layout />);
    const main = screen.getByTestId("main-content");
    expect(main.className).toContain("ml-[52px]");
  });
});
