import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Sidebar } from "./Sidebar";

const mockLogout = vi.fn();
vi.mock("react-router-dom", () => ({
  NavLink: ({ to, children, className, onClick }: {
    to: string; children: React.ReactNode; className: string | ((p: { isActive: boolean }) => string); onClick?: () => void;
  }) => {
    const cn = typeof className === "function" ? className({ isActive: to === "/" }) : className;
    return <a href={to} className={cn} onClick={onClick}>{children}</a>;
  },
  useLocation: vi.fn(() => ({ pathname: "/" })),
}));

vi.mock("@/lib/auth.tsx", () => ({
  useAuth: () => ({
    user: { id: "u1", name: "Alice", email: "alice@test.com", role: "admin", created_at: "" },
    logout: mockLogout,
    login: vi.fn(),
    register: vi.fn(),
    token: "tok",
    loading: false,
  }),
}));

describe("Sidebar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it("renders sidebar element", () => {
    render(<Sidebar />);
    expect(screen.getByTestId("sidebar")).toBeInTheDocument();
  });

  it("renders logo V", () => {
    render(<Sidebar />);
    expect(screen.getByText("V")).toBeInTheDocument();
    expect(screen.getByText("ulture")).toBeInTheDocument();
  });

  it("renders nav items", () => {
    render(<Sidebar />);
    expect(screen.getByText("nav.dashboard")).toBeInTheDocument();
    expect(screen.getByText("nav.audit")).toBeInTheDocument();
    expect(screen.getByText("nav.memories")).toBeInTheDocument();
    expect(screen.getByText("nav.settings")).toBeInTheDocument();
  });

  it("renders user initial", () => {
    render(<Sidebar />);
    expect(screen.getByText("A")).toBeInTheDocument();
  });

  it("renders user name", () => {
    render(<Sidebar />);
    expect(screen.getByText("Alice")).toBeInTheDocument();
  });

  it("renders logout button", () => {
    render(<Sidebar />);
    expect(screen.getByText("auth.logout")).toBeInTheDocument();
  });

  it("calls logout when clicked", () => {
    render(<Sidebar />);
    fireEvent.click(screen.getByText("auth.logout"));
    expect(mockLogout).toHaveBeenCalledTimes(1);
  });

  it("renders version text", () => {
    render(<Sidebar />);
    expect(screen.getByText("v1.0.0")).toBeInTheDocument();
  });

  it("has toggle pin button", () => {
    render(<Sidebar />);
    expect(screen.getByTestId("sidebar-toggle")).toBeInTheDocument();
  });

  it("persists pin state to localStorage", () => {
    render(<Sidebar />);
    // Initially pinned (default)
    fireEvent.click(screen.getByTestId("sidebar-toggle"));
    expect(localStorage.getItem("vulture_sidebar_pinned")).toBe("false");
  });
});
