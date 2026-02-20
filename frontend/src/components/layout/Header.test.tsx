import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { Header } from "./Header";

// Mock react-router-dom
vi.mock("react-router-dom", () => ({
  Link: ({ to, children }: { to: string; children: React.ReactNode }) => (
    <a href={to}>{children}</a>
  ),
  useLocation: vi.fn(() => ({ pathname: "/" })),
}));

import { useLocation } from "react-router-dom";
const mockUseLocation = vi.mocked(useLocation);

describe("Header", () => {
  it("renders header element", () => {
    render(<Header />);
    expect(screen.getByTestId("header")).toBeInTheDocument();
  });

  it("shows dashboard title on root path", () => {
    mockUseLocation.mockReturnValue({ pathname: "/" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("dashboard.title")).toBeInTheDocument();
  });

  it("shows audit title on /audit path", () => {
    mockUseLocation.mockReturnValue({ pathname: "/audit" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("audit.title")).toBeInTheDocument();
  });

  it("shows results title for audit detail path", () => {
    mockUseLocation.mockReturnValue({ pathname: "/audit/abc123def" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("results.title")).toBeInTheDocument();
  });

  it("renders home breadcrumb", () => {
    render(<Header />);
    expect(screen.getByText("nav.home")).toBeInTheDocument();
  });

  it("renders audit breadcrumb trail for audit detail", () => {
    mockUseLocation.mockReturnValue({ pathname: "/audit/abc123def" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("nav.audit")).toBeInTheDocument();
    expect(screen.getByText("abc123de...")).toBeInTheDocument();
  });

  it("shows settings title on /settings", () => {
    mockUseLocation.mockReturnValue({ pathname: "/settings" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("settings.title")).toBeInTheDocument();
  });

  it("shows memories title on /memories", () => {
    mockUseLocation.mockReturnValue({ pathname: "/memories" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("memories.title")).toBeInTheDocument();
  });

  it("renders memories breadcrumb on /memories", () => {
    mockUseLocation.mockReturnValue({ pathname: "/memories" } as ReturnType<typeof useLocation>);
    render(<Header />);
    expect(screen.getByText("nav.memories")).toBeInTheDocument();
  });
});
