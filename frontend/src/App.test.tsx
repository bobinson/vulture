import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// Mock all page components to simple stubs
vi.mock("@/pages/Dashboard.tsx", () => ({
  Dashboard: () => <div data-testid="dashboard-page">Dashboard</div>,
}));
vi.mock("@/pages/AuditNew.tsx", () => ({
  AuditNew: () => <div data-testid="audit-page">AuditNew</div>,
}));
vi.mock("@/pages/AuditResults.tsx", () => ({
  AuditResults: () => <div data-testid="results-page">AuditResults</div>,
}));
vi.mock("@/pages/Settings.tsx", () => ({
  Settings: () => <div data-testid="settings-page">Settings</div>,
}));
vi.mock("@/pages/Memories.tsx", () => ({
  Memories: () => <div data-testid="memories-page">Memories</div>,
}));
vi.mock("@/pages/Login.tsx", () => ({
  Login: () => <div data-testid="login-page">Login</div>,
}));
vi.mock("@/pages/Register.tsx", () => ({
  Register: () => <div data-testid="register-page">Register</div>,
}));
vi.mock("@/components/layout/Layout.tsx", async () => {
  const { Outlet } = await import("react-router-dom");
  return {
    Layout: () => (
      <div data-testid="layout">
        <Outlet />
      </div>
    ),
  };
});

// Mock auth to return authenticated user by default
vi.mock("@/lib/auth.tsx", async () => {
  const React = await import("react");
  return {
    AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    useAuth: () => ({
      user: { id: "u1", name: "Test", email: "t@t.com", role: "admin", created_at: "" },
      token: "tok",
      loading: false,
      login: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
    }),
  };
});

import { App } from "./App";

describe("App", () => {
  it("renders without crashing", () => {
    render(<App />);
    // When authenticated and at "/", should show dashboard
    expect(screen.getByTestId("dashboard-page")).toBeInTheDocument();
  });

  it("renders layout wrapper for authenticated routes", () => {
    render(<App />);
    expect(screen.getByTestId("layout")).toBeInTheDocument();
  });
});
