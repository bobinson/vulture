import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Register } from "./Register";

vi.mock("react-router-dom", () => ({
  Link: ({ to, children }: { to: string; children: React.ReactNode }) => (
    <a href={to}>{children}</a>
  ),
  useNavigate: () => vi.fn(),
}));

vi.mock("@/lib/auth.tsx", () => ({
  useAuth: () => ({
    register: vi.fn().mockResolvedValue(undefined),
    user: null,
    token: null,
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

describe("Register", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders registration form heading", () => {
    render(<Register />);
    expect(screen.getByRole("heading", { name: "auth.createAccount" })).toBeInTheDocument();
  });

  it("renders all form fields", () => {
    render(<Register />);
    expect(screen.getByPlaceholderText("auth.namePlaceholder")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("auth.emailPlaceholder")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("auth.passwordPlaceholder")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("auth.teamPlaceholder")).toBeInTheDocument();
  });

  it("renders login link", () => {
    render(<Register />);
    const links = screen.getAllByText("auth.login");
    expect(links.length).toBeGreaterThanOrEqual(1);
  });

  it("shows password hint", () => {
    render(<Register />);
    expect(screen.getByText("auth.passwordHint")).toBeInTheDocument();
  });

  it("shows optional label for team name", () => {
    render(<Register />);
    expect(screen.getByText(/auth.optional/)).toBeInTheDocument();
  });

  it("renders submit button", () => {
    render(<Register />);
    expect(screen.getByRole("button", { name: "auth.createAccount" })).toBeInTheDocument();
  });

  it("shows error for short password", async () => {
    render(<Register />);
    fireEvent.change(screen.getByPlaceholderText("auth.namePlaceholder"), {
      target: { value: "Test User" },
    });
    fireEvent.change(screen.getByPlaceholderText("auth.emailPlaceholder"), {
      target: { value: "test@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("auth.passwordPlaceholder"), {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: "auth.createAccount" }));
    await waitFor(() => {
      expect(screen.getByText("auth.passwordTooShort")).toBeInTheDocument();
    });
  });

  it("renders subtitle text", () => {
    render(<Register />);
    expect(screen.getByText("auth.registerSubtitle")).toBeInTheDocument();
  });

  it("renders has account text", () => {
    render(<Register />);
    expect(screen.getByText(/auth.hasAccount/)).toBeInTheDocument();
  });

  it("has correct input types", () => {
    render(<Register />);
    const name = screen.getByPlaceholderText("auth.namePlaceholder") as HTMLInputElement;
    const email = screen.getByPlaceholderText("auth.emailPlaceholder") as HTMLInputElement;
    const pass = screen.getByPlaceholderText("auth.passwordPlaceholder") as HTMLInputElement;
    expect(name.type).toBe("text");
    expect(email.type).toBe("email");
    expect(pass.type).toBe("password");
  });

  it("updates name value on change", () => {
    render(<Register />);
    const name = screen.getByPlaceholderText("auth.namePlaceholder") as HTMLInputElement;
    fireEvent.change(name, { target: { value: "John" } });
    expect(name.value).toBe("John");
  });
});
