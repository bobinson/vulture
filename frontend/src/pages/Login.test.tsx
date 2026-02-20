import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Login } from "./Login";

vi.mock("react-router-dom", () => ({
  Link: ({ to, children }: { to: string; children: React.ReactNode }) => (
    <a href={to}>{children}</a>
  ),
  useNavigate: () => vi.fn(),
}));

vi.mock("@/lib/auth.tsx", () => ({
  useAuth: () => ({
    login: vi.fn().mockResolvedValue(undefined),
    user: null,
    token: null,
    loading: false,
    register: vi.fn(),
    logout: vi.fn(),
  }),
}));

describe("Login", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders login heading", () => {
    render(<Login />);
    expect(screen.getByRole("heading", { name: "auth.login" })).toBeInTheDocument();
  });

  it("renders email and password inputs", () => {
    render(<Login />);
    expect(screen.getByPlaceholderText("auth.emailPlaceholder")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("auth.passwordPlaceholder")).toBeInTheDocument();
  });

  it("renders logo text", () => {
    render(<Login />);
    expect(screen.getByText("ulture")).toBeInTheDocument();
  });

  it("renders register link", () => {
    render(<Login />);
    expect(screen.getByText("auth.register")).toBeInTheDocument();
  });

  it("renders submit button", () => {
    render(<Login />);
    expect(screen.getByRole("button", { name: "auth.login" })).toBeInTheDocument();
  });

  it("renders subtitle text", () => {
    render(<Login />);
    expect(screen.getByText("auth.loginSubtitle")).toBeInTheDocument();
  });

  it("renders no account text", () => {
    render(<Login />);
    expect(screen.getByText(/auth.noAccount/)).toBeInTheDocument();
  });

  it("has email and password fields", () => {
    render(<Login />);
    const email = screen.getByPlaceholderText("auth.emailPlaceholder") as HTMLInputElement;
    const pass = screen.getByPlaceholderText("auth.passwordPlaceholder") as HTMLInputElement;
    expect(email.type).toBe("email");
    expect(pass.type).toBe("password");
  });

  it("updates email value on change", () => {
    render(<Login />);
    const email = screen.getByPlaceholderText("auth.emailPlaceholder") as HTMLInputElement;
    fireEvent.change(email, { target: { value: "user@test.com" } });
    expect(email.value).toBe("user@test.com");
  });

  it("updates password value on change", () => {
    render(<Login />);
    const pass = screen.getByPlaceholderText("auth.passwordPlaceholder") as HTMLInputElement;
    fireEvent.change(pass, { target: { value: "secret123" } });
    expect(pass.value).toBe("secret123");
  });
});
