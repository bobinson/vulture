import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { AuthProvider, useAuth } from "./auth";
import type { ReactNode } from "react";

vi.mock("./api.ts", () => ({
  api: {
    me: vi.fn(),
    login: vi.fn(),
    register: vi.fn(),
    localSession: vi.fn(),
  },
}));

import { api } from "./api.ts";

const mockMe = vi.mocked(api.me);
const mockLogin = vi.mocked(api.login);
const mockRegister = vi.mocked(api.register);
const mockLocalSession = vi.mocked(api.localSession);

const SAMPLE_USER = {
  id: "user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

beforeEach(() => {
  mockMe.mockReset();
  mockLogin.mockReset();
  mockRegister.mockReset();
  mockLocalSession.mockReset();
  // Default: no local session (simulates a non-local/centralized server,
  // where /api/auth/local-session 404s). Tests that exercise local-mode
  // auto-login override this to resolve.
  mockLocalSession.mockRejectedValue(new Error("not found"));
  localStorage.clear();
});

describe("useAuth", () => {
  it("throws when used outside AuthProvider", () => {
    expect(() => {
      renderHook(() => useAuth());
    }).toThrow("useAuth must be used within AuthProvider");
  });

  it("starts loading, probes local session, resolves to no user when none", async () => {
    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    // Runtime detection: it ALWAYS probes the passwordless local session;
    // here it 404s (non-local) so we land unauthenticated → /login.
    expect(mockLocalSession).toHaveBeenCalled();
    expect(result.current.user).toBeNull();
    expect(result.current.token).toBeNull();
  });

  it("auto-logs-in via local session (local mode) with no token", async () => {
    mockLocalSession.mockResolvedValue({ user: SAMPLE_USER, token: "local-jwt" });

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current.token).toBe("local-jwt");
    expect(localStorage.getItem("vulture_token")).toBe("local-jwt");
    expect(mockMe).not.toHaveBeenCalled(); // no token → straight to local session
  });

  it("fetches user profile when token exists in localStorage", async () => {
    localStorage.setItem("vulture_token", "saved-jwt");
    mockMe.mockResolvedValue(SAMPLE_USER);

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current.token).toBe("saved-jwt");
    expect(mockMe).toHaveBeenCalledWith("saved-jwt");
  });

  it("clears token when me() fails", async () => {
    localStorage.setItem("vulture_token", "bad-token");
    mockMe.mockRejectedValue(new Error("Unauthorized"));

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    expect(result.current.user).toBeNull();
    expect(result.current.token).toBeNull();
    expect(localStorage.getItem("vulture_token")).toBeNull();
  });

  it("login saves token and sets user", async () => {
    mockLogin.mockResolvedValue({ user: SAMPLE_USER, token: "new-jwt" });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.login("test@example.com", "password123");
    });

    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current.token).toBe("new-jwt");
    expect(localStorage.getItem("vulture_token")).toBe("new-jwt");
  });

  it("register saves token and sets user", async () => {
    mockRegister.mockResolvedValue({ user: SAMPLE_USER, token: "reg-jwt" });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.register("test@example.com", "password123", "Test User", "Team A");
    });

    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current.token).toBe("reg-jwt");
    expect(localStorage.getItem("vulture_token")).toBe("reg-jwt");
    expect(mockRegister).toHaveBeenCalledWith({
      email: "test@example.com",
      password: "password123",
      name: "Test User",
      team_name: "Team A",
    });
  });

  it("logout clears user and token", async () => {
    mockLogin.mockResolvedValue({ user: SAMPLE_USER, token: "jwt-1" });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.login("test@example.com", "pass");
    });
    expect(result.current.user).not.toBeNull();

    act(() => {
      result.current.logout();
    });

    expect(result.current.user).toBeNull();
    expect(result.current.token).toBeNull();
    expect(localStorage.getItem("vulture_token")).toBeNull();
  });
});
