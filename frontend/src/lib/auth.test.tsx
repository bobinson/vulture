import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import type { MockInstance } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { AuthProvider, useAuth } from "./auth";
import type { ReactNode } from "react";

// Feature 0102: the session is an HttpOnly cookie. The provider keeps no
// credential (the legacy key is purged), boots with me() and then a local
// session, and clears the session only on a confirmed logout.

vi.mock("./api.ts", () => ({
  api: {
    me: vi.fn(),
    login: vi.fn(),
    register: vi.fn(),
    localSession: vi.fn(),
    logout: vi.fn(),
  },
}));

import { api } from "./api.ts";

const mockMe = vi.mocked(api.me);
const mockLogin = vi.mocked(api.login);
const mockRegister = vi.mocked(api.register);
const mockLocalSession = vi.mocked(api.localSession);
const mockLogout = vi.mocked(api.logout);

const SAMPLE_USER = {
  id: "user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};

const LEGACY_KEY = "vulture_token";
const CREDENTIAL_KEY = /token|jwt|session/i;
const LOGOUT_CAP_MS = 3_000;

let setItem: MockInstance<Storage["setItem"]>;

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

function credentialWrites(): unknown[][] {
  return setItem.mock.calls.filter(([key]) => CREDENTIAL_KEY.test(String(key)));
}

async function renderBooted() {
  const { result } = renderHook(() => useAuth(), { wrapper });
  await waitFor(() => expect(result.current.loading).toBe(false));
  return result;
}

// Signed in through login(), so a logout test does not depend on the boot.
async function renderSignedIn() {
  mockLogin.mockResolvedValue({ user: SAMPLE_USER });
  const result = await renderBooted();
  await act(async () => {
    await result.current.login("test@example.com", "password123");
  });
  expect(result.current.user).toEqual(SAMPLE_USER);
  return result;
}

function signalOf(arg: unknown): AbortSignal | undefined {
  return arg instanceof AbortSignal ? arg : (arg as { signal?: AbortSignal } | undefined)?.signal;
}

// A logout the server never answers: it settles only if the caller aborts it.
function stalledLogout(arg?: unknown): Promise<void> {
  return new Promise((_resolve, reject) => {
    signalOf(arg)?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  });
}

beforeEach(() => {
  [mockMe, mockLogin, mockRegister, mockLocalSession, mockLogout].forEach((m) => m.mockReset());
  // Default: no cookie session and no local mode (a centralized server).
  mockMe.mockRejectedValue(new Error("not authenticated"));
  mockLocalSession.mockRejectedValue(new Error("not found"));
  localStorage.clear();
  setItem = vi.spyOn(localStorage, "setItem");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useAuth", () => {
  it("throws when used outside AuthProvider", () => {
    expect(() => {
      renderHook(() => useAuth());
    }).toThrow("useAuth must be used within AuthProvider");
  });
});

describe("boot", () => {
  it("purges the legacy vulture_token and never sends it", async () => {
    localStorage.setItem(LEGACY_KEY, "legacy-jwt");
    setItem.mockClear();

    await renderBooted();

    expect(localStorage.getItem(LEGACY_KEY)).toBeNull();
    expect(mockMe).toHaveBeenCalledTimes(1);
    expect(mockMe).toHaveBeenCalledWith();
  });

  it("survives Web Storage that throws", async () => {
    for (const method of ["getItem", "setItem", "removeItem"] as const) {
      vi.spyOn(localStorage, method).mockImplementation(() => {
        throw new DOMException("storage is blocked", "SecurityError");
      });
    }
    mockMe.mockResolvedValue(SAMPLE_USER);

    const result = await renderBooted();

    expect(result.current.user).toEqual(SAMPLE_USER);
  });

  it("validates the cookie session with me() and skips the local session", async () => {
    mockMe.mockResolvedValue(SAMPLE_USER);

    const result = await renderBooted();

    expect(result.current.user).toEqual(SAMPLE_USER);

    expect(mockMe).toHaveBeenCalledTimes(1);
    expect(mockMe).toHaveBeenCalledWith();
    expect(mockLocalSession).not.toHaveBeenCalled();
    expect(result.current).not.toHaveProperty("token");
  });

  it("falls back to exactly one local session after me() fails", async () => {
    mockLocalSession.mockResolvedValue({ user: SAMPLE_USER });

    const result = await renderBooted();

    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(mockMe).toHaveBeenCalledTimes(1);
    expect(mockLocalSession).toHaveBeenCalledTimes(1);
    expect(mockMe.mock.invocationCallOrder[0]).toBeLessThan(mockLocalSession.mock.invocationCallOrder[0]);
    expect(credentialWrites()).toEqual([]);
  });

  it("ends unauthenticated when neither me() nor a local session works", async () => {
    const result = await renderBooted();

    expect(result.current.user).toBeNull();
    expect(mockMe).toHaveBeenCalledTimes(1);
    expect(mockLocalSession).toHaveBeenCalledTimes(1);
  });
});

describe("sign in", () => {
  // A body token (an older backend, or a header-less request) is ignored.
  it("login keeps only the user", async () => {
    mockLogin.mockResolvedValue({ user: SAMPLE_USER, token: "body-jwt" });
    const result = await renderBooted();

    await act(async () => {
      await result.current.login("test@example.com", "password123");
    });

    expect(mockLogin).toHaveBeenCalledWith({ email: "test@example.com", password: "password123" });
    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current).not.toHaveProperty("token");
    expect(credentialWrites()).toEqual([]);
  });

  it("register keeps only the user", async () => {
    mockRegister.mockResolvedValue({ user: SAMPLE_USER, token: "body-jwt" });
    const result = await renderBooted();

    await act(async () => {
      await result.current.register("test@example.com", "password123", "Test User", "Team A");
    });

    expect(mockRegister).toHaveBeenCalledWith({
      email: "test@example.com",
      password: "password123",
      name: "Test User",
      team_name: "Team A",
    });
    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current).not.toHaveProperty("token");
    expect(credentialWrites()).toEqual([]);
  });
});

describe("logout", () => {
  it("clears the session only once the server confirms", async () => {
    const result = await renderSignedIn();
    let confirm!: () => void;
    mockLogout.mockReturnValue(new Promise<void>((resolve) => (confirm = resolve)));

    act(() => result.current.logout());

    expect(mockLogout).toHaveBeenCalledTimes(1);
    expect(result.current.user).toEqual(SAMPLE_USER);
    await act(async () => confirm());
    await waitFor(() => expect(result.current.user).toBeNull());
    expect(result.current.logoutFailed).toBe(false);
    expect(result.current.loading).toBe(false);
  });

  it.each([
    ["a server error", () => Promise.reject(Object.assign(new Error("internal error"), { status: 500 }))],
    ["a network error", () => Promise.reject(new TypeError("Failed to fetch"))],
    ["an abort", () => Promise.reject(new DOMException("aborted", "AbortError"))],
  ])("keeps the session and sets logoutFailed after %s", async (_name, failure) => {
    const result = await renderSignedIn();
    mockLogout.mockImplementation(failure);

    act(() => result.current.logout());

    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    expect(result.current.user).toEqual(SAMPLE_USER);
    expect(result.current.loading).toBe(false);
  });

  it("gives up on a stalled logout after 3 s and keeps the session", async () => {
    const result = await renderSignedIn();
    mockLogout.mockImplementation(stalledLogout);
    const started = Date.now();

    act(() => result.current.logout());

    expect(result.current.logoutFailed).toBe(false);
    await waitFor(() => expect(result.current.logoutFailed).toBe(true), { timeout: LOGOUT_CAP_MS + 2_000 });
    expect(Date.now() - started).toBeGreaterThanOrEqual(LOGOUT_CAP_MS - 100);
    expect(result.current.user).toEqual(SAMPLE_USER);
  }, 10_000);

  it("a retry after a failed logout signs out once the server confirms", async () => {
    const result = await renderSignedIn();
    mockLogout.mockRejectedValueOnce(new TypeError("Failed to fetch")).mockResolvedValueOnce(undefined);

    act(() => result.current.logout());
    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    act(() => result.current.logout());

    await waitFor(() => expect(result.current.user).toBeNull());
    expect(result.current.logoutFailed).toBe(false);
    expect(mockLogout).toHaveBeenCalledTimes(2);
  });
});
