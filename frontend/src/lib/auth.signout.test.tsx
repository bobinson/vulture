import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "./auth";

// One sign-out request at a time. While it is in flight the context reports
// logoutPending and ignores another call, so two overlapping answers cannot
// leave the flags out of step with the session. A failed sign-out keeps
// logoutFailed set until the server confirms a retry: the failure line, and a
// focused Retry button in it, stay on screen while the retry runs.

vi.mock("./api.ts", () => ({
  api: { me: vi.fn(), localSession: vi.fn(), logout: vi.fn() },
}));

import { api } from "./api.ts";

const mockLogout = vi.mocked(api.logout);

const USER = {
  id: "user-1",
  email: "test@example.com",
  name: "Test User",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
};

const NETWORK_ERROR = new TypeError("Failed to fetch");

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

// A logout the test answers by hand, so it can look at the state in flight.
function heldLogout() {
  let confirm!: () => void;
  let fail!: () => void;
  mockLogout.mockReturnValueOnce(
    new Promise<void>((resolve, reject) => {
      confirm = resolve;
      fail = () => reject(NETWORK_ERROR);
    }),
  );
  return { confirm: () => act(async () => confirm()), fail: () => act(async () => fail()) };
}

// Signed in, with every rendered value of logoutFailed recorded in `seen`.
async function renderSignedIn() {
  vi.mocked(api.me).mockResolvedValue(USER);
  const seen: boolean[] = [];
  const { result } = renderHook(
    () => {
      const auth = useAuth();
      seen.push(auth.logoutFailed);
      return auth;
    },
    { wrapper },
  );
  await waitFor(() => expect(result.current.user).toEqual(USER));
  return { result, seen };
}

beforeEach(() => {
  vi.mocked(api.me).mockReset();
  vi.mocked(api.localSession).mockReset();
  mockLogout.mockReset();
});

describe("sign-out in flight", () => {
  it("reports logoutPending while the request runs and clears it when it fails", async () => {
    const { result } = await renderSignedIn();
    const answer = heldLogout();
    expect(result.current.logoutPending).toBe(false);

    act(() => result.current.logout());

    expect(result.current.logoutPending).toBe(true);
    await answer.fail();
    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    expect(result.current.logoutPending).toBe(false);
    expect(result.current.user).toEqual(USER);
  });

  it("sends one request however often sign-out is called while it runs", async () => {
    const { result } = await renderSignedIn();
    const answer = heldLogout();

    act(() => {
      result.current.logout();
      result.current.logout();
    });
    act(() => result.current.logout());

    expect(mockLogout).toHaveBeenCalledTimes(1);
    await answer.confirm();
    await waitFor(() => expect(result.current.user).toBeNull());
    expect(result.current.logoutPending).toBe(false);
    expect(result.current.logoutFailed).toBe(false);
  });

  it("accepts a new sign-out once the previous one has failed", async () => {
    const { result } = await renderSignedIn();
    mockLogout.mockRejectedValueOnce(NETWORK_ERROR);

    act(() => result.current.logout());
    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    heldLogout();
    act(() => result.current.logout());

    expect(mockLogout).toHaveBeenCalledTimes(2);
  });
});

describe("retry after a failed sign-out", () => {
  it("keeps logoutFailed set while the retry runs and clears it only on a confirmed sign-out", async () => {
    const { result } = await renderSignedIn();
    mockLogout.mockRejectedValueOnce(NETWORK_ERROR);
    act(() => result.current.logout());
    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    const retry = heldLogout();

    act(() => result.current.logout());

    expect(result.current.logoutFailed).toBe(true);
    expect(result.current.logoutPending).toBe(true);
    await retry.confirm();
    await waitFor(() => expect(result.current.user).toBeNull());
    expect(result.current.logoutFailed).toBe(false);
    expect(result.current.logoutPending).toBe(false);
  });

  it("keeps logoutFailed set, with no flicker, when the retry fails again", async () => {
    const { result, seen } = await renderSignedIn();
    mockLogout.mockRejectedValueOnce(NETWORK_ERROR);
    act(() => result.current.logout());
    await waitFor(() => expect(result.current.logoutFailed).toBe(true));
    const retry = heldLogout();
    const firstFailure = seen.length;

    act(() => result.current.logout());
    await retry.fail();

    expect(seen.slice(firstFailure)).not.toContain(false);
    expect(result.current.logoutFailed).toBe(true);
    expect(result.current.logoutPending).toBe(false);
    expect(result.current.user).toEqual(USER);
  });

  // The count tells a repeat failure apart from the one already on screen, so
  // the UI can announce it again.
  it("counts each failed sign-out and clears the count only on a confirmed sign-out", async () => {
    const { result } = await renderSignedIn();
    expect(result.current.logoutFailures).toBe(0);
    mockLogout.mockRejectedValueOnce(NETWORK_ERROR);

    act(() => result.current.logout());
    await waitFor(() => expect(result.current.logoutFailures).toBe(1));
    const retry = heldLogout();
    act(() => result.current.logout());
    expect(result.current.logoutFailures).toBe(1);
    await retry.fail();
    await waitFor(() => expect(result.current.logoutFailures).toBe(2));
    expect(result.current.logoutFailed).toBe(true);

    const last = heldLogout();
    act(() => result.current.logout());
    await last.confirm();
    await waitFor(() => expect(result.current.user).toBeNull());
    expect(result.current.logoutFailures).toBe(0);
    expect(result.current.logoutFailed).toBe(false);
  });
});
