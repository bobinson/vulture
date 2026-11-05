import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { api } from "./api.ts";

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  team_id?: string;
  created_at: string;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  // Sign-outs the server did not confirm since the last sign-in or sign-out,
  // so the session is kept. A count, not a flag: the UI can tell a repeat
  // failure from the one already on screen and announce it again.
  logoutFailures: number;
  // A sign-out request is in flight.
  logoutPending: boolean;
}

interface AuthContextValue extends AuthState {
  // The last sign-out was not confirmed by the server (logoutFailures > 0).
  logoutFailed: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    email: string,
    password: string,
    name: string,
    teamName?: string
  ) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// The bearer token an older SPA kept in Web Storage. It is only ever removed.
const LEGACY_TOKEN_KEY = "vulture_token";
const LOGOUT_TIMEOUT_MS = 3000;
const BOOTING: AuthState = { user: null, loading: true, logoutFailures: 0, logoutPending: false };

// Auth is resolved: to a user, or to signed out (null).
function resolved(user: User | null): AuthState {
  return { user, loading: false, logoutFailures: 0, logoutPending: false };
}

// Sign-out updaters. Only resolved() clears the failure count, so a retry
// keeps the failure line (and a focused Retry button in it) on screen while it
// runs.
const signingOut = (s: AuthState): AuthState => ({ ...s, logoutPending: true });
const signOutFailed = (s: AuthState): AuthState => ({
  ...s,
  logoutFailures: s.logoutFailures + 1,
  logoutPending: false,
});

function purgeLegacyToken() {
  try {
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  } catch {
    // Web Storage is blocked: there is nothing to purge.
  }
}

// The session is an HttpOnly cookie (feature 0102): no credential is kept in
// Web Storage or in this context, and only the server can end the session.
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(BOOTING);

  useEffect(() => {
    purgeLegacyToken();
    let cancelled = false;
    const settle = (user: User | null) => {
      if (!cancelled) setState(resolved(user));
    };
    // The cookie session first. Then the passwordless local session, which is
    // RUNTIME-detected (not a build flag): the backend grants it only when
    // VULTURE_LOCAL_MODE is on AND the host is loopback, so a native/local
    // install signs in with no credentials while a centralized (Mode B) server
    // answers an error and the user lands on /login (0055).
    api
      .me()
      .catch(() => api.localSession().then((resp) => resp.user))
      .then(settle, () => settle(null));
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const resp = await api.login({ email, password });
    setState(resolved(resp.user));
  }, []);

  const register = useCallback(
    async (
      email: string,
      password: string,
      name: string,
      teamName?: string
    ) => {
      const resp = await api.register({
        email,
        password,
        name,
        team_name: teamName,
      });
      setState(resolved(resp.user));
    },
    []
  );

  // Signed out only once the server confirms (it clears the cookie). A failure,
  // or no answer within LOGOUT_TIMEOUT_MS, keeps the session and counts in
  // logoutFailures, so the UI can offer a retry instead of a /login page shown
  // over a cookie that still works. One request at a time: a call while one
  // is in flight is ignored (the timeout bounds how long that lasts), so two
  // overlapping answers cannot leave the flags out of step with the session.
  const logoutInFlight = useRef(false);
  const logout = useCallback(() => {
    if (logoutInFlight.current) return;
    logoutInFlight.current = true;
    setState(signingOut);
    api
      .logout(AbortSignal.timeout(LOGOUT_TIMEOUT_MS))
      .then(
        () => setState(resolved(null)),
        () => setState(signOutFailed)
      )
      .finally(() => {
        logoutInFlight.current = false;
      });
  }, []);

  const value = useMemo(
    () => ({ ...state, logoutFailed: state.logoutFailures > 0, login, register, logout }),
    [state, login, register, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
