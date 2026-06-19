import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
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
  token: string | null;
  loading: boolean;
}

interface AuthContextValue extends AuthState {
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

const TOKEN_KEY = "vulture_token";

function getInitialToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const token = getInitialToken();
    // Always start in loading: we resolve auth (existing token OR a
    // passwordless local session) before deciding to show /login.
    return { user: null, token, loading: true };
  });

  useEffect(() => {
    let cancelled = false;

    // Passwordless local session — RUNTIME-detected (not a build flag): the
    // backend returns a token only when VULTURE_LOCAL_MODE is on AND the host
    // is loopback; otherwise it 404s and we fall through to /login. This makes
    // a native/local install auto-login with no credentials, while a
    // centralized (Mode B) server still requires sign-in (0055).
    const tryLocalSession = () => {
      api
        .localSession()
        .then((resp) => {
          if (cancelled) return;
          localStorage.setItem(TOKEN_KEY, resp.token);
          setState({ user: resp.user, token: resp.token, loading: false });
        })
        .catch(() => {
          if (!cancelled) setState({ user: null, token: null, loading: false });
        });
    };

    // No token: attempt a local session.
    if (!state.token) {
      tryLocalSession();
      return () => { cancelled = true; };
    }

    // Have a token: validate it; on failure drop it and retry a local session.
    const token = state.token;
    api
      .me(token)
      .then((user) => { if (!cancelled) setState({ user, token, loading: false }); })
      .catch(() => {
        if (cancelled) return;
        localStorage.removeItem(TOKEN_KEY);
        tryLocalSession();
      });
    return () => { cancelled = true; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(async (email: string, password: string) => {
    const resp = await api.login({ email, password });
    localStorage.setItem(TOKEN_KEY, resp.token);
    setState({ user: resp.user, token: resp.token, loading: false });
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
      localStorage.setItem(TOKEN_KEY, resp.token);
      setState({ user: resp.user, token: resp.token, loading: false });
    },
    []
  );

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setState({ user: null, token: null, loading: false });
  }, []);

  const value = useMemo(
    () => ({ ...state, login, register, logout }),
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
