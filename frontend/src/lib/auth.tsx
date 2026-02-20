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
const LOCAL_MODE = import.meta.env.VITE_LOCAL_MODE === "true";

function getInitialToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const token = getInitialToken();
    return { user: null, token, loading: !!token || LOCAL_MODE };
  });

  useEffect(() => {
    let cancelled = false;

    // Local mode: auto-obtain session without credentials
    if (LOCAL_MODE && !state.token) {
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
      return () => { cancelled = true; };
    }

    // Normal mode: validate existing token
    if (!state.token) return;
    const token = state.token;
    api
      .me(token)
      .then((user) => { if (!cancelled) setState({ user, token, loading: false }); })
      .catch(() => {
        if (cancelled) return;
        localStorage.removeItem(TOKEN_KEY);
        // In local mode, retry with local session
        if (LOCAL_MODE) {
          api.localSession()
            .then((resp) => {
              if (cancelled) return;
              localStorage.setItem(TOKEN_KEY, resp.token);
              setState({ user: resp.user, token: resp.token, loading: false });
            })
            .catch(() => {
              if (!cancelled) setState({ user: null, token: null, loading: false });
            });
        } else {
          setState({ user: null, token: null, loading: false });
        }
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
