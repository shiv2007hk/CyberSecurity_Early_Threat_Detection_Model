import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getStoredUser, getToken, setStoredUser, setToken, type User } from "../lib/api";

interface AuthState {
  user: User | null;
  initializing: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (payload: { full_name: string; email: string; password: string }) => Promise<User>;
  logout: () => Promise<void>;
  updateUser: (user: User) => void;
  can: (minimum: "viewer" | "analyst" | "admin") => boolean;
}

const AuthContext = createContext<AuthState>({
  user: null,
  initializing: true,
  login: async () => {
    throw new Error("Auth not ready");
  },
  register: async () => {
    throw new Error("Auth not ready");
  },
  logout: async () => {},
  updateUser: () => {},
  can: () => false,
});

const RANK = { viewer: 1, analyst: 2, admin: 3 } as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getStoredUser());
  const [initializing, setInitializing] = useState(true);

  const updateUser = useCallback((next: User) => {
    setUser(next);
    setStoredUser(next);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const bootstrap = async () => {
      if (!getToken()) {
        setInitializing(false);
        return;
      }
      try {
        const me = await api<User>("/auth/me");
        if (!cancelled) updateUser(me);
      } catch {
        if (!cancelled) {
          setToken(null);
          setStoredUser(null);
          setUser(null);
        }
      } finally {
        if (!cancelled) setInitializing(false);
      }
    };
    bootstrap();
    const onUnauthorized = () => {
      setToken(null);
      setStoredUser(null);
      setUser(null);
    };
    window.addEventListener("aegis:unauthorized", onUnauthorized);
    return () => {
      cancelled = true;
      window.removeEventListener("aegis:unauthorized", onUnauthorized);
    };
  }, [updateUser]);

  const login = useCallback(
    async (email: string, password: string) => {
      const result = await api<{ access_token: string; user: User }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setToken(result.access_token);
      updateUser(result.user);
      return result.user;
    },
    [updateUser],
  );

  const register = useCallback(
    async (payload: { full_name: string; email: string; password: string }) => {
      const result = await api<{ access_token: string; user: User }>("/auth/register", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setToken(result.access_token);
      updateUser(result.user);
      return result.user;
    },
    [updateUser],
  );

  const logout = useCallback(async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* Local session must clear even if the audit call fails. */
    }
    setToken(null);
    setStoredUser(null);
    setUser(null);
  }, []);

  const can = useCallback(
    (minimum: "viewer" | "analyst" | "admin") => {
      if (!user) return false;
      return RANK[user.role] >= RANK[minimum];
    },
    [user],
  );

  const value = useMemo(
    () => ({ user, initializing, login, register, logout, updateUser, can }),
    [user, initializing, login, register, logout, updateUser, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
