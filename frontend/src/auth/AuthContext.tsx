import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import * as api from "../api/client";
import type { User } from "../api/types";
import { AuthContext } from "./useAuth";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);

  useEffect(() => {
    api.me().then(setUser, () => setUser(null));
  }, []);

  const login = useCallback(async (email: string, password: string, code?: string) => {
    setUser(await api.login(email, password, code));
  }, []);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  return <AuthContext.Provider value={{ user, login, logout }}>{children}</AuthContext.Provider>;
}
