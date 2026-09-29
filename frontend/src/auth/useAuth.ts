import { createContext, useContext } from "react";
import type { User } from "../api/types";

export interface AuthState {
  // undefined: not checked yet (the app is asking GET /v1/auth/me). null: checked, not logged in.
  user: User | null | undefined;
  login: (email: string, password: string, code?: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const state = useContext(AuthContext);
  if (state === null) throw new Error("useAuth() must be used inside an <AuthProvider>");
  return state;
}
