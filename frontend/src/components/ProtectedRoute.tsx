import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth/useAuth";

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  if (user === undefined) return <p className="status">Loading…</p>;
  if (user === null) return <Navigate to="/login" replace />;
  return <>{children}</>;
}
