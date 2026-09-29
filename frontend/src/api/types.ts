// Mirrors the Pydantic response models in backend/src/sentinel_core/api/{auth,alerts}.py.
// Keep these in sync by hand for now: the surface is small and changes deliberately slowly.

export type Role = "admin" | "analyst";

export interface User {
  id: string;
  email: string;
  role: Role;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  title: string;
  severity: number;
  ts: string;
  created_at: string;
  src_ip: string | null;
  host: string | null;
  user_name: string | null;
  match_count: number;
  country_code: string | null;
  abuse_score: number | null;
  risk_score: number | null;
}
