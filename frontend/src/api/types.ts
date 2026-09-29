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

export interface EvidenceEvent {
  ts: string;
  received_at: string;
  action: string;
  user_name: string | null;
  src_ip: string | null;
  raw: string;
}

export interface GeoInfo {
  country_code: string | null;
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  as_org: string | null;
}

export interface Reputation {
  source: "abuseipdb";
  score: number;
  total_reports: number;
  distinct_reporters: number;
  last_reported_at: string | null;
  usage_type: string | null;
  isp: string | null;
  is_tor: boolean;
  is_whitelisted: boolean;
  checked_at: string;
}

export interface Enrichment {
  ip_scope: "public" | "non_public";
  geo: GeoInfo | null;
  reputation: Reputation | null;
}

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface RiskFactor {
  name: string;
  points: number;
  reason: string;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  factors: RiskFactor[];
}

export interface AlertDetail {
  alert: Alert;
  mitre: string[];
  group: Record<string, unknown>;
  evidence: EvidenceEvent[];
  incident_id: string | null;
  detection_latency_ms: number | null;
  enrichment: Enrichment | null;
  risk: RiskAssessment | null;
}

export interface MitreSummaryRow {
  technique: string;
  count: number;
  latest_ts: string;
}

export interface GeoSummaryRow {
  country_code: string | null;
  country: string | null;
  city: string | null;
  latitude: number;
  longitude: number;
  count: number;
  max_risk_score: number | null;
  latest_ts: string;
}

export type IncidentStatus = "new" | "investigating" | "closed";

export interface Incident {
  id: string;
  title: string;
  status: IncidentStatus;
  assignee_email: string | null;
  created_at: string;
  closed_at: string | null;
  alert_count: number;
  max_risk_score: number | null;
}

export interface IncidentDetail {
  summary: Incident;
  alerts: Alert[];
  notes: { id: string; author_email: string; body: string; created_at: string }[];
}

export interface MFAStatus {
  enabled: boolean;
  setup_available: boolean;
  recovery_codes_remaining: number;
}

export interface MFASetup {
  secret: string;
  provisioning_uri: string;
  expires_at: string;
}
