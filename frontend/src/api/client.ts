import type {
  MFAStatus,
  MFASetup,
  Incident,
  IncidentDetail,
  IncidentStatus,
  Alert,
  AlertDetail,
  GeoSummaryRow,
  MitreSummaryRow,
  User,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// FastAPI's error body is {"detail": "a string"} for HTTPException, or
// {"detail": [{"msg": "...", ...}, ...]} for a pydantic validation error (422). Cover both so the
// UI always has a readable message instead of "[object Object]".
function detailMessage(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const first = detail[0] as { msg?: unknown } | undefined;
      if (first && typeof first.msg === "string") return first.msg;
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw new ApiError(response.status, detailMessage(body, response.statusText));
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function login(email: string, password: string, code?: string): Promise<User> {
  return request<User>("/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password, code }),
  });
}

export function logout(): Promise<void> {
  return request<void>("/v1/auth/logout", { method: "POST" });
}

export function me(): Promise<User> {
  return request<User>("/v1/auth/me");
}

export interface ListAlertsParams {
  limit?: number;
  rule?: string;
}

export function listAlerts(params: ListAlertsParams = {}): Promise<Alert[]> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.rule) query.set("rule", params.rule);
  const qs = query.toString();
  return request<Alert[]>(`/v1/alerts${qs ? `?${qs}` : ""}`);
}

export function getAlert(alertId: string): Promise<AlertDetail> {
  return request<AlertDetail>(`/v1/alerts/${encodeURIComponent(alertId)}`);
}

export function mitreSummary(days = 30): Promise<MitreSummaryRow[]> {
  return request<MitreSummaryRow[]>(`/v1/stats/mitre?days=${days}`);
}

export function geoSummary(days = 30): Promise<GeoSummaryRow[]> {
  return request<GeoSummaryRow[]>(`/v1/stats/geo?days=${days}`);
}

export function listIncidents(status?: IncidentStatus): Promise<Incident[]> {
  return request<Incident[]>(`/v1/incidents${status ? `?status=${status}` : ""}`);
}

export function createIncident(title: string, alertIds: string[]): Promise<Incident> {
  return request<Incident>("/v1/incidents", {
    method: "POST",
    body: JSON.stringify({ title, alert_ids: alertIds }),
  });
}

export function getIncident(id: string): Promise<IncidentDetail> {
  return request<IncidentDetail>(`/v1/incidents/${encodeURIComponent(id)}`);
}

export function setIncidentStatus(id: string, status: IncidentStatus): Promise<void> {
  return request<void>(`/v1/incidents/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

export function claimIncident(id: string): Promise<void> {
  return request<void>(`/v1/incidents/${encodeURIComponent(id)}/claim`, { method: "POST" });
}

export function unassignIncident(id: string): Promise<void> {
  return request<void>(`/v1/incidents/${encodeURIComponent(id)}/assignee`, { method: "DELETE" });
}

export function addIncidentNote(id: string, body: string): Promise<void> {
  return request<void>(`/v1/incidents/${encodeURIComponent(id)}/notes`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

export function linkIncidentAlerts(id: string, alertIds: string[]): Promise<void> {
  return request<void>(`/v1/incidents/${encodeURIComponent(id)}/alerts`, {
    method: "POST",
    body: JSON.stringify({ alert_ids: alertIds }),
  });
}

export function unlinkIncidentAlert(id: string, alertId: string): Promise<void> {
  return request<void>(
    `/v1/incidents/${encodeURIComponent(id)}/alerts/${encodeURIComponent(alertId)}`,
    {
      method: "DELETE",
    },
  );
}

export function mfaStatus(): Promise<MFAStatus> {
  return request<MFAStatus>("/v1/auth/2fa");
}

export function startMfa(password: string): Promise<MFASetup> {
  return request<MFASetup>("/v1/auth/2fa/setup", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function confirmMfa(password: string, code: string): Promise<{ recovery_codes: string[] }> {
  return request("/v1/auth/2fa/confirm", {
    method: "POST",
    body: JSON.stringify({ password, code }),
  });
}

export function regenerateRecoveryCodes(
  password: string,
  code: string,
): Promise<{ recovery_codes: string[] }> {
  return request("/v1/auth/2fa/recovery-codes", {
    method: "POST",
    body: JSON.stringify({ password, code }),
  });
}

export function disableMfa(password: string, code: string): Promise<void> {
  return request("/v1/auth/2fa/disable", {
    method: "POST",
    body: JSON.stringify({ password, code }),
  });
}
