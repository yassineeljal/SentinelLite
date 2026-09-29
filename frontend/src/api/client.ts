import type { Alert, AlertDetail, MitreSummaryRow, User } from "./types";

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

export function login(email: string, password: string): Promise<User> {
  return request<User>("/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
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
