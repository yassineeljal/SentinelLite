import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, listAlerts } from "../api/client";
import type { Alert } from "../api/types";

const REFRESH_MS = 15_000;

function riskLevel(score: number | null): string {
  if (score === null) return "unknown";
  if (score >= 95) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  });
}

export function Alerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [rule, setRule] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback((ruleFilter: string) => {
    listAlerts({ limit: 100, rule: ruleFilter || undefined }).then(
      (found) => {
        setAlerts(found);
        setError(null);
      },
      (err: unknown) => setError(err instanceof ApiError ? err.message : "Could not load alerts"),
    );
  }, []);

  useEffect(() => {
    refresh(rule);
    const id = setInterval(() => refresh(rule), REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh, rule]);

  return (
    <main className="alerts-page">
      <div className="alerts-toolbar">
        <h1>Alerts</h1>
        <label>
          Rule
          <input
            type="text"
            placeholder="e.g. ssh-bruteforce"
            value={rule}
            onChange={(e) => setRule(e.target.value)}
          />
        </label>
        <button type="button" onClick={() => refresh(rule)}>
          Refresh
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {alerts === null && !error && <p className="status">Loading…</p>}
      {alerts !== null && alerts.length === 0 && <p className="status">No alerts.</p>}
      {alerts !== null && alerts.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Rule</th>
                <th>Host</th>
                <th>User</th>
                <th>Source</th>
                <th>Country</th>
                <th>Abuse</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.alert_id}
                  className="clickable-row"
                  onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                >
                  <td>{formatTime(alert.ts)}</td>
                  <td>
                    <span className={`risk risk-${riskLevel(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    {alert.risk_score === null ? (
                      "—"
                    ) : (
                      <span className={`risk risk-${riskLevel(alert.risk_score)}`}>
                        {alert.risk_score}
                      </span>
                    )}
                  </td>
                  <td>
                    <Link to={`/alerts/${alert.alert_id}`} title={alert.title}>
                      {alert.rule_id}
                    </Link>
                  </td>
                  <td>{alert.host ?? "—"}</td>
                  <td>{alert.user_name ?? "—"}</td>
                  <td>{alert.src_ip ?? "—"}</td>
                  <td>{alert.country_code ?? "—"}</td>
                  <td>{alert.abuse_score ?? "—"}</td>
                  <td>{alert.match_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
