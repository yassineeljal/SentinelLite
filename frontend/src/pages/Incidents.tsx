import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, createIncident, listIncidents } from "../api/client";
import type { Incident, IncidentStatus } from "../api/types";

import { statusBadge, statusLabels } from "../incidentStatus";

export function Incidents() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const alertId = params.get("alert") ?? "";
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [status, setStatus] = useState<IncidentStatus | "">("");
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    listIncidents(status || undefined).then(
      (rows) => {
        if (active) {
          setIncidents(rows);
          setError(null);
        }
      },
      (err: unknown) => {
        if (active) setError(err instanceof ApiError ? err.message : "Could not load incidents");
      },
    );
    return () => {
      active = false;
    };
  }, [status, revision]);

  async function create(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setCreateError(null);
    try {
      const incident = await createIncident(title.trim(), alertId ? [alertId] : []);
      navigate(`/incidents/${incident.id}`);
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.message : "Could not create incident");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="incidents-page">
      <div className="alerts-toolbar">
        <h1>Incidents</h1>
        <label>
          Status
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as IncidentStatus | "");
              setIncidents(null);
              setError(null);
            }}
          >
            <option value="">All statuses</option>
            {Object.entries(statusLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => {
            setIncidents(null);
            setError(null);
            setRevision((n) => n + 1);
          }}
        >
          Refresh
        </button>
      </div>
      <form className="incident-form" onSubmit={create}>
        <h2>Create incident</h2>
        {alertId && (
          <p>
            Include <Link to={`/alerts/${encodeURIComponent(alertId)}`}>the selected alert</Link>.
          </p>
        )}
        <label>
          Title
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
            maxLength={200}
          />
        </label>
        <button disabled={busy || !title.trim()}>{busy ? "Creating…" : "Create incident"}</button>
        {createError && (
          <p className="error" role="alert">
            {createError}
          </p>
        )}
      </form>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!incidents && !error && <p className="status">Loading…</p>}
      {incidents?.length === 0 && <p className="status">No incidents.</p>}
      {incidents && incidents.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>Alerts</th>
                <th>Highest risk</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id}>
                  <td>
                    <Link to={`/incidents/${incident.id}`}>{incident.title}</Link>
                  </td>
                  <td>
                    <span className={`badge ${statusBadge[incident.status]}`}>
                      {statusLabels[incident.status]}
                    </span>
                  </td>
                  <td>{incident.assignee_email ?? "Unassigned"}</td>
                  <td>{incident.alert_count}</td>
                  <td>{incident.max_risk_score ?? "Not scored"}</td>
                  <td>{new Date(incident.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
