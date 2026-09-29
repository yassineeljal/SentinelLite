import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../api/client";
import type { Alert, IncidentDetail as Detail, IncidentStatus } from "../api/types";
import { statusLabels } from "../incidentStatus";

export function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [alertError, setAlertError] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [alertId, setAlertId] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    if (!incidentId) return;
    let active = true;
    api.getIncident(incidentId).then(
      (found) => {
        if (active) {
          setDetail(found);
          setError(null);
        }
      },
      (err: unknown) => {
        if (active) setError(err instanceof api.ApiError ? err.message : "Could not load incident");
      },
    );
    return () => {
      active = false;
    };
  }, [incidentId, revision]);

  useEffect(() => {
    let active = true;
    api.listAlerts({ limit: 200 }).then(
      (found) => {
        if (active) setAlerts(found);
      },
      () => {
        if (active)
          setAlertError("Recent alerts could not be loaded. You can still paste an alert ID.");
      },
    );
    return () => {
      active = false;
    };
  }, []);

  async function update(action: () => Promise<void>, onSaved?: () => void) {
    if (!incidentId) return;
    setBusy(true);
    setError(null);
    try {
      await action();
      onSaved?.();
    } catch (err) {
      setError(err instanceof api.ApiError ? err.message : "Could not save changes");
      setBusy(false);
      return;
    }
    try {
      setDetail(await api.getIncident(incidentId));
    } catch {
      setError(
        "Changes saved, but the updated incident could not be loaded. Refresh to try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="incidents-page">
      <div className="alerts-toolbar">
        <Link to="/incidents">&larr; Back to incidents</Link>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setDetail(null);
            setError(null);
            setRevision((n) => n + 1);
          }}
        >
          Refresh
        </button>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!detail && !error && <p className="status">Loading…</p>}
      {detail && incidentId && (
        <>
          <h1>{detail.summary.title}</h1>
          <p>
            Created {new Date(detail.summary.created_at).toLocaleString()}
            {detail.summary.closed_at && (
              <> · Closed {new Date(detail.summary.closed_at).toLocaleString()}</>
            )}
          </p>
          <p>
            Highest risk: {detail.summary.max_risk_score ?? "Not scored"} ·{" "}
            {detail.summary.alert_count} alert(s)
          </p>
          <fieldset disabled={busy} className="incident-controls">
            <legend>Triage</legend>
            <label>
              Status
              <select
                value={detail.summary.status}
                onChange={(e) => {
                  void update(() =>
                    api.setIncidentStatus(incidentId, e.target.value as IncidentStatus),
                  );
                }}
              >
                {Object.entries(statusLabels).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <p>Assignee: {detail.summary.assignee_email ?? "Unassigned"}</p>
            <button type="button" onClick={() => void update(() => api.claimIncident(incidentId))}>
              Assign to me
            </button>
            {detail.summary.assignee_email && (
              <button
                type="button"
                onClick={() => void update(() => api.unassignIncident(incidentId))}
              >
                Unassign
              </button>
            )}
            <section>
              <h2>Linked alerts</h2>
              {detail.alerts.length === 0 ? (
                <p>No linked alerts.</p>
              ) : (
                <ul className="incident-alerts">
                  {detail.alerts.map((alert) => (
                    <li key={alert.alert_id}>
                      <Link to={`/alerts/${alert.alert_id}`}>{alert.title}</Link>
                      <span>
                        {alert.src_ip ?? alert.host ?? "Unknown source"} ·{" "}
                        {new Date(alert.ts).toLocaleString()}
                      </span>
                      <button
                        type="button"
                        aria-label={`Unlink ${alert.title}`}
                        onClick={() =>
                          void update(() => api.unlinkIncidentAlert(incidentId, alert.alert_id))
                        }
                      >
                        Unlink
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <form
                className="incident-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void update(
                    () => api.linkIncidentAlerts(incidentId, [alertId.trim()]),
                    () => setAlertId(""),
                  );
                }}
              >
                <label>
                  Alert ID
                  <input
                    list="recent-alerts"
                    value={alertId}
                    onChange={(e) => setAlertId(e.target.value)}
                    required
                    pattern="[0-9a-f]{64}"
                    maxLength={64}
                    aria-describedby="alert-help"
                  />
                </label>
                <datalist id="recent-alerts">
                  {alerts
                    .filter((a) => !detail.alerts.some((linked) => linked.alert_id === a.alert_id))
                    .map((a) => (
                      <option key={a.alert_id} value={a.alert_id}>
                        {a.title} · {a.src_ip ?? a.host ?? "Unknown source"} ·{" "}
                        {new Date(a.ts).toLocaleString()}
                      </option>
                    ))}
                </datalist>
                <p id="alert-help">
                  Choose from the latest 200 alerts, or paste the full ID from an alert’s URL.
                </p>
                {alertError && <p className="error">{alertError}</p>}
                <button disabled={busy || !/^[0-9a-f]{64}$/.test(alertId.trim())}>
                  Link alert
                </button>
              </form>
            </section>
            <section>
              <h2>Notes</h2>
              {detail.notes.length === 0 && <p>No notes yet.</p>}
              <ol className="incident-notes">
                {detail.notes.map((entry) => (
                  <li key={entry.id}>
                    <p>
                      <strong>{entry.author_email}</strong> ·{" "}
                      {new Date(entry.created_at).toLocaleString()}
                    </p>
                    <p className="note-body">{entry.body}</p>
                  </li>
                ))}
              </ol>
              <form
                className="incident-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void update(
                    () => api.addIncidentNote(incidentId, note.trim()),
                    () => setNote(""),
                  );
                }}
              >
                <label>
                  Add a note
                  <textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    required
                    maxLength={4000}
                    rows={4}
                  />
                </label>
                <button disabled={busy || !note.trim()}>Add note</button>
              </form>
            </section>
          </fieldset>
          {busy && <p role="status">Saving…</p>}
        </>
      )}
    </main>
  );
}
