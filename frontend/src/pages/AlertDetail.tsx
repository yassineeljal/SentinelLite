import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, getAlert } from "../api/client";
import type { AlertDetail as AlertDetailData } from "../api/types";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

function riskLevelClass(level: string): string {
  return `risk risk-${level}`;
}

export function AlertDetail() {
  const { alertId } = useParams<{ alertId: string }>();
  const [detail, setDetail] = useState<AlertDetailData | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Keyed by alertId in App.tsx: React remounts this component (fresh state, no stale flash)
  // whenever the route param changes, instead of this effect resetting state by hand.
  useEffect(() => {
    if (!alertId) return;
    getAlert(alertId).then(setDetail, (err: unknown) =>
      setError(err instanceof ApiError ? err.message : "Could not load this alert"),
    );
  }, [alertId]);

  return (
    <main className="alert-detail-page">
      <p>
        <Link to="/alerts">&larr; Back to alerts</Link>
      </p>
      {error && <p className="error">{error}</p>}
      {!detail && !error && <p className="status">Loading…</p>}
      {detail && (
        <>
          <header className="alert-detail-header">
            <h1>{detail.alert.title}</h1>
            <p>
              {detail.incident_id ? (
                <Link to={`/incidents/${detail.incident_id}`}>View linked incident</Link>
              ) : (
                <Link to={`/incidents?alert=${detail.alert.alert_id}`}>
                  Create incident from this alert
                </Link>
              )}
            </p>
            <div className="alert-detail-meta">
              <span>{detail.alert.rule_id}</span>
              {detail.mitre.map((technique) => (
                <span key={technique} className="mitre-tag">
                  {technique}
                </span>
              ))}
              <span>severity {detail.alert.severity}</span>
            </div>
          </header>

          <section className="detail-grid">
            <div>
              <h2>When</h2>
              <p>Triggered {formatTime(detail.alert.ts)}</p>
              <p>Stored {formatTime(detail.alert.created_at)}</p>
              {detail.detection_latency_ms !== null && (
                <p>Detection latency {Math.round(detail.detection_latency_ms)} ms</p>
              )}
            </div>
            <div>
              <h2>Who / where</h2>
              {Object.entries(detail.group).map(([key, value]) => (
                <p key={key}>
                  {key} = {String(value)}
                </p>
              ))}
              {detail.alert.host && <p>host {detail.alert.host}</p>}
              {detail.alert.user_name && <p>user {detail.alert.user_name}</p>}
              {detail.alert.src_ip && <p>source {detail.alert.src_ip}</p>}
            </div>
          </section>

          <section>
            <h2>Risk</h2>
            {detail.risk ? (
              <>
                <p>
                  <span className={riskLevelClass(detail.risk.level)}>{detail.risk.score}</span>{" "}
                  {detail.risk.level}
                </p>
                <ul className="risk-factors">
                  {detail.risk.factors.map((factor) => (
                    <li key={factor.name}>
                      <strong>
                        {factor.points >= 0 ? "+" : ""}
                        {factor.points}
                      </strong>{" "}
                      {factor.name}: {factor.reason}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="status">Not scored yet.</p>
            )}
          </section>

          <section>
            <h2>Location &amp; reputation</h2>
            {detail.enrichment ? (
              detail.enrichment.ip_scope === "non_public" ? (
                <p className="status">Non-public address: no location.</p>
              ) : (
                <>
                  {detail.enrichment.geo ? (
                    <p>
                      {[
                        detail.enrichment.geo.city,
                        detail.enrichment.geo.country,
                        detail.enrichment.geo.country_code,
                      ]
                        .filter(Boolean)
                        .join(", ") || "Location unknown"}
                      {detail.enrichment.geo.asn !== null &&
                        ` — AS${detail.enrichment.geo.asn} ${detail.enrichment.geo.as_org ?? ""}`}
                    </p>
                  ) : (
                    <p className="status">Public address, unknown to the GeoIP database.</p>
                  )}
                  {detail.enrichment.reputation ? (
                    <p>
                      AbuseIPDB {detail.enrichment.reputation.score}/100 —{" "}
                      {detail.enrichment.reputation.total_reports} report(s) by{" "}
                      {detail.enrichment.reputation.distinct_reporters} user(s)
                      {detail.enrichment.reputation.is_tor && " — Tor exit"}
                      {detail.enrichment.reputation.is_whitelisted && " — whitelisted"}
                    </p>
                  ) : (
                    <p className="status">No reputation data.</p>
                  )}
                </>
              )
            ) : (
              <p className="status">Not enriched yet.</p>
            )}
          </section>

          <section>
            <h2>Evidence ({detail.evidence.length})</h2>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>User</th>
                  <th>Source</th>
                  <th>Raw line</th>
                </tr>
              </thead>
              <tbody>
                {detail.evidence.map((event) => (
                  <tr key={event.ts + event.raw}>
                    <td>{formatTime(event.ts)}</td>
                    <td>{event.action}</td>
                    <td>{event.user_name ?? "—"}</td>
                    <td>{event.src_ip ?? "—"}</td>
                    <td className="raw-line">{event.raw}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </main>
  );
}
