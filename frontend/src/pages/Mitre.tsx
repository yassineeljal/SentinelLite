import { useCallback, useEffect, useState } from "react";
import { ApiError, mitreSummary } from "../api/client";
import type { MitreSummaryRow } from "../api/types";

const WINDOWS = [7, 30, 90] as const;

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

export function Mitre() {
  const [days, setDays] = useState<number>(30);
  const [rows, setRows] = useState<MitreSummaryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback((window: number) => {
    mitreSummary(window).then(setRows, (err: unknown) =>
      setError(err instanceof ApiError ? err.message : "Could not load the MITRE summary"),
    );
  }, []);

  useEffect(() => {
    refresh(days);
  }, [days, refresh]);

  // The reset lives in the event that caused it (the select's own change), not in the effect
  // above, which only fetches: this is what oxlint's set-state-in-effect rule is steering toward.
  function handleWindowChange(next: number) {
    setRows(null);
    setError(null);
    setDays(next);
  }

  const max = rows && rows.length > 0 ? Math.max(...rows.map((r) => r.count)) : 0;

  return (
    <main className="mitre-page">
      <div className="alerts-toolbar">
        <h1>MITRE ATT&amp;CK coverage</h1>
        <label>
          Window
          <select value={days} onChange={(e) => handleWindowChange(Number(e.target.value))}>
            {WINDOWS.map((w) => (
              <option key={w} value={w}>
                last {w} days
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && <p className="error">{error}</p>}
      {rows === null && !error && <p className="status">Loading…</p>}
      {rows !== null && rows.length === 0 && <p className="status">No alerts in this window.</p>}
      {rows !== null && rows.length > 0 && (
        <ul className="mitre-bars">
          {rows.map((row) => (
            <li key={row.technique}>
              <a
                href={`https://attack.mitre.org/techniques/${row.technique.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                className="mitre-technique"
              >
                {row.technique}
              </a>
              <div className="mitre-bar-track">
                <div
                  className="mitre-bar-fill"
                  style={{ width: `${max ? (row.count / max) * 100 : 0}%` }}
                />
              </div>
              <span className="mitre-count">{row.count}</span>
              <span className="mitre-latest">last {formatTime(row.latest_ts)}</span>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
