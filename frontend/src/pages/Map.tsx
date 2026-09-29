import { useEffect, useState } from "react";
import { ApiError, geoSummary } from "../api/client";
import type { GeoSummaryRow } from "../api/types";

const WINDOWS = [7, 30, 90] as const;
const WIDTH = 960;
const HEIGHT = 480;
const MIN_RADIUS = 4;
const MAX_RADIUS = 22;

function project(latitude: number, longitude: number): { x: number; y: number } {
  return { x: ((longitude + 180) / 360) * WIDTH, y: ((90 - latitude) / 180) * HEIGHT };
}

function riskLevel(score: number | null): string {
  if (score === null) return "unknown";
  if (score >= 95) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function locationLabel(row: GeoSummaryRow): string {
  return [row.city, row.country, row.country_code].filter(Boolean).join(", ") || "Unknown";
}

export function WorldMap() {
  const [days, setDays] = useState(30);
  const [rows, setRows] = useState<GeoSummaryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    geoSummary(days).then(setRows, (err: unknown) =>
      setError(err instanceof ApiError ? err.message : "Could not load the map"),
    );
  }, [days]);

  function handleWindowChange(next: number) {
    setRows(null);
    setError(null);
    setDays(next);
  }

  const max = rows && rows.length > 0 ? Math.max(...rows.map((r) => r.count)) : 0;
  const radius = (count: number) =>
    max <= 1 ? MIN_RADIUS : MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * Math.sqrt(count / max);

  return (
    <main className="map-page">
      <div className="alerts-toolbar">
        <h1>Source locations</h1>
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
      {rows !== null && rows.length === 0 && (
        <p className="status">No enriched, public-address alerts in this window.</p>
      )}
      {rows !== null && rows.length > 0 && (
        <>
          <svg
            className="world-map"
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            role="img"
            aria-label="Map of alert source locations"
          >
            <rect x={0} y={0} width={WIDTH} height={HEIGHT} className="map-background" />
            {[-60, -30, 0, 30, 60].map((lat) => (
              <line
                key={`lat-${lat}`}
                x1={0}
                x2={WIDTH}
                y1={project(lat, 0).y}
                y2={project(lat, 0).y}
                className={lat === 0 ? "map-graticule map-equator" : "map-graticule"}
              />
            ))}
            {[-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map((lon) => (
              <line
                key={`lon-${lon}`}
                x1={project(0, lon).x}
                x2={project(0, lon).x}
                y1={0}
                y2={HEIGHT}
                className={lon === 0 ? "map-graticule map-meridian" : "map-graticule"}
              />
            ))}
            {rows.map((row) => {
              const { x, y } = project(row.latitude, row.longitude);
              return (
                <circle
                  key={`${row.country_code ?? "?"}-${row.city ?? "?"}`}
                  cx={x}
                  cy={y}
                  r={radius(row.count)}
                  className={`map-point map-point-${riskLevel(row.max_risk_score)}`}
                >
                  <title>
                    {locationLabel(row)}: {row.count} alert(s), worst risk{" "}
                    {row.max_risk_score ?? "unscored"}
                  </title>
                </circle>
              );
            })}
          </svg>
          <ul className="map-legend">
            {rows
              .slice()
              .sort((a, b) => b.count - a.count)
              .map((row) => (
                <li key={`${row.country_code ?? "?"}-${row.city ?? "?"}`}>
                  <span className={`risk risk-${riskLevel(row.max_risk_score)}`}>{row.count}</span>{" "}
                  {locationLabel(row)}
                </li>
              ))}
          </ul>
        </>
      )}
    </main>
  );
}
