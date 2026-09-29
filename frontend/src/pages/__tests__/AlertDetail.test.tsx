import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import type { AlertDetail as AlertDetailData } from "../../api/types";
import { AlertDetail } from "../AlertDetail";

const ALERT_ID = "ab".repeat(32);

function detail(overrides: Partial<AlertDetailData> = {}): AlertDetailData {
  return {
    alert: {
      alert_id: ALERT_ID,
      rule_id: "ssh-bruteforce",
      title: "SSH brute force",
      severity: 60,
      ts: "2026-09-24T15:00:03Z",
      created_at: "2026-09-24T15:00:03.200Z",
      src_ip: "185.220.101.1",
      host: "ubuntu-01",
      user_name: "root",
      match_count: 5,
      country_code: "DE",
      abuse_score: 90,
      risk_score: 87,
    },
    mitre: ["T1110"],
    group: { src_ip: "185.220.101.1" },
    evidence: [
      {
        ts: "2026-09-24T15:00:00Z",
        received_at: "2026-09-24T15:00:00.100Z",
        action: "login_failed",
        user_name: "root",
        src_ip: "185.220.101.1",
        raw: "Failed password for root from 185.220.101.1 port 4422 ssh2",
      },
    ],
    incident_id: null,
    detection_latency_ms: 473,
    enrichment: {
      ip_scope: "public",
      geo: {
        country_code: "DE",
        country: "Germany",
        city: "Berlin",
        latitude: 52.52,
        longitude: 13.405,
        asn: 60729,
        as_org: "Example Hosting",
      },
      reputation: {
        source: "abuseipdb",
        score: 90,
        total_reports: 200,
        distinct_reporters: 50,
        last_reported_at: "2026-09-24T00:00:00Z",
        usage_type: "Data Center",
        isp: "Example Hosting",
        is_tor: true,
        is_whitelisted: false,
        checked_at: "2026-09-24T15:00:03Z",
      },
    },
    risk: {
      score: 87,
      level: "high",
      factors: [
        { name: "rule severity", points: 60, reason: "severity 60 set by the rule" },
        { name: "reputation", points: 22, reason: "AbuseIPDB abuse confidence 90/100" },
        { name: "tor exit", points: 5, reason: "the source is a Tor exit node" },
      ],
    },
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={[`/alerts/${ALERT_ID}`]}>
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("AlertDetail", () => {
  it("renders the rule, MITRE technique, risk breakdown and evidence", async () => {
    vi.spyOn(api, "getAlert").mockResolvedValue(detail());

    renderDetail();

    expect(await screen.findByText("SSH brute force")).toBeInTheDocument();
    expect(screen.getByText("T1110")).toBeInTheDocument();
    expect(screen.getByText("87")).toHaveClass("risk-high");
    expect(screen.getByText(/AbuseIPDB abuse confidence 90\/100/)).toBeInTheDocument();
    expect(screen.getByText(/Berlin, Germany, DE/)).toBeInTheDocument();
    expect(
      screen.getByText("Failed password for root from 185.220.101.1 port 4422 ssh2"),
    ).toBeInTheDocument();
    expect(screen.getByText("Detection latency 473 ms")).toBeInTheDocument();
  });

  it("shows the server's error message when the alert cannot be loaded", async () => {
    vi.spyOn(api, "getAlert").mockRejectedValue(new ApiError(404, "alert not found"));

    renderDetail();

    expect(await screen.findByText("alert not found")).toBeInTheDocument();
  });

  it("says an alert has not been scored or enriched yet when both are null", async () => {
    vi.spyOn(api, "getAlert").mockResolvedValue(detail({ enrichment: null, risk: null }));

    renderDetail();

    await screen.findByText("SSH brute force");
    expect(screen.getByText("Not scored yet.")).toBeInTheDocument();
    expect(screen.getByText("Not enriched yet.")).toBeInTheDocument();
  });

  it("shows a non-public address without a location", async () => {
    vi.spyOn(api, "getAlert").mockResolvedValue(
      detail({ enrichment: { ip_scope: "non_public", geo: null, reputation: null } }),
    );

    renderDetail();

    expect(await screen.findByText("Non-public address: no location.")).toBeInTheDocument();
  });

  it("has a link back to the alert list", async () => {
    vi.spyOn(api, "getAlert").mockResolvedValue(detail());

    renderDetail();
    await screen.findByText("SSH brute force");

    expect(screen.getByRole("link", { name: /Back to alerts/ })).toHaveAttribute("href", "/alerts");
  });
});

it("opens the existing incident instead of offering a duplicate case", async () => {
  const id = "79dbe125-6064-46da-8234-102e038a788a";
  vi.spyOn(api, "getAlert").mockResolvedValue(detail({ incident_id: id }));
  renderDetail();
  expect(await screen.findByRole("link", { name: "View linked incident" })).toHaveAttribute(
    "href",
    `/incidents/${id}`,
  );
  expect(
    screen.queryByRole("link", { name: "Create incident from this alert" }),
  ).not.toBeInTheDocument();
});
