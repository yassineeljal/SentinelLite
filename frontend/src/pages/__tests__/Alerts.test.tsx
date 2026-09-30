import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import type { Alert } from "../../api/types";
import { Alerts } from "../Alerts";

function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    alert_id: "a".repeat(64),
    rule_id: "ssh-bruteforce",
    title: "SSH brute force",
    severity: 60,
    ts: "2026-09-24T15:00:00Z",
    created_at: "2026-09-24T15:00:01Z",
    src_ip: "203.0.113.7",
    host: "ubuntu-01",
    user_name: "root",
    match_count: 5,
    country_code: "DE",
    abuse_score: 90,
    risk_score: 82,
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

function renderAlerts() {
  return render(
    <MemoryRouter>
      <Alerts />
    </MemoryRouter>,
  );
}

function renderAlertsWithDetailRoute() {
  return render(
    <MemoryRouter initialEntries={["/alerts"]}>
      <Routes>
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:alertId" element={<p>Detail page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Alerts", () => {
  it("colours the rule severity like the risk score, by level", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([
      alert({ alert_id: "1".repeat(64), severity: 30, risk_score: null }),
      alert({ alert_id: "2".repeat(64), severity: 45, risk_score: null }),
      alert({ alert_id: "3".repeat(64), severity: 75, risk_score: null }),
      alert({ alert_id: "4".repeat(64), severity: 96, risk_score: null }),
    ]);

    renderAlerts();

    expect(await screen.findByText("30")).toHaveClass("risk-low");
    expect(screen.getByText("45")).toHaveClass("risk-medium");
    expect(screen.getByText("75")).toHaveClass("risk-high");
    expect(screen.getByText("96")).toHaveClass("risk-critical");
  });

  it("renders a row per alert with its risk score", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([alert()]);

    renderAlerts();

    expect(await screen.findByText("ssh-bruteforce")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("82")).toHaveClass("risk-high");
  });

  it("shows a message when there are no alerts", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([]);

    renderAlerts();

    expect(await screen.findByText("No alerts.")).toBeInTheDocument();
  });

  it("shows the server's error message when the request fails", async () => {
    vi.spyOn(api, "listAlerts").mockRejectedValue(new ApiError(401, "Not authenticated"));

    renderAlerts();

    expect(await screen.findByText("Not authenticated")).toBeInTheDocument();
  });

  it("shows a dash for every field an alert lacks", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([
      alert({
        src_ip: null,
        host: null,
        user_name: null,
        country_code: null,
        abuse_score: null,
        risk_score: null,
      }),
    ]);

    renderAlerts();

    await screen.findByText("ssh-bruteforce");
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(5);
  });

  it("refetches with the rule filter typed into the toolbar", async () => {
    const { default: userEvent } = await import("@testing-library/user-event");
    const listAlerts = vi.spyOn(api, "listAlerts").mockResolvedValue([alert()]);
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByText("ssh-bruteforce");

    await user.type(screen.getByLabelText("Rule"), "ssh-root-login");

    await waitFor(() =>
      expect(listAlerts).toHaveBeenLastCalledWith({ limit: 100, rule: "ssh-root-login" }),
    );
  });

  it("polls again after the refresh interval", async () => {
    const listAlerts = vi.spyOn(api, "listAlerts").mockResolvedValue([alert()]);
    vi.useFakeTimers();
    try {
      renderAlerts();
      await vi.advanceTimersByTimeAsync(0); // flush the initial fetch triggered by the effect
      expect(listAlerts).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(15_000);

      expect(listAlerts).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

it("navigates to the alert's detail page when a row is clicked", async () => {
  const { default: userEvent } = await import("@testing-library/user-event");
  vi.spyOn(api, "listAlerts").mockResolvedValue([alert()]);
  const user = userEvent.setup();
  renderAlertsWithDetailRoute();

  await user.click(await screen.findByText("ssh-bruteforce"));

  expect(await screen.findByText("Detail page")).toBeInTheDocument();
});
