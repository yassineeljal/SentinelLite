import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import type { Incident, IncidentDetail as Detail } from "../../api/types";
import { Incidents } from "../Incidents";
import { IncidentDetail } from "../IncidentDetail";

const ID = "79dbe125-6064-46da-8234-102e038a788a";
const ALERT = "a".repeat(64);
const incident: Incident = {
  id: ID,
  title: "SSH spike",
  status: "new",
  assignee_email: null,
  created_at: "2026-09-29T12:00:00Z",
  closed_at: null,
  alert_count: 0,
  max_risk_score: null,
};
function detail(overrides: Partial<Detail> = {}): Detail {
  return { summary: incident, alerts: [], notes: [], ...overrides };
}
function renderList(path = "/incidents") {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:incidentId" element={<p>Opened incident</p>} />
      </Routes>
    </MemoryRouter>,
  );
}
function renderDetail() {
  render(
    <MemoryRouter initialEntries={[`/incidents/${ID}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "listAlerts").mockResolvedValue([]);
});
afterEach(() => vi.restoreAllMocks());

describe("Incidents", () => {
  it("shows an empty list and disables blank titles", async () => {
    vi.spyOn(api, "listIncidents").mockResolvedValue([]);
    renderList();
    expect(await screen.findByText("No incidents.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create incident" })).toBeDisabled();
  });

  it("shows the list, links and status filter", async () => {
    const list = vi.spyOn(api, "listIncidents").mockResolvedValue([incident]);
    renderList();
    expect(await screen.findByRole("link", { name: "SSH spike" })).toHaveAttribute(
      "href",
      `/incidents/${ID}`,
    );
    expect(screen.getByText("Unassigned")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Status"), "closed");
    await waitFor(() => expect(list).toHaveBeenLastCalledWith("closed"));
  });

  it("creates an incident from the selected alert and opens it", async () => {
    vi.spyOn(api, "listIncidents").mockResolvedValue([]);
    const create = vi.spyOn(api, "createIncident").mockResolvedValue(incident);
    renderList(`/incidents?alert=${ALERT}`);
    await userEvent.type(screen.getByLabelText("Title"), "SSH spike");
    await userEvent.click(screen.getByRole("button", { name: "Create incident" }));
    expect(await screen.findByText("Opened incident")).toBeInTheDocument();
    expect(create).toHaveBeenCalledWith("SSH spike", [ALERT]);
  });

  it("preserves the title and displays a creation conflict", async () => {
    vi.spyOn(api, "listIncidents").mockResolvedValue([]);
    vi.spyOn(api, "createIncident").mockRejectedValue(
      new api.ApiError(409, "alert already linked"),
    );
    renderList();
    await userEvent.type(screen.getByLabelText("Title"), "SSH spike");
    await userEvent.click(screen.getByRole("button", { name: "Create incident" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("alert already linked");
    expect(screen.getByLabelText("Title")).toHaveValue("SSH spike");
  });

  it("displays a list failure and retries on refresh", async () => {
    vi.spyOn(api, "listIncidents")
      .mockRejectedValueOnce(new api.ApiError(401, "Not authenticated"))
      .mockResolvedValue([]);
    renderList();
    expect(await screen.findByRole("alert")).toHaveTextContent("Not authenticated");
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("No incidents.")).toBeInTheDocument();
  });
});

describe("IncidentDetail", () => {
  it("claims, closes, reopens and unassigns the incident", async () => {
    let current = detail();
    vi.spyOn(api, "getIncident").mockImplementation(async () => current);
    const claim = vi.spyOn(api, "claimIncident").mockImplementation(async () => {
      current = detail({ summary: { ...incident, assignee_email: "me@example.com" } });
    });
    const status = vi.spyOn(api, "setIncidentStatus").mockImplementation(async (_id, value) => {
      current = { ...current, summary: { ...current.summary, status: value } };
    });
    const unassign = vi.spyOn(api, "unassignIncident").mockImplementation(async () => {
      current = detail();
    });
    renderDetail();
    await screen.findByText("SSH spike");
    await userEvent.click(screen.getByRole("button", { name: "Assign to me" }));
    expect(await screen.findByText("Assignee: me@example.com")).toBeInTheDocument();
    expect(claim).toHaveBeenCalledWith(ID);
    await userEvent.selectOptions(screen.getByLabelText("Status"), "closed");
    await waitFor(() => expect(screen.getByLabelText("Status")).toHaveValue("closed"));
    expect(status).toHaveBeenCalledWith(ID, "closed");
    await userEvent.selectOptions(screen.getByLabelText("Status"), "new");
    await waitFor(() => expect(screen.getByLabelText("Status")).toHaveValue("new"));
    expect(status).toHaveBeenCalledWith(ID, "new");
    await userEvent.click(screen.getByRole("button", { name: "Unassign" }));
    expect(await screen.findByText("Assignee: Unassigned")).toBeInTheDocument();
    expect(unassign).toHaveBeenCalledWith(ID);
  });

  it("adds a note, renders it as text and clears the input only after saving", async () => {
    const saved = detail({
      notes: [
        {
          id: "note",
          author_email: "me@example.com",
          body: "<script>hello</script>",
          created_at: incident.created_at,
        },
      ],
    });
    vi.spyOn(api, "getIncident").mockResolvedValueOnce(detail()).mockResolvedValue(saved);
    const add = vi.spyOn(api, "addIncidentNote").mockResolvedValue();
    renderDetail();
    await screen.findByText("SSH spike");
    await userEvent.type(screen.getByLabelText("Add a note"), "<script>hello</script>");
    await userEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByText("<script>hello</script>")).toBeInTheDocument();
    expect(screen.getByLabelText("Add a note")).toHaveValue("");
    expect(add).toHaveBeenCalledWith(ID, "<script>hello</script>");
  });

  it("preserves a failed note so it can be retried", async () => {
    vi.spyOn(api, "getIncident").mockResolvedValue(detail());
    vi.spyOn(api, "addIncidentNote").mockRejectedValue(new api.ApiError(401, "Not authenticated"));
    renderDetail();
    await screen.findByText("SSH spike");
    await userEvent.type(screen.getByLabelText("Add a note"), "Keep this draft");
    await userEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Not authenticated");
    expect(screen.getByLabelText("Add a note")).toHaveValue("Keep this draft");
  });

  it("does not encourage resubmitting a saved note when only the refresh failed", async () => {
    vi.spyOn(api, "getIncident")
      .mockResolvedValueOnce(detail())
      .mockRejectedValue(new Error("offline"));
    vi.spyOn(api, "addIncidentNote").mockResolvedValue();
    renderDetail();
    await screen.findByText("SSH spike");
    await userEvent.type(screen.getByLabelText("Add a note"), "Saved note");
    await userEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Changes saved");
    expect(screen.getByLabelText("Add a note")).toHaveValue("");
  });

  it("links an alert and unlinks it without deleting its evidence", async () => {
    const linked = detail({
      summary: { ...incident, alert_count: 1 },
      alerts: [
        {
          alert_id: ALERT,
          rule_id: "ssh-bruteforce",
          title: "SSH brute force",
          severity: 60,
          ts: incident.created_at,
          created_at: incident.created_at,
          src_ip: "203.0.113.7",
          host: null,
          user_name: null,
          match_count: 5,
          country_code: null,
          abuse_score: null,
          risk_score: null,
        },
      ],
    });
    vi.spyOn(api, "getIncident")
      .mockResolvedValueOnce(detail())
      .mockResolvedValueOnce(linked)
      .mockResolvedValue(detail());
    const link = vi.spyOn(api, "linkIncidentAlerts").mockResolvedValue();
    const unlink = vi.spyOn(api, "unlinkIncidentAlert").mockResolvedValue();
    renderDetail();
    await screen.findByText("SSH spike");
    await userEvent.type(screen.getByLabelText("Alert ID"), ALERT);
    await userEvent.click(screen.getByRole("button", { name: "Link alert" }));
    expect(await screen.findByRole("link", { name: "SSH brute force" })).toHaveAttribute(
      "href",
      `/alerts/${ALERT}`,
    );
    expect(link).toHaveBeenCalledWith(ID, [ALERT]);
    await userEvent.click(screen.getByRole("button", { name: "Unlink SSH brute force" }));
    expect(await screen.findByText("No linked alerts.")).toBeInTheDocument();
    expect(unlink).toHaveBeenCalledWith(ID, ALERT);
  });

  it("shows unknown incident errors", async () => {
    vi.spyOn(api, "getIncident").mockRejectedValue(new api.ApiError(404, "incident not found"));
    renderDetail();
    expect(await screen.findByRole("alert")).toHaveTextContent("incident not found");
  });
});
