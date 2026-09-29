import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import type { MitreSummaryRow } from "../../api/types";
import { Mitre } from "../Mitre";

function row(overrides: Partial<MitreSummaryRow> = {}): MitreSummaryRow {
  return { technique: "T1110", count: 5, latest_ts: "2026-09-24T15:00:00Z", ...overrides };
}

afterEach(() => {
  vi.restoreAllMocks();
});

function renderMitre() {
  return render(
    <MemoryRouter>
      <Mitre />
    </MemoryRouter>,
  );
}

describe("Mitre", () => {
  it("renders a bar per technique, sized relative to the largest count", async () => {
    vi.spyOn(api, "mitreSummary").mockResolvedValue([
      row({ technique: "T1110", count: 10 }),
      row({ technique: "T1078", count: 5 }),
    ]);

    renderMitre();

    expect(await screen.findByText("T1110")).toBeInTheDocument();
    expect(screen.getByText("T1078")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
    const links = screen.getAllByRole("link");
    expect(links[0]).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1110/");
  });

  it("links a sub-technique to its own ATT&CK page", async () => {
    vi.spyOn(api, "mitreSummary").mockResolvedValue([row({ technique: "T1110.003" })]);

    renderMitre();

    expect(await screen.findByRole("link", { name: "T1110.003" })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/003/",
    );
  });

  it("shows a message when there is nothing in the window", async () => {
    vi.spyOn(api, "mitreSummary").mockResolvedValue([]);

    renderMitre();

    expect(await screen.findByText("No alerts in this window.")).toBeInTheDocument();
  });

  it("shows the server's error message when the request fails", async () => {
    vi.spyOn(api, "mitreSummary").mockRejectedValue(new ApiError(401, "Not authenticated"));

    renderMitre();

    expect(await screen.findByText("Not authenticated")).toBeInTheDocument();
  });

  it("refetches with the selected window", async () => {
    const mitreSummary = vi.spyOn(api, "mitreSummary").mockResolvedValue([row()]);
    const user = userEvent.setup();
    renderMitre();
    await screen.findByText("T1110");
    expect(mitreSummary).toHaveBeenCalledWith(30);

    await user.selectOptions(screen.getByLabelText("Window"), "7");

    await waitFor(() => expect(mitreSummary).toHaveBeenLastCalledWith(7));
  });

  it("defaults to a 30-day window", async () => {
    vi.spyOn(api, "mitreSummary").mockResolvedValue([]);

    renderMitre();

    expect(await screen.findByLabelText("Window")).toHaveValue("30");
  });
});
