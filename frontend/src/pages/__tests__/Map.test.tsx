import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import type { GeoSummaryRow } from "../../api/types";
import { WorldMap } from "../Map";

function point(overrides: Partial<GeoSummaryRow> = {}): GeoSummaryRow {
  return {
    country_code: "DE",
    country: "Germany",
    city: "Berlin",
    latitude: 52.52,
    longitude: 13.4,
    count: 5,
    max_risk_score: 90,
    latest_ts: "2026-09-24T15:00:00Z",
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

function renderMap() {
  return render(
    <MemoryRouter>
      <WorldMap />
    </MemoryRouter>,
  );
}

describe("WorldMap", () => {
  it("renders a point per location with a title summarising it", async () => {
    vi.spyOn(api, "geoSummary").mockResolvedValue([point()]);

    renderMap();

    await screen.findAllByText(/Berlin, Germany, DE/);
    const circle = document.querySelector("circle.map-point-high");
    expect(circle).not.toBeNull();
    expect(circle?.querySelector("title")?.textContent).toContain("5 alert(s)");
  });

  it("colours a point by its worst risk level", async () => {
    vi.spyOn(api, "geoSummary").mockResolvedValue([point({ max_risk_score: 96 })]);

    renderMap();

    await screen.findAllByText(/Berlin/);
    expect(document.querySelector("circle.map-point-critical")).not.toBeNull();
  });

  it("shows an unscored point distinctly", async () => {
    vi.spyOn(api, "geoSummary").mockResolvedValue([point({ max_risk_score: null })]);

    renderMap();

    await screen.findAllByText(/Berlin/);
    expect(document.querySelector("circle.map-point-unknown")).not.toBeNull();
  });

  it("shows a message when there is nothing to plot", async () => {
    vi.spyOn(api, "geoSummary").mockResolvedValue([]);

    renderMap();

    expect(
      await screen.findByText("No enriched, public-address alerts in this window."),
    ).toBeInTheDocument();
  });

  it("shows the server's error message when the request fails", async () => {
    vi.spyOn(api, "geoSummary").mockRejectedValue(new ApiError(401, "Not authenticated"));

    renderMap();

    expect(await screen.findByText("Not authenticated")).toBeInTheDocument();
  });

  it("refetches with the selected window", async () => {
    const geoSummary = vi.spyOn(api, "geoSummary").mockResolvedValue([point()]);
    const user = userEvent.setup();
    renderMap();
    await screen.findAllByText(/Berlin/);
    expect(geoSummary).toHaveBeenCalledWith(30);

    await user.selectOptions(screen.getByLabelText("Window"), "7");

    await waitFor(() => expect(geoSummary).toHaveBeenLastCalledWith(7));
  });

  it("lists every location in a legend sorted by count", async () => {
    vi.spyOn(api, "geoSummary").mockResolvedValue([
      point({ city: "Small", count: 1 }),
      point({ city: "Big", count: 9 }),
    ]);

    renderMap();

    const items = await screen.findAllByRole("listitem");
    expect(items[0].textContent).toContain("Big");
    expect(items[1].textContent).toContain("Small");
  });
});
