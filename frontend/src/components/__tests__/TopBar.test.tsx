import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { User } from "../../api/types";
import { AuthContext } from "../../auth/useAuth";
import { TopBar } from "../TopBar";

const user: User = { id: "u1", email: "admin@example.com", role: "admin" };

function renderBar(path = "/alerts", who: User | null = user, logout = vi.fn()) {
  render(
    <AuthContext.Provider value={{ user: who, login: vi.fn(), logout }}>
      <MemoryRouter initialEntries={[path]}>
        <TopBar />
        <Routes>
          <Route path="/login" element={<p>Login page</p>} />
          <Route path="*" element={<p>Somewhere</p>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
  return logout;
}

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});
afterEach(() => vi.restoreAllMocks());

describe("TopBar", () => {
  it("shows the navigation and marks only the current page", () => {
    renderBar("/blocks");

    const current = screen
      .getAllByRole("link")
      .filter((link) => link.getAttribute("aria-current") === "page");
    expect(current.map((link) => link.textContent)).toEqual(["Blocks"]);
    for (const name of ["Alerts", "Security", "Incidents", "Map", "MITRE ATT&CK"]) {
      expect(screen.getByRole("link", { name })).toBeInTheDocument();
    }
  });

  it("shows who is signed in and their role", () => {
    renderBar();

    expect(screen.getByText("admin@example.com")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  it("has no navigation and no sign out when nobody is signed in, but keeps the theme switch", () => {
    renderBar("/login", null);

    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign out" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /theme/ })).toBeInTheDocument();
  });

  it("signs out and goes to the login page", async () => {
    const logout = renderBar();

    await userEvent.setup().click(screen.getByRole("button", { name: "Sign out" }));

    expect(logout).toHaveBeenCalledOnce();
    expect(await screen.findByText("Login page")).toBeInTheDocument();
  });

  it("switches theme, remembers it and offers the way back", async () => {
    renderBar();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Switch to the dark theme" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("sl-theme")).toBe("dark");

    await user.click(screen.getByRole("button", { name: "Switch to the light theme" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("sl-theme")).toBe("light");
  });

  it("starts from a remembered choice", () => {
    localStorage.setItem("sl-theme", "dark");

    renderBar();

    expect(screen.getByRole("button", { name: "Switch to the light theme" })).toBeInTheDocument();
  });
});
