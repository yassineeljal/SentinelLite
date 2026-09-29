import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import { AuthProvider } from "../../auth/AuthContext";
import { ProtectedRoute } from "../ProtectedRoute";

afterEach(() => {
  vi.restoreAllMocks();
});

function renderProtected() {
  return render(
    <MemoryRouter initialEntries={["/alerts"]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<p>Login page</p>} />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <p>Secret alerts</p>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute", () => {
  it("shows a loading state before the session check resolves", () => {
    vi.spyOn(api, "me").mockReturnValue(new Promise(() => {})); // never resolves

    renderProtected();

    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("renders the protected content once logged in", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ id: "1", email: "a@b.com", role: "analyst" });

    renderProtected();

    expect(await screen.findByText("Secret alerts")).toBeInTheDocument();
  });

  it("redirects to /login when not authenticated", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "Not authenticated"));

    renderProtected();

    expect(await screen.findByText("Login page")).toBeInTheDocument();
  });
});
