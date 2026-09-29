import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { ApiError } from "../../api/client";
import { AuthProvider } from "../../auth/AuthContext";
import { Login } from "../Login";

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={["/login"]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/alerts" element={<p>Alerts page</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Login", () => {
  it("shows the form once the initial me() check resolves to logged out", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "Not authenticated"));

    renderLogin();

    expect(await screen.findByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("navigates to /alerts on a successful login", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "Not authenticated"));
    vi.spyOn(api, "login").mockResolvedValue({ id: "1", email: "a@b.com", role: "analyst" });
    const user = userEvent.setup();
    renderLogin();

    await user.type(await screen.findByLabelText("Email"), "a@b.com");
    await user.type(screen.getByLabelText("Password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Alerts page")).toBeInTheDocument();
    expect(api.login).toHaveBeenCalledWith("a@b.com", "correct horse battery staple");
  });

  it("shows the server's error message on a failed login and stays on the form", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "Not authenticated"));
    vi.spyOn(api, "login").mockRejectedValue(new ApiError(401, "Invalid email or password"));
    const user = userEvent.setup();
    renderLogin();

    await user.type(await screen.findByLabelText("Email"), "a@b.com");
    await user.type(screen.getByLabelText("Password"), "wrong password entirely");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
    expect(screen.getByLabelText("Email")).toBeInTheDocument(); // still on the login form
  });

  it("redirects away immediately if already logged in", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ id: "1", email: "a@b.com", role: "admin" });

    renderLogin();

    expect(await screen.findByText("Alerts page")).toBeInTheDocument();
  });

  it("disables the submit button while the request is in flight", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "Not authenticated"));
    let resolveLogin!: (u: { id: string; email: string; role: "analyst" }) => void;
    vi.spyOn(api, "login").mockReturnValue(
      new Promise((resolve) => {
        resolveLogin = resolve;
      }),
    );
    const user = userEvent.setup();
    renderLogin();

    await user.type(await screen.findByLabelText("Email"), "a@b.com");
    await user.type(screen.getByLabelText("Password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(screen.getByRole("button")).toBeDisabled();
    resolveLogin({ id: "1", email: "a@b.com", role: "analyst" });
    await waitFor(() => expect(screen.queryByText("Alerts page")).toBeInTheDocument());
  });
});
