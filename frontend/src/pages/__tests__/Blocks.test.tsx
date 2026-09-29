import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import type { AllowlistEntry, Block, User } from "../../api/types";
import { AuthContext } from "../../auth/useAuth";
import { Blocks } from "../Blocks";

const block: Block = {
  id: 1,
  ip: "45.83.64.10",
  rule_id: "ssh-bruteforce",
  reason: "ssh-bruteforce: SSH brute force (9 event(s), severity 60)",
  mode: "enforce",
  created_at: "2026-09-29T20:00:00Z",
  expires_at: "2026-09-29T21:00:00Z",
  released_at: null,
  released_by: null,
  state: "active",
};
const entry: AllowlistEntry = {
  cidr: "198.51.100.0/24",
  note: "the office",
  created_by: "user:admin@example.com",
  created_at: "2026-09-29T12:00:00Z",
};

function renderPage(role: User["role"]) {
  const user: User = { id: "u1", email: `${role}@example.com`, role };
  render(
    <AuthContext.Provider value={{ user, login: vi.fn(), logout: vi.fn() }}>
      <MemoryRouter>
        <Blocks />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

function mockData(blocks: Block[] = [block], allowlist: AllowlistEntry[] = [entry]) {
  vi.spyOn(api, "listBlocks").mockResolvedValue(blocks);
  vi.spyOn(api, "listAllowlist").mockResolvedValue(allowlist);
}

afterEach(() => vi.restoreAllMocks());

describe("Blocks", () => {
  it("shows the blocks and the allowlist", async () => {
    mockData();
    renderPage("analyst");

    expect(await screen.findByText("45.83.64.10")).toBeInTheDocument();
    expect(screen.getByText("Enforced")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("198.51.100.0/24")).toBeInTheDocument();
    expect(screen.getByText("the office")).toBeInTheDocument();
  });

  it("is read only for an analyst: no unblock, no allowlist editing", async () => {
    mockData();
    renderPage("analyst");

    await screen.findByText("45.83.64.10");
    expect(screen.getByText(/needs an admin/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unblock" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add to the allowlist" })).not.toBeInTheDocument();
  });

  it("says when there is nothing to show", async () => {
    mockData([], []);
    renderPage("admin");

    expect(await screen.findByText("Nothing blocked yet.")).toBeInTheDocument();
    expect(screen.getByText("The allowlist is empty.")).toBeInTheDocument();
  });

  it("labels a dry-run block as not applied", async () => {
    mockData([{ ...block, mode: "dry_run" }]);
    renderPage("analyst");

    expect(await screen.findByText("Dry run (nothing applied)")).toBeInTheDocument();
  });

  it("needs a second click to unblock, and Cancel backs out", async () => {
    mockData();
    const unblock = vi.spyOn(api, "unblockAddress").mockResolvedValue(undefined);
    renderPage("admin");
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Unblock" }));
    expect(unblock).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Unblock" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Unblock" }));
    await user.click(screen.getByRole("button", { name: "Confirm unblock 45.83.64.10" }));

    expect(unblock).toHaveBeenCalledWith("45.83.64.10");
    await waitFor(() => expect(api.listBlocks).toHaveBeenCalledTimes(2)); // reloaded
  });

  it("only offers to unblock an active block, and says who released the others", async () => {
    mockData([
      {
        ...block,
        id: 2,
        ip: "45.83.64.2",
        state: "released",
        released_by: "user:admin@example.com",
      },
      { ...block, id: 3, ip: "45.83.64.3", state: "expired" },
    ]);
    renderPage("admin");

    expect(await screen.findByText("Released by user:admin@example.com")).toBeInTheDocument();
    expect(screen.getByText("Expired")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unblock" })).not.toBeInTheDocument();
  });

  it("shows the server's message when an unblock fails", async () => {
    mockData();
    vi.spyOn(api, "unblockAddress").mockRejectedValue(
      new api.ApiError(404, "No active block for this address"),
    );
    renderPage("admin");
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Unblock" }));
    await user.click(screen.getByRole("button", { name: /Confirm unblock/ }));

    expect(await screen.findByRole("alert")).toHaveTextContent("No active block for this address");
  });

  it("lets an admin protect an address and clears the form", async () => {
    mockData();
    const add = vi.spyOn(api, "addAllowlist").mockResolvedValue(entry);
    renderPage("admin");
    const user = userEvent.setup();

    await screen.findByText("45.83.64.10");
    await user.type(screen.getByLabelText("Address or network"), " 203.0.113.7 ");
    await user.type(screen.getByLabelText("Note"), "my home");
    await user.click(screen.getByRole("button", { name: "Add to the allowlist" }));

    expect(add).toHaveBeenCalledWith("203.0.113.7", "my home");
    await waitFor(() => expect(screen.getByLabelText("Address or network")).toHaveValue(""));
  });

  it("does not submit an empty allowlist entry", async () => {
    mockData();
    renderPage("admin");

    await screen.findByText("45.83.64.10");
    expect(screen.getByRole("button", { name: "Add to the allowlist" })).toBeDisabled();
  });

  it("lets an admin remove an allowlist entry", async () => {
    mockData();
    const remove = vi.spyOn(api, "removeAllowlist").mockResolvedValue(undefined);
    renderPage("admin");
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Remove 198.51.100.0/24" }));

    expect(remove).toHaveBeenCalledWith("198.51.100.0/24");
  });

  it("reports a loading failure", async () => {
    vi.spyOn(api, "listBlocks").mockRejectedValue(new api.ApiError(500, "boom"));
    vi.spyOn(api, "listAllowlist").mockResolvedValue([]);
    renderPage("analyst");

    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });
});
