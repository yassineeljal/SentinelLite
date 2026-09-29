import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import QRCode from "qrcode";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "../../api/client";
import { Security } from "../Security";

const off = { enabled: false, setup_available: true, recovery_codes_remaining: 0 };
const on = { enabled: true, setup_available: true, recovery_codes_remaining: 10 };
const setup = {
  secret: "PUBLIC-TEST-KEY",
  provisioning_uri: "otpauth://totp/test?secret=PUBLIC",
  expires_at: "2099-01-01T00:10:00Z",
};
const codes = ["12345678-abcdef01-12345678-abcdef01", "abcdef01-12345678-abcdef01-12345678"];

beforeEach(() => {
  vi.spyOn(api, "mfaStatus").mockResolvedValue(off);
  vi.spyOn(QRCode, "toDataURL").mockImplementation(() =>
    Promise.resolve("data:image/png;base64,dGVzdA=="),
  );
});
afterEach(() => vi.restoreAllMocks());

async function start() {
  vi.spyOn(api, "startMfa").mockResolvedValue(setup);
  render(<Security />);
  await userEvent.type(await screen.findByLabelText("Current password"), "my current password");
  await userEvent.click(screen.getByRole("button", { name: "Set up two-factor authentication" }));
  await screen.findByLabelText("Authenticator code");
}

describe("Security", () => {
  it("sets up with a local QR and shows recovery codes only after confirmation", async () => {
    vi.spyOn(api, "confirmMfa").mockResolvedValue({ recovery_codes: codes });
    await start();
    expect(api.startMfa).toHaveBeenCalledWith("my current password");
    expect(QRCode.toDataURL).toHaveBeenCalledWith(setup.provisioning_uri, {
      width: 240,
      margin: 4,
    });
    expect(screen.getByRole("img", { name: "Authenticator setup QR code" })).toHaveAttribute(
      "src",
      "data:image/png;base64,dGVzdA==",
    );
    expect(screen.getByText(setup.secret)).toBeInTheDocument();
    expect(screen.queryByText(codes[0])).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Authenticator code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Enable two-factor authentication" }));
    expect(await screen.findByText(codes[0])).toBeInTheDocument();
    expect(api.confirmMfa).toHaveBeenCalledWith("my current password", "123456");
    expect(screen.queryByText(setup.secret)).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "I have saved my recovery codes" }));
    expect(screen.queryByText(codes[0])).not.toBeInTheDocument();
    expect(screen.getByLabelText("Current password")).toHaveValue("");
    expect(screen.getByText("Enabled", { exact: true })).toBeInTheDocument();
  });

  it("keeps setup available after a bad confirmation code", async () => {
    vi.spyOn(api, "confirmMfa").mockRejectedValue(new api.ApiError(401, "Invalid code"));
    await start();
    await userEvent.type(screen.getByLabelText("Authenticator code"), "000000");
    await userEvent.click(screen.getByRole("button", { name: "Enable two-factor authentication" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid code");
    expect(screen.getByText("Not enabled")).toBeInTheDocument();
    expect(screen.queryByText("Save your recovery codes")).not.toBeInTheDocument();
  });

  it("falls back to the manual key if QR rendering fails", async () => {
    vi.mocked(QRCode.toDataURL).mockRejectedValue(new Error("no canvas"));
    await start();
    expect(await screen.findByRole("status")).toHaveTextContent("Enter the setup key manually");
    expect(screen.getByText(setup.secret)).toBeInTheDocument();
  });

  it("clears the secret and password when starting over", async () => {
    await start();
    await userEvent.click(screen.getByRole("button", { name: "Start over" }));
    expect(screen.queryByText(setup.secret)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Current password")).toHaveValue("");
  });

  it("does not offer enrollment if the server has no encryption key", async () => {
    vi.mocked(api.mfaStatus).mockResolvedValue({ ...off, setup_available: false });
    render(<Security />);
    expect(await screen.findByText(/Contact your administrator/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
  });

  it("requires reauthentication to regenerate recovery codes", async () => {
    vi.mocked(api.mfaStatus).mockResolvedValue(on);
    vi.spyOn(api, "regenerateRecoveryCodes").mockResolvedValue({ recovery_codes: codes });
    render(<Security />);
    await userEvent.type(await screen.findByLabelText("Current password"), "my current password");
    await userEvent.type(screen.getByLabelText("Authentication or recovery code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Generate new recovery codes" }));
    expect(await screen.findByText(codes[0])).toBeInTheDocument();
    expect(api.regenerateRecoveryCodes).toHaveBeenCalledWith("my current password", "123456");
  });

  it("disables only after a successful server response", async () => {
    vi.mocked(api.mfaStatus).mockResolvedValue(on);
    vi.spyOn(api, "disableMfa")
      .mockRejectedValueOnce(new api.ApiError(401, "Invalid code"))
      .mockResolvedValue();
    render(<Security />);
    await userEvent.selectOptions(await screen.findByLabelText("Action"), "disable");
    await userEvent.type(screen.getByLabelText("Current password"), "my current password");
    await userEvent.type(screen.getByLabelText("Authentication or recovery code"), "123456");
    await userEvent.click(
      screen.getByRole("button", { name: "Disable two-factor authentication" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid code");
    expect(screen.getByText("Enabled", { exact: true })).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "Disable two-factor authentication" }),
    );
    expect(await screen.findByText("Not enabled")).toBeInTheDocument();
  });

  it("displays throttling instructions without losing the setup form", async () => {
    vi.spyOn(api, "startMfa").mockRejectedValue(
      new api.ApiError(429, "Too many attempts. Try again in 60 seconds."),
    );
    render(<Security />);
    await userEvent.type(await screen.findByLabelText("Current password"), "my current password");
    await userEvent.click(screen.getByRole("button", { name: "Set up two-factor authentication" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("60 seconds");
    expect(screen.getByRole("button", { name: "Set up two-factor authentication" })).toBeEnabled();
  });

  it("can retry loading the security settings", async () => {
    vi.mocked(api.mfaStatus).mockRejectedValueOnce(new Error("offline")).mockResolvedValue(off);
    render(<Security />);
    await userEvent.click(await screen.findByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByText("Not enabled")).toBeInTheDocument());
  });
});
