import { useEffect, useState } from "react";
import QRCode from "qrcode";
import * as api from "../api/client";
import type { MFASetup, MFAStatus } from "../api/types";

type Action = "setup" | "confirm" | "regenerate" | "disable";

export function Security() {
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [setup, setSetup] = useState<MFASetup | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [action, setAction] = useState<"regenerate" | "disable">("regenerate");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    api.mfaStatus().then(
      (found) => {
        if (active) {
          setStatus(found);
          setError(null);
        }
      },
      (err: unknown) => {
        if (active)
          setError(err instanceof api.ApiError ? err.message : "Could not load security settings");
      },
    );
    return () => {
      active = false;
    };
  }, [revision]);

  async function submit(next: Action) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (next === "setup") {
        const found = await api.startMfa(password);
        setSetup(found);
        // Generate locally: no secret or provisioning URI is sent to a QR service.
        try {
          setQr(await QRCode.toDataURL(found.provisioning_uri, { width: 240, margin: 4 }));
        } catch {
          setNotice("QR code unavailable. Enter the setup key manually in your authenticator.");
        }
      } else {
        if (next === "disable") {
          await api.disableMfa(password, code.trim());
          setCodes(null);
          setStatus(
            (previous) => previous && { ...previous, enabled: false, recovery_codes_remaining: 0 },
          );
          setNotice("Two-factor authentication disabled. Other sessions have been signed out.");
        } else {
          const result =
            next === "confirm"
              ? await api.confirmMfa(password, code.trim())
              : await api.regenerateRecoveryCodes(password, code.trim());
          setCodes(result.recovery_codes);
          setStatus(
            (previous) =>
              previous && {
                ...previous,
                enabled: true,
                recovery_codes_remaining: result.recovery_codes.length,
              },
          );
          setNotice("Two-factor authentication enabled. Other sessions have been signed out.");
        }
        setSetup(null);
        setQr(null);
        setPassword("");
        setCode("");
      }
    } catch (err) {
      setError(err instanceof api.ApiError ? err.message : "Could not update security settings");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="security-page">
      <h1>Account security</h1>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {!status && !error && <p className="status">Loading…</p>}
      {!status && error && (
        <button
          onClick={() => {
            setError(null);
            setRevision((n) => n + 1);
          }}
        >
          Retry
        </button>
      )}
      {status && (
        <>
          <h2>Two-factor authentication</h2>
          <p>{status.enabled ? "Enabled" : "Not enabled"}</p>
          {codes ? (
            <section className="recovery-panel">
              <h2>Save your recovery codes</h2>
              <p>
                These codes are shown only once. Store them somewhere safe. Each code can replace
                your authenticator code once, together with your password. Any previous recovery
                codes are now invalid.
              </p>
              <ul className="recovery-codes">
                {codes.map((value) => (
                  <li key={value}>
                    <code>{value}</code>
                  </li>
                ))}
              </ul>
              <button onClick={() => setCodes(null)}>I have saved my recovery codes</button>
            </section>
          ) : (
            <>
              {status.enabled && (
                <p>{status.recovery_codes_remaining} recovery code(s) remaining.</p>
              )}
              {!status.enabled && !status.setup_available && (
                <p>Two-factor setup is unavailable. Contact your administrator.</p>
              )}
              {(status.enabled || status.setup_available) && (
                <form
                  className="security-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void submit(status.enabled ? action : setup ? "confirm" : "setup");
                  }}
                >
                  <fieldset disabled={busy}>
                    {setup && (
                      <section>
                        <h2>Add SentinelLite to your authenticator</h2>
                        <p>
                          Scan the QR code or enter the setup key manually. This setup expires at{" "}
                          {new Date(setup.expires_at).toLocaleTimeString()}.
                        </p>
                        {qr && (
                          <img
                            className="totp-qr"
                            src={qr}
                            alt="Authenticator setup QR code"
                            width={240}
                            height={240}
                          />
                        )}
                        <p>
                          Setup key: <code className="setup-key">{setup.secret}</code>
                        </p>
                        <p>
                          Enter the six-digit code from your app to enable two-factor
                          authentication.
                        </p>
                      </section>
                    )}
                    {status.enabled && (
                      <label>
                        Action
                        <select
                          value={action}
                          onChange={(e) => setAction(e.target.value as "regenerate" | "disable")}
                        >
                          <option value="regenerate">Generate new recovery codes</option>
                          <option value="disable">Disable two-factor authentication</option>
                        </select>
                      </label>
                    )}
                    {status.enabled && (
                      <p>
                        {action === "disable"
                          ? "Disabling removes the second factor from future logins."
                          : "Generating new codes invalidates all previous recovery codes."}{" "}
                        Other sessions will be signed out.
                      </p>
                    )}
                    <label>
                      Current password
                      <input
                        type="password"
                        autoComplete="current-password"
                        required
                        maxLength={1024}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                      />
                    </label>
                    {(setup || status.enabled) && (
                      <label>
                        {setup ? "Authenticator code" : "Authentication or recovery code"}
                        <input
                          autoComplete="one-time-code"
                          autoCapitalize="none"
                          spellCheck={false}
                          required
                          maxLength={setup ? 6 : 64}
                          pattern={setup ? "[0-9]{6}" : undefined}
                          value={code}
                          onChange={(e) => setCode(e.target.value)}
                        />
                      </label>
                    )}
                    {(setup || status.enabled) && (
                      <p className="form-help">
                        A code can only be used once. If you just used your authenticator, wait for
                        its next code.
                      </p>
                    )}
                    <button
                      disabled={busy || !password || ((!!setup || status.enabled) && !code.trim())}
                    >
                      {busy
                        ? "Saving…"
                        : status.enabled
                          ? action === "disable"
                            ? "Disable two-factor authentication"
                            : "Generate new recovery codes"
                          : setup
                            ? "Enable two-factor authentication"
                            : "Set up two-factor authentication"}
                    </button>
                    {setup && (
                      <button
                        type="button"
                        onClick={() => {
                          setSetup(null);
                          setQr(null);
                          setCode("");
                          setPassword("");
                          setError(null);
                        }}
                      >
                        Start over
                      </button>
                    )}
                  </fieldset>
                </form>
              )}
            </>
          )}
        </>
      )}
    </main>
  );
}
