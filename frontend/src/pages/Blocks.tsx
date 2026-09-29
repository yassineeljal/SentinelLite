import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  addAllowlist,
  listAllowlist,
  listBlocks,
  removeAllowlist,
  unblockAddress,
} from "../api/client";
import type { AllowlistEntry, Block } from "../api/types";
import { useAuth } from "../auth/useAuth";

const modeLabels: Record<Block["mode"], string> = {
  dry_run: "Dry run (nothing applied)",
  enforce: "Enforced",
};

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

export function Blocks() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [blocks, setBlocks] = useState<Block[] | null>(null);
  const [allowlist, setAllowlist] = useState<AllowlistEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    Promise.all([listBlocks(), listAllowlist()]).then(
      ([b, a]) => {
        if (!active) return;
        setBlocks(b);
        setAllowlist(a);
        setError(null);
      },
      (err: unknown) => {
        if (active) setError(message(err, "Could not load the response data"));
      },
    );
    return () => {
      active = false;
    };
  }, [revision]);

  const reload = useCallback(() => setRevision((n) => n + 1), []);

  async function run(action: () => Promise<unknown>, fallback: string) {
    setBusy(true);
    setActionError(null);
    try {
      await action();
      setConfirming(null);
      reload();
    } catch (err) {
      setActionError(message(err, fallback));
    } finally {
      setBusy(false);
    }
  }

  function addEntry(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      await addAllowlist(cidr.trim(), note.trim());
      setCidr("");
      setNote("");
    }, "Could not add to the allowlist");
  }

  return (
    <main className="incidents-page">
      <div className="alerts-toolbar">
        <h1>Blocks</h1>
        <button
          type="button"
          onClick={() => {
            setBlocks(null);
            setAllowlist(null);
            setError(null);
            reload();
          }}
        >
          Refresh
        </button>
      </div>
      {!isAdmin && (
        <p className="status">
          Read only: lifting a block or editing the allowlist needs an admin.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {actionError && (
        <p className="error" role="alert">
          {actionError}
        </p>
      )}

      <h2>Blocked addresses</h2>
      {!blocks && !error && <p className="status">Loading…</p>}
      {blocks?.length === 0 && <p className="status">Nothing blocked yet.</p>}
      {blocks && blocks.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Mode</th>
                <th>State</th>
                <th>Rule</th>
                <th>Since</th>
                <th>Until</th>
                {isAdmin && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {blocks.map((block) => (
                <tr key={block.id}>
                  <td title={block.reason}>{block.ip}</td>
                  <td>{modeLabels[block.mode]}</td>
                  <td>
                    {block.state === "released" && block.released_by
                      ? `Released by ${block.released_by}`
                      : block.state[0].toUpperCase() + block.state.slice(1)}
                  </td>
                  <td>{block.rule_id}</td>
                  <td>{new Date(block.created_at).toLocaleString()}</td>
                  <td>{new Date(block.expires_at).toLocaleString()}</td>
                  {isAdmin && (
                    <td>
                      {block.state === "active" &&
                        (confirming === block.ip ? (
                          <>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() =>
                                void run(() => unblockAddress(block.ip), "Could not unblock")
                              }
                            >
                              Confirm unblock {block.ip}
                            </button>{" "}
                            <button type="button" onClick={() => setConfirming(null)}>
                              Cancel
                            </button>
                          </>
                        ) : (
                          <button type="button" onClick={() => setConfirming(block.ip)}>
                            Unblock
                          </button>
                        ))}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Allowlist</h2>
      <p className="status">
        Addresses and networks that are never blocked, whatever the rules say.
      </p>
      {allowlist?.length === 0 && <p className="status">The allowlist is empty.</p>}
      {allowlist && allowlist.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Note</th>
                <th>Added by</th>
                <th>Added</th>
                {isAdmin && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {allowlist.map((entry) => (
                <tr key={entry.cidr}>
                  <td>{entry.cidr}</td>
                  <td>{entry.note}</td>
                  <td>{entry.created_by}</td>
                  <td>{new Date(entry.created_at).toLocaleString()}</td>
                  {isAdmin && (
                    <td>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void run(() => removeAllowlist(entry.cidr), "Could not remove the entry")
                        }
                      >
                        Remove {entry.cidr}
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {isAdmin && (
        <form className="incident-form" onSubmit={addEntry}>
          <h2>Protect an address</h2>
          <label>
            Address or network
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="203.0.113.7 or 198.51.100.0/24"
              maxLength={64}
              required
            />
          </label>
          <label>
            Note
            <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
          </label>
          <button disabled={busy || !cidr.trim()}>Add to the allowlist</button>
        </form>
      )}
    </main>
  );
}
