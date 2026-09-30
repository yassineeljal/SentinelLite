import { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/useAuth";
import { applyTheme, effectiveTheme, saveTheme, storedTheme } from "../theme";
import type { ThemeChoice } from "../theme";

const links = [
  ["/alerts", "Alerts"],
  ["/security", "Security"],
  ["/incidents", "Incidents"],
  ["/blocks", "Blocks"],
  ["/map", "Map"],
  ["/mitre", "MITRE ATT&CK"],
] as const;

function ThemeIcon({ dark }: { dark: boolean }) {
  // Shows what a click switches TO: a sun while dark, a moon while light.
  return dark ? (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2" fill="none" stroke="currentColor" strokeWidth="2" />
      <path
        d="M12 2.5v2.6M12 18.9v2.6M2.5 12h2.6M18.9 12h2.6M5.3 5.3l1.8 1.8M16.9 16.9l1.8 1.8M5.3 18.7l1.8-1.8M16.9 7.1l1.8-1.8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <path
        d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5a8.5 8.5 0 1 0 10.7 10.7z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function TopBar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [choice, setChoice] = useState<ThemeChoice>(storedTheme);
  const dark = effectiveTheme(choice) === "dark";

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  function toggleTheme() {
    const next: ThemeChoice = dark ? "light" : "dark";
    setChoice(next);
    saveTheme(next);
    applyTheme(next);
  }

  return (
    <header className="top-bar">
      <span className="brand">SentinelLite</span>
      {user && (
        <nav className="top-nav" aria-label="Main">
          {links.map(([to, label]) => (
            <NavLink key={to} to={to}>
              {label}
            </NavLink>
          ))}
        </nav>
      )}
      <span className="who">
        <button
          type="button"
          className="icon-button"
          onClick={toggleTheme}
          aria-label={dark ? "Switch to the light theme" : "Switch to the dark theme"}
          title={dark ? "Light theme" : "Dark theme"}
        >
          <ThemeIcon dark={dark} />
        </button>
        {user && (
          <>
            <span className="user-email">{user.email}</span>
            <span className="badge badge-muted role">{user.role}</span>
            <button type="button" onClick={handleLogout}>
              Sign out
            </button>
          </>
        )}
      </span>
    </header>
  );
}
