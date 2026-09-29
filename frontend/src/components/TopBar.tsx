import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/useAuth";

export function TopBar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <header className="top-bar">
      <span className="brand">SentinelLite</span>
      {user && (
        <nav className="top-nav">
          <Link to="/alerts">Alerts</Link>
          <Link to="/mitre">MITRE ATT&amp;CK</Link>
        </nav>
      )}
      {user && (
        <span className="who">
          {user.email} <span className="role">({user.role})</span>
          <button type="button" onClick={handleLogout}>
            Sign out
          </button>
        </span>
      )}
    </header>
  );
}
