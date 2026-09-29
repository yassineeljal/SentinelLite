import { Navigate, Route, Routes, useParams } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { TopBar } from "./components/TopBar";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { Login } from "./pages/Login";
import { Mitre } from "./pages/Mitre";

// Keyed on alertId so React remounts AlertDetail (fresh state) when navigating from one alert's
// detail page straight to another's, instead of it reusing the same instance with stale data.
function AlertDetailRoute() {
  const { alertId } = useParams<{ alertId: string }>();
  return <AlertDetail key={alertId} />;
}

export function App() {
  return (
    <AuthProvider>
      <TopBar />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute>
              <Alerts />
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts/:alertId"
          element={
            <ProtectedRoute>
              <AlertDetailRoute />
            </ProtectedRoute>
          }
        />
        <Route
          path="/mitre"
          element={
            <ProtectedRoute>
              <Mitre />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/alerts" replace />} />
      </Routes>
    </AuthProvider>
  );
}
