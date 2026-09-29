import { Navigate, Route, Routes, useParams } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { TopBar } from "./components/TopBar";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { Blocks } from "./pages/Blocks";
import { Incidents } from "./pages/Incidents";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Security } from "./pages/Security";
import { Login } from "./pages/Login";
import { WorldMap } from "./pages/Map";
import { Mitre } from "./pages/Mitre";

// Keyed on alertId so React remounts AlertDetail (fresh state) when navigating from one alert's
// detail page straight to another's, instead of it reusing the same instance with stale data.
function AlertDetailRoute() {
  const { alertId } = useParams<{ alertId: string }>();
  return <AlertDetail key={alertId} />;
}

function IncidentDetailRoute() {
  const { incidentId } = useParams<{ incidentId: string }>();
  return <IncidentDetail key={incidentId} />;
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
        <Route
          path="/map"
          element={
            <ProtectedRoute>
              <WorldMap />
            </ProtectedRoute>
          }
        />
        <Route
          path="/incidents"
          element={
            <ProtectedRoute>
              <Incidents />
            </ProtectedRoute>
          }
        />
        <Route
          path="/incidents/:incidentId"
          element={
            <ProtectedRoute>
              <IncidentDetailRoute />
            </ProtectedRoute>
          }
        />
        <Route
          path="/blocks"
          element={
            <ProtectedRoute>
              <Blocks />
            </ProtectedRoute>
          }
        />
        <Route
          path="/security"
          element={
            <ProtectedRoute>
              <Security />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/alerts" replace />} />
      </Routes>
    </AuthProvider>
  );
}
