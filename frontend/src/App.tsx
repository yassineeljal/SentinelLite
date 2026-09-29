import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { TopBar } from "./components/TopBar";
import { Alerts } from "./pages/Alerts";
import { Login } from "./pages/Login";

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
        <Route path="*" element={<Navigate to="/alerts" replace />} />
      </Routes>
    </AuthProvider>
  );
}
