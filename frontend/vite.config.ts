import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard and the API are meant to be same-origin in production (see docs/DASHBOARD.md:
// the session cookie is SameSite=Strict). In dev, proxying /v1 keeps that true from the browser's
// point of view too, so no CORS setup is ever needed.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1": "http://127.0.0.1:8000",
    },
  },
});
