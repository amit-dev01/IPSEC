import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const devBackendOrigin = process.env.VITE_BACKEND_ORIGIN || "https://ipsec-app.onrender.com";
const previewBackendOrigin =
  process.env.VITE_PREVIEW_BACKEND_ORIGIN ||
  process.env.VITE_BACKEND_ORIGIN ||
  "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  preview: {
    proxy: {
      "/api": {
        target: previewBackendOrigin,
        changeOrigin: true,
        secure: previewBackendOrigin.startsWith("https"),
      },
    },
  },
  server: {
    proxy: {
      // Same-origin topology: browser calls /api/v1, Vite dev server proxies to
      // the live Render backend (https://ipsec-app.onrender.com) or custom origin.
      "/api": {
        target: devBackendOrigin,
        changeOrigin: true,
        secure: devBackendOrigin.startsWith("https"),
      },
    },
  },
});
