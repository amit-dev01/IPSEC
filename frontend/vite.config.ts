import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const backendOrigin = process.env.VITE_BACKEND_ORIGIN || "https://ipsec-app.onrender.com";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  preview: {
    proxy: {
      "/api": {
        target: backendOrigin,
        changeOrigin: true,
        secure: backendOrigin.startsWith("https"),
      },
    },
  },
  server: {
    proxy: {
      // Same-origin topology: browser calls /api/v1, Vite proxies to
      // the live Render backend or local FastAPI.
      "/api": {
        target: backendOrigin,
        changeOrigin: true,
        secure: backendOrigin.startsWith("https"),
      },
    },
  },
});
