import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": new URL("./src", import.meta.url).pathname },
  },
  server: {
    proxy: {
      // Same-origin topology: browser only calls /api/v1, Vite proxies to
      // the local FastAPI backend. No backend hostname in feature code.
      "/api": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
