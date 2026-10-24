import { defineConfig, devices } from "@playwright/test";

/**
 * E2E against the production build served by `vite preview`, backed by the
 * deterministic mock API (e2e/mock-api.mjs) on :8000. In CI the same suite
 * can target the full Docker Compose stack by setting E2E_BASE_URL.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:4173",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : [
        {
          command: "node e2e/mock-api.mjs",
          url: "http://127.0.0.1:8000/api/v1/health/ready",
          reuseExistingServer: true,
        },
        {
          command: "pnpm build && pnpm preview --port 4173 --host 127.0.0.1",
          url: "http://127.0.0.1:4173",
          timeout: 180_000,
          reuseExistingServer: true,
        },
      ],
});
