import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;
const baseURL = process.env.BASE_URL || "http://localhost:8080/sql-injection-knowledge-base/";
// Default timeout for Docker webServer startup (120s for cold image pulls)
// Can be overridden via PLAYWRIGHT_WEBSERVER_TIMEOUT env var for different environments
const webServerTimeout = Number(process.env.PLAYWRIGHT_WEBSERVER_TIMEOUT) || 120000;
// CI worker count - override via PLAYWRIGHT_WORKERS env var if needed
// Default: 2 workers in CI for reasonable parallelism, undefined locally (uses CPU cores)
const ciWorkers = Number(process.env.PLAYWRIGHT_WORKERS) || 2;

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? ciWorkers : undefined,
  reporter: "html",
  use: {
    baseURL,
    trace: "on-first-retry",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // Only use Docker webServer locally, not in CI (CI uses pre-built artifacts)
  ...(isCI
    ? {}
    : {
        webServer: {
          // Use a robust script that handles container lifecycle properly
          command: "./docker-run.sh",
          url: baseURL,
          reuseExistingServer: true,
          timeout: webServerTimeout,
        },
      }),
});
