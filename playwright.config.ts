import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;
const baseURL = process.env.BASE_URL || "http://localhost:8080/sql-injection-knowledge-base/";

/**
 * Parse an environment variable as an integer with fallback.
 * Returns the fallback value if the env var is not set or is not a valid number.
 */
function parseEnvInt(envValue: string | undefined, fallback: number): number {
  if (!envValue) return fallback;
  const parsed = parseInt(envValue, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

// Default timeout for Docker webServer startup (120s for cold image pulls)
// Can be overridden via PLAYWRIGHT_WEBSERVER_TIMEOUT env var for different environments
const webServerTimeout = parseEnvInt(process.env.PLAYWRIGHT_WEBSERVER_TIMEOUT, 120000);
// CI worker count - override via PLAYWRIGHT_WORKERS env var if needed
// Default: 2 workers in CI for reasonable parallelism, undefined locally (uses CPU cores)
const ciWorkers = parseEnvInt(process.env.PLAYWRIGHT_WORKERS, 2);
// Allow CI to override the webServer command (e.g., to use pre-built artifacts)
const webServerCommand = process.env.PLAYWRIGHT_WEBSERVER_COMMAND || "./docker-run.sh";

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
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],

  // Use webServer to automatically start/stop the server before tests
  // - Locally: uses ./docker-run.sh (default)
  // - In CI: uses PLAYWRIGHT_WEBSERVER_COMMAND env var (e.g., "npx serve dist -l 8080")
  webServer: {
    command: webServerCommand,
    url: baseURL,
    // In CI, always start fresh; locally, reuse existing server if running
    reuseExistingServer: !isCI,
    timeout: webServerTimeout,
  },
});
