import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    tsconfigPaths: true,
    alias: {
      // Mock astro:content virtual module for unit tests
      "astro:content": new URL("./tests/mocks/astro-content.ts", import.meta.url).pathname,
    },
  },
  test: {
    include: ["src/**/*.{test,spec}.ts", "tests/unit/**/*.{test,spec}.ts"],
    exclude: ["node_modules", "dist", ".astro", "tests/e2e/**"],
    environment: "jsdom",
    // Node 25+ enables a native localStorage global that shadows jsdom's
    // implementation; disable it so tests behave the same on all Node versions.
    execArgv: ["--no-experimental-webstorage"],
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/utils/**/*.ts"],
      // Note: src/scripts/*.ts are NOT included in coverage collection above.
      // They are tested but excluded from thresholds because they require
      // complex DOM/browser mocking that doesn't translate to meaningful
      // line-by-line coverage metrics.
      thresholds: {
        global: {
          statements: 80,
          branches: 80,
          functions: 80,
          lines: 80,
        },
      },
    },
    setupFiles: ["./tests/setup.ts"],
  },
});
