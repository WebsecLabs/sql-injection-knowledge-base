import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    include: ["src/**/*.{test,spec}.ts", "tests/unit/**/*.{test,spec}.ts"],
    exclude: ["node_modules", "dist", ".astro", "tests/e2e/**"],
    environment: "jsdom",
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
