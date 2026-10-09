import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import { satteri } from "@astrojs/markdown-satteri";
import { hastBasePath } from "./src/plugins/hast-base-path.mjs";
import { contentGuardIntegration, hastContentGuard } from "./src/plugins/hast-content-guard.mjs";
import { cspIntegration } from "./src/plugins/csp-integration.mjs";

// Use "/" for standalone mode, "/sql-injection-knowledge-base/" for integrated mode
const isStandalone = process.env.STANDALONE === "true";
const base = isStandalone ? "/" : "/sql-injection-knowledge-base/";

// Standalone mode requires SITE_URL to avoid localhost URLs in sitemaps
// For local development, use: STANDALONE=true SITE_URL=http://localhost:3000 npm run dev
if (isStandalone && !process.env.SITE_URL) {
  throw new Error(
    "SITE_URL environment variable is required when STANDALONE=true.\n" +
      "Set SITE_URL to your production URL (e.g., https://example.com) for builds,\n" +
      "or http://localhost:3000 for local development."
  );
}

export default defineConfig({
  site: isStandalone ? process.env.SITE_URL : "https://websec.ca",
  outDir: "./dist",
  publicDir: "./public",
  base,

  server: {
    port: 3000,
  },

  vite: {
    resolve: {
      tsconfigPaths: true,
    },
    build: {
      // Emit every asset and script as a file instead of a data: URI or inline
      // module. Fonts stay cacheable and out of the render-blocking CSS, and the
      // CSP needs neither data: sources nor ClientRouter's inline-module probe.
      assetsInlineLimit: 0,
    },
  },

  markdown: {
    // Keep SQL syntax such as "--" and quotes literal in prose and headings
    smartypants: false,
    processor: satteri({
      // Parse raw HTML into elements so plugins can inspect and rewrite it
      features: { rawHtml: true },
      hastPlugins: [hastContentGuard, hastBasePath({ base })],
    }),
    shikiConfig: {
      themes: {
        light: "github-light",
        dark: "github-dark",
      },
      defaultColor: false,
    },
  },

  integrations: [sitemap(), contentGuardIntegration(), cspIntegration()],
});
