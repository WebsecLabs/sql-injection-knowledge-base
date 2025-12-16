import { defineConfig } from "astro/config";
import tsconfigPaths from "vite-tsconfig-paths";
import sitemap from "@astrojs/sitemap";
import { remarkBasePath } from "./src/plugins/remark-base-path.mjs";

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
    plugins: [tsconfigPaths()],
  },

  markdown: {
    remarkPlugins: [[remarkBasePath, { base }]],
  },

  integrations: [sitemap()],
});
