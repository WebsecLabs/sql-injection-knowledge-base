import { defineConfig } from "astro/config";
import tsconfigPaths from "vite-tsconfig-paths";
import sitemap from "@astrojs/sitemap";
import { remarkBasePath } from "./src/plugins/remark-base-path.mjs";

// Use "/" for standalone mode, "/sql-injection-knowledge-base/" for integrated mode
const isStandalone = process.env.STANDALONE === "true";
const base = isStandalone ? "/" : "/sql-injection-knowledge-base/";
const standaloneSiteUrl = process.env.SITE_URL || "http://localhost:3000";

export default defineConfig({
  site: isStandalone ? standaloneSiteUrl : "https://websec.ca",
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
