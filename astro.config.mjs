import { defineConfig } from "astro/config";
import tsconfigPaths from "vite-tsconfig-paths";
import sitemap from "@astrojs/sitemap";
import { remarkBasePath } from "./src/plugins/remark-base-path.mjs";

// Use "/" for standalone mode, "/sql-injection-knowledge-base/" for integrated mode
const isStandalone = process.env.STANDALONE === "true";
const base = isStandalone ? "/" : "/sql-injection-knowledge-base/";

export default defineConfig({
  site: isStandalone ? "http://localhost:8080" : "https://websec.ca",
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
