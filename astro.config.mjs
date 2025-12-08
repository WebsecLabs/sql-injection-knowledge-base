import { defineConfig } from "astro/config";
import tsconfigPaths from "vite-tsconfig-paths";
import sitemap from "@astrojs/sitemap";
import { remarkBasePath } from "./src/plugins/remark-base-path.mjs";

const base = "/sql-injection-knowledge-base/";

export default defineConfig({
  site: "https://websec.ca",
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
