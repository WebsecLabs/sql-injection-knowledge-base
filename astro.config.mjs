import { defineConfig } from "astro/config";
import tsconfigPaths from "vite-tsconfig-paths";

import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://websec.ca",
  outDir: "./dist",
  publicDir: "./public",
  base: "/sql-injection-knowledge-base/",

  server: {
    port: 3000,
  },

  vite: {
    plugins: [tsconfigPaths()],
  },

  integrations: [sitemap()],
});
