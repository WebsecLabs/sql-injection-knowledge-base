import { defineConfig, envField, fontProviders } from "astro/config";
import sitemap from "@astrojs/sitemap";
import { satteri } from "@astrojs/markdown-satteri";
import { hastBasePath } from "./src/plugins/hast-base-path.mjs";
import { contentGuardIntegration, hastContentGuard } from "./src/plugins/hast-content-guard.mjs";
import { cspIntegration } from "./src/plugins/csp-integration.mjs";
import { linkCheckIntegration } from "./src/plugins/link-check-integration.mjs";
import {
  createSitemapOptions,
  isCanonicalDeployment,
  resolveCanonicalBase,
} from "./src/plugins/site-options.mjs";

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

const site = isStandalone ? process.env.SITE_URL : "https://websec.ca";

// Canonical URLs point at websec.ca, the official home, unless CANONICAL_URL
// overrides it. A deployment elsewhere does not publish a competing sitemap.
const canonicalBase = resolveCanonicalBase();
const isCanonical = isCanonicalDeployment(site, base, canonicalBase);

export default defineConfig({
  site,
  outDir: "./dist",
  publicDir: "./public",
  base,
  trailingSlash: "always",

  env: {
    schema: {
      CANONICAL_URL: envField.string({
        context: "server",
        access: "public",
        default: canonicalBase,
      }),
    },
  },

  server: {
    port: 3000,
  },

  build: {
    // Inline page CSS so first paint never waits on a stylesheet request
    inlineStylesheets: "always",
  },

  // Self-hosted from the installed @fontsource packages, so builds need no
  // network. font-display: optional plus Astro's metric-matched fallback faces
  // means text never reflows: a web font is used only if it is ready by first
  // render (it is preloaded), otherwise the fallback stays for that page view.
  // Latin only: the content is English, and other scripts use the fallback.
  fonts: [
    {
      provider: fontProviders.local(),
      name: "Inter",
      cssVariable: "--font-inter",
      fallbacks: ["sans-serif"],
      display: "optional",
      options: {
        variants: [400, 500, 600, 700].map((weight) => ({
          weight,
          style: "normal",
          src: [`@fontsource/inter/files/inter-latin-${weight}-normal.woff2`],
        })),
      },
    },
    {
      provider: fontProviders.local(),
      name: "JetBrains Mono",
      cssVariable: "--font-jetbrains-mono",
      fallbacks: ["monospace"],
      display: "optional",
      options: {
        variants: [400, 500].map((weight) => ({
          weight,
          style: "normal",
          src: [`@fontsource/jetbrains-mono/files/jetbrains-mono-latin-${weight}-normal.woff2`],
        })),
      },
    },
  ],

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

  integrations: [
    ...(isCanonical ? [sitemap(createSitemapOptions({ site, base }))] : []),
    contentGuardIntegration(),
    linkCheckIntegration(),
    cspIntegration(),
  ],
});
