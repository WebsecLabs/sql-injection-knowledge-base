import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

/** The knowledge base's official home; mirrors point search engines here */
export const OFFICIAL_CANONICAL_URL = "https://websec.ca/sql-injection-knowledge-base/";

/** Collections whose index route only redirects to their first entry */
const REDIRECT_COLLECTIONS = ["mysql", "mariadb", "mssql", "oracle", "postgresql", "extras"];

/**
 * Resolve the canonical base URL for this build: CANONICAL_URL when set,
 * otherwise the official websec.ca URL. Always ends with a slash.
 */
export function resolveCanonicalBase(value = process.env.CANONICAL_URL) {
  const url = new URL(value || OFFICIAL_CANONICAL_URL);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`CANONICAL_URL must be an http(s) URL, got "${value}"`);
  }
  return url.href.endsWith("/") ? url.href : `${url.href}/`;
}

/** Whether a build served at site + base is the canonical deployment */
export function isCanonicalDeployment(site, base, canonicalBase) {
  return new URL(base, site).href === canonicalBase;
}

/** Map each entry URL path ("mysql/intro/") to its lastUpdated date */
function readLastUpdated(contentDir) {
  const dates = new Map();
  for (const collection of readdirSync(contentDir)) {
    const dir = path.join(contentDir, collection);
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".md"))) {
      const source = readFileSync(path.join(dir, file), "utf8");
      const match = source.match(/^lastUpdated:\s*["']?(\d{4}-\d{2}-\d{2})/m);
      if (match) dates.set(`${collection}/${file.replace(/\.md$/, "")}/`, new Date(match[1]));
    }
  }
  return dates;
}

/**
 * Options for @astrojs/sitemap: leave out pages that must not be indexed and
 * report each entry's lastUpdated date as lastmod.
 */
export function createSitemapOptions({ site, base, contentDir = "src/content" }) {
  const root = new URL(base, site).href;
  const excluded = new Set(
    ["404/", ...REDIRECT_COLLECTIONS.map((c) => `${c}/`)].map((p) => root + p)
  );
  const lastUpdated = readLastUpdated(contentDir);

  return {
    filter: (page) => !excluded.has(page),
    serialize(item) {
      const lastmod = lastUpdated.get(item.url.slice(root.length));
      return lastmod ? { ...item, lastmod: lastmod.toISOString() } : item;
    },
  };
}
