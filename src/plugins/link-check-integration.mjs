import { existsSync, statSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ANCHOR_HREF = /<a\b[^>]*?\shref="([^"]*)"/g;
const ELEMENT_ID = /\sid="([^"]*)"/g;

function decodeEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

/**
 * Resolve a site path to the built file that serves it.
 * Returns null when nothing exists, or "directory" when the path names a
 * page directory without its trailing slash (served only via a redirect).
 */
function resolveTarget(outDir, sitePath) {
  const filePath = path.join(outDir, decodeURIComponent(sitePath));
  if (sitePath.endsWith("/")) {
    const index = path.join(filePath, "index.html");
    return existsSync(index) ? index : null;
  }
  if (!existsSync(filePath)) return null;
  return statSync(filePath).isDirectory() ? "directory" : filePath;
}

/**
 * Find internal links in the built pages whose target page or fragment does
 * not exist.
 *
 * @param pages - Map of built file path to HTML
 * @param outDir - The build output directory
 * @param base - The site base path, e.g. "/sql-injection-knowledge-base/"
 * @returns Human-readable descriptions of each broken link
 */
export function findBrokenLinks(pages, outDir, base) {
  const ids = new Map();
  const idsOf = (file) => {
    if (!ids.has(file)) {
      const html = pages.get(file) ?? "";
      ids.set(file, new Set([...html.matchAll(ELEMENT_ID)].map(([, id]) => decodeEntities(id))));
    }
    return ids.get(file);
  };

  const broken = [];
  for (const [file, html] of pages) {
    const page = path.relative(outDir, file);
    // The URL this page is served at, used to resolve relative links
    const pageUrl = new URL(
      base +
        page
          .split(path.sep)
          .join("/")
          .replace(/index\.html$/, ""),
      "http://site.invalid"
    );
    for (const [, rawHref] of html.matchAll(ANCHOR_HREF)) {
      const rawValue = decodeEntities(rawHref);
      // Skip external links and other schemes (https:, mailto:, ...)
      if (/^[a-z][a-z0-9+.-]*:/i.test(rawValue) || rawValue.startsWith("//")) continue;
      const resolved = new URL(rawValue, pageUrl);
      const href = rawValue.startsWith("#")
        ? rawValue
        : resolved.pathname + resolved.search + resolved.hash;
      if (!href.startsWith(base) && !href.startsWith("#")) continue;

      const [pathAndQuery, fragment] = href.split("#", 2);
      const sitePath = pathAndQuery.split("?")[0];
      const target = sitePath ? resolveTarget(outDir, sitePath.slice(base.length - 1)) : file;

      if (!target) {
        broken.push(`${page}: ${href} (no such page)`);
      } else if (target === "directory") {
        broken.push(`${page}: ${href} (missing trailing slash)`);
      } else if (
        fragment &&
        target.endsWith(".html") &&
        !idsOf(target).has(decodeURIComponent(fragment))
      ) {
        broken.push(`${page}: ${href} (no element with id "${fragment}")`);
      }
    }
  }
  return broken;
}

/**
 * Astro integration that fails the build when any internal link in the built
 * site points to a missing page or heading.
 */
export function linkCheckIntegration() {
  let base = "/";
  return {
    name: "link-check",
    hooks: {
      "astro:config:done": ({ config }) => {
        base = config.base.endsWith("/") ? config.base : `${config.base}/`;
      },
      "astro:build:done": async ({ dir, logger }) => {
        const outDir = fileURLToPath(dir);
        const files = (await readdir(outDir, { recursive: true }))
          .filter((file) => file.endsWith(".html"))
          .map((file) => path.join(outDir, file));
        const pages = new Map(
          await Promise.all(files.map(async (file) => [file, await readFile(file, "utf8")]))
        );

        const broken = findBrokenLinks(pages, outDir, base);
        if (broken.length > 0) {
          throw new Error(
            `Found ${broken.length} broken internal link(s):\n- ${broken.join("\n- ")}`
          );
        }
        logger.info(`All internal links resolve across ${files.length} pages`);
      },
    },
  };
}
