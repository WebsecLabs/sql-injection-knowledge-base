import { defineHastPlugin } from "satteri";

/**
 * Add a trailing slash to page paths, keeping any query string or fragment.
 * Paths whose last segment has a file extension (e.g. /og-image.png) are files
 * and stay as they are.
 */
function withTrailingSlash(href) {
  const match = href.match(/^([^?#]*)(.*)$/);
  const [, path, suffix] = match;
  const lastSegment = path.slice(path.lastIndexOf("/") + 1);
  if (path.endsWith("/") || lastSegment.includes(".")) return href;
  return `${path}/${suffix}`;
}

/**
 * Sätteri hast plugin for internal links: prefixes them with the base path so
 * they work when deployed to a subdirectory, and adds the trailing slash used
 * by page URLs so links never go through a redirect.
 */
export function hastBasePath(options = {}) {
  // Normalize base to always have exactly one trailing slash
  const rawBase = options.base || "/";
  const base = rawBase.replace(/\/+$/, "") + "/";

  return defineHastPlugin({
    name: "hast-base-path",
    element: {
      filter: ["a"],
      visit(node, context) {
        const href = node.properties.href;
        // Only process internal absolute links (start with / but not //)
        if (typeof href !== "string" || !href.startsWith("/") || href.startsWith("//")) {
          return;
        }
        // Remove leading slash and prepend normalized base, unless already present
        const prefixed = href.startsWith(base) ? href : base + href.slice(1);
        const rewritten = withTrailingSlash(prefixed);
        if (rewritten !== href) {
          context.setProperty(node, "href", rewritten);
        }
      },
    },
  });
}
