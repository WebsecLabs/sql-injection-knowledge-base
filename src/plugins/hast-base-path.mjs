import { defineHastPlugin } from "satteri";

/**
 * Sätteri hast plugin that prefixes internal links with the base path.
 * This ensures markdown links work correctly when deployed to a subdirectory.
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
        if (
          typeof href === "string" &&
          href.startsWith("/") &&
          !href.startsWith("//") &&
          !href.startsWith(base)
        ) {
          // Remove leading slash and prepend normalized base
          context.setProperty(node, "href", base + href.slice(1));
        }
      },
    },
  });
}
