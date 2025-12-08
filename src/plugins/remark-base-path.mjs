import { visit } from "unist-util-visit";

/**
 * Remark plugin to prefix internal links with the base path.
 * This ensures markdown links work correctly when deployed to a subdirectory.
 */
export function remarkBasePath(options = {}) {
  // Normalize base to always have exactly one trailing slash
  const rawBase = options.base || "/";
  const base = rawBase.replace(/\/+$/, "") + "/";

  return (tree) => {
    visit(tree, "link", (node) => {
      // Only process internal absolute links (start with / but not //)
      if (
        node.url &&
        node.url.startsWith("/") &&
        !node.url.startsWith("//") &&
        !node.url.startsWith(base)
      ) {
        // Remove leading slash and prepend normalized base
        node.url = base + node.url.slice(1);
      }
    });
  };
}
