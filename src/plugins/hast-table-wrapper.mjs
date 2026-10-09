import { defineHastPlugin } from "satteri";

const HEADING = /^h[1-6]$/;

/** Text of the closest heading before `node` among its siblings, if any */
function precedingHeadingText(node, context) {
  const parent = context.parent(node);
  const index = context.indexOf(node);
  if (!parent || index === undefined) return "";
  for (let i = index - 1; i >= 0; i--) {
    const sibling = parent.children[i];
    if (sibling.type === "element" && HEADING.test(sibling.tagName)) {
      return context.textContent(sibling).trim();
    }
  }
  return "";
}

/**
 * Sätteri hast plugin that wraps tables in a scrollable region, so wide tables
 * scroll on their own instead of widening the page on small screens. The
 * region is focusable and named so keyboard and screen reader users can reach
 * and scroll it (WCAG 2.1.1 and 1.4.10).
 */
export function hastTableWrapper() {
  return defineHastPlugin({
    name: "hast-table-wrapper",
    element: {
      filter: ["table"],
      visit(node, context) {
        const parent = context.parent(node);
        const parentClass = parent?.type === "element" ? parent.properties.className : undefined;
        if (Array.isArray(parentClass) && parentClass.includes("table-wrapper")) return;

        const caption = node.children.find(
          (child) => child.type === "element" && child.tagName === "caption"
        );
        const name =
          (caption && context.textContent(caption).trim()) || precedingHeadingText(node, context);

        context.wrapNode(node, {
          type: "element",
          tagName: "div",
          properties: {
            className: ["table-wrapper"],
            role: "region",
            tabIndex: 0,
            ariaLabel: name ? `${name} (table)` : "Table",
          },
          children: [],
        });
      },
    },
  });
}
