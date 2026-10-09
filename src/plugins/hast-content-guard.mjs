import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { defineHastPlugin, markdownToHtml } from "satteri";

/**
 * Elements that can execute code, load active content or change how the
 * page resolves URLs. Article content never needs them.
 */
const BLOCKED_ELEMENTS = [
  "script",
  "iframe",
  "frame",
  "frameset",
  "object",
  "embed",
  "applet",
  "base",
  "meta",
  "link",
  "style",
  "form",
  "svg",
  "math",
  "template",
];

const URL_PROPERTIES = new Set([
  "href",
  "src",
  "srcSet",
  "action",
  "formAction",
  "poster",
  "cite",
  "background",
  "xLinkHref",
]);

// Strip whitespace and control characters browsers ignore inside a scheme
const UNSAFE_URL = /^(?:javascript|vbscript|data):/i;

function isUnsafeUrl(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.some(
    (v) => typeof v === "string" && UNSAFE_URL.test(v.replace(/[\s\u0000-\u001f]+/g, ""))
  );
}

function reject(message) {
  throw new Error(message);
}

function describeLocation(context) {
  return context.fileURL ? fileURLToPath(context.fileURL) : "markdown content";
}

/**
 * Sätteri hast plugin that fails the build when Markdown content contains
 * markup able to run script: blocked elements, inline event handlers or
 * script-capable URLs. Requires `features: { rawHtml: true }` so that raw
 * HTML in Markdown is parsed into elements this plugin can inspect.
 */
export const hastContentGuard = defineHastPlugin({
  name: "hast-content-guard",
  element: {
    // An empty filter visits every element
    filter: [],
    visit(node, context) {
      const where = describeLocation(context);

      if (BLOCKED_ELEMENTS.includes(node.tagName)) {
        reject(`${where}: <${node.tagName}> is not allowed in content`);
      }

      for (const [name, value] of Object.entries(node.properties ?? {})) {
        if (/^on/i.test(name)) {
          reject(`${where}: event handler attribute "${name}" on <${node.tagName}>`);
        }
        if (URL_PROPERTIES.has(name) && isUnsafeUrl(value)) {
          reject(`${where}: unsafe URL in "${name}" on <${node.tagName}>`);
        }
      }
    },
  },
  raw(_node, context) {
    // With rawHtml enabled no raw nodes should remain; refuse anything unparsed
    reject(`${describeLocation(context)}: unparsed raw HTML in content`);
  },
});

/**
 * Astro integration that checks every Markdown file under `contentDir` with
 * hastContentGuard before the build starts, and fails the build on any
 * violation. Astro's content loader only logs render errors and caches
 * rendered entries, so the render-time plugin alone cannot gate a build.
 */
export function contentGuardIntegration({ contentDir = "src/content" } = {}) {
  return {
    name: "content-guard",
    hooks: {
      "astro:build:start": async ({ logger }) => {
        const root = path.resolve(contentDir);
        const files = (await readdir(root, { recursive: true }))
          .filter((file) => file.endsWith(".md"))
          .map((file) => path.join(root, file));

        const violations = [];
        for (const file of files) {
          const source = await readFile(file, "utf8");
          // Frontmatter is YAML, not Markdown; only the body can contain HTML
          const body = source.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, "");
          try {
            markdownToHtml(body, {
              features: { rawHtml: true },
              hastPlugins: [hastContentGuard],
              fileURL: pathToFileURL(file),
            });
          } catch (error) {
            violations.push(error instanceof Error ? error.message : String(error));
          }
        }

        if (violations.length > 0) {
          throw new Error(
            `Content guard rejected ${violations.length} file(s):\n- ${violations.join("\n- ")}`
          );
        }
        logger.info(`Checked ${files.length} Markdown files`);
      },
    },
  };
}
