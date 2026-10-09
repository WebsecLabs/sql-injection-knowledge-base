/**
 * Tests for the content guard Sätteri plugin
 * @vitest-environment node
 */
import { describe, it, expect } from "vitest";
import { markdownToHtml } from "satteri";
import { hastContentGuard } from "../../../src/plugins/hast-content-guard.mjs";

function render(markdown: string): string {
  const result = markdownToHtml(markdown, {
    features: { rawHtml: true },
    hastPlugins: [hastContentGuard],
  });
  return result.html;
}

describe("hastContentGuard", () => {
  it.each([
    ["script element", "<script>alert(1)</script>"],
    ["iframe element", '<iframe src="https://example.com"></iframe>'],
    ["inline style element", "<style>body{display:none}</style>"],
    ["svg element", "<svg><circle r='1'/></svg>"],
    ["form element", "<form action='/x'><input></form>"],
    ["base element", '<base href="https://example.com/">'],
    ["event handler", '<img src="x.png" onerror="alert(1)">'],
    ["event handler in inline HTML", 'Text <span onmouseover="alert(1)">hover</span>'],
    ["javascript: link in raw HTML", '<a href="javascript:alert(1)">x</a>'],
    ["javascript: link in Markdown syntax", "[x](javascript:alert(1))"],
    ["entity-encoded javascript: link", '<a href="&#106;avascript:alert(1)">x</a>'],
    ["javascript: link split by whitespace", '<a href="java\tscript:alert(1)">x</a>'],
    ["mixed-case scheme", '<a href="JaVaScRiPt:alert(1)">x</a>'],
    ["data: URL", '<a href="data:text/html,<b>x</b>">x</a>'],
    ["vbscript: URL", '<a href="vbscript:msgbox(1)">x</a>'],
  ])("rejects %s", (_label, markdown) => {
    expect(() => render(markdown)).toThrow(
      /is not allowed in content|event handler attribute|unsafe URL/
    );
  });

  it.each([
    ["details and summary", "<details><summary>More</summary>\n\nBody\n\n</details>"],
    ["relative and absolute links", '[a](/mysql/intro) <a href="https://websec.ca">b</a>'],
    ["inline code with HTML", "`<script>alert(1)</script>` and `onerror=alert(1)`"],
    ["fenced payloads", "```sql\n' UNION SELECT '<script>alert(1)</script>'--\n```"],
    ["anchor links", "[top](#top)"],
  ])("allows %s", (_label, markdown) => {
    expect(render(markdown)).toBeTypeOf("string");
  });
});
