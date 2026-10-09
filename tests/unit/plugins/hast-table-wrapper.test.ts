/**
 * Tests for the table wrapper Sätteri plugin
 * @vitest-environment node
 */
import { describe, it, expect } from "vitest";
import { markdownToHtml } from "satteri";
import { hastTableWrapper } from "../../../src/plugins/hast-table-wrapper.mjs";

function render(markdown: string): string {
  return markdownToHtml(markdown, {
    features: { rawHtml: true },
    hastPlugins: [hastTableWrapper()],
  }).html;
}

const TABLE = "| a | b |\n|---|---|\n| 1 | 2 |";

describe("hastTableWrapper", () => {
  it("wraps Markdown tables in a focusable, named scroll region", () => {
    const html = render(`## Default databases\n\n${TABLE}`);
    expect(html).toMatch(
      /<div class="table-wrapper" role="region" tabindex="0" aria-label="Default databases \(table\)"><table>/
    );
    expect(html).toContain("</table></div>");
  });

  it("names the region after the table caption when there is one", () => {
    const html = render("<table><caption>Versions</caption><tr><td>1</td></tr></table>");
    expect(html).toContain('aria-label="Versions (table)"');
  });

  it("falls back to a generic name without a heading or caption", () => {
    expect(render(TABLE)).toContain('aria-label="Table"');
  });

  it("does not wrap a table twice", () => {
    const html = render(`<div class="table-wrapper"><table><tr><td>1</td></tr></table></div>`);
    expect(html.match(/table-wrapper/g)).toHaveLength(1);
  });
});
