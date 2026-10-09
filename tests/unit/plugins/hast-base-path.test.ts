/**
 * Tests for the base-path Sätteri plugin
 * @vitest-environment node
 */
import { describe, it, expect } from "vitest";
import { markdownToHtml } from "satteri";
import { hastBasePath } from "../../../src/plugins/hast-base-path.mjs";

function render(markdown: string, base: string): string {
  const result = markdownToHtml(markdown, {
    features: { rawHtml: true },
    hastPlugins: [hastBasePath({ base })],
  });
  return result.html;
}

describe("hastBasePath", () => {
  const base = "/sql-injection-knowledge-base/";

  it("prefixes internal absolute links in Markdown syntax", () => {
    expect(render("[a](/mysql/intro)", base)).toContain(
      'href="/sql-injection-knowledge-base/mysql/intro/"'
    );
  });

  it("prefixes internal absolute links in raw HTML", () => {
    expect(render('<a href="/mysql/intro">a</a>', base)).toContain(
      'href="/sql-injection-knowledge-base/mysql/intro/"'
    );
  });

  it("does not double-prefix links that already include the base", () => {
    expect(render("[a](/sql-injection-knowledge-base/mysql/intro/)", base)).toContain(
      'href="/sql-injection-knowledge-base/mysql/intro/"'
    );
  });

  it("adds the trailing slash before a fragment or query string", () => {
    expect(render("[a](/mysql/intro#comments)", base)).toContain(
      'href="/sql-injection-knowledge-base/mysql/intro/#comments"'
    );
    expect(render("[a](/search?q=union)", base)).toContain(
      'href="/sql-injection-knowledge-base/search/?q=union"'
    );
  });

  it("leaves links to files unchanged apart from the base", () => {
    expect(render("[a](/og-image.png)", base)).toContain(
      'href="/sql-injection-knowledge-base/og-image.png"'
    );
  });

  it.each([
    ["protocol-relative", "//example.com/x"],
    ["external", "https://websec.ca/"],
    ["relative", "password-hashing"],
    ["fragment", "#section"],
  ])("leaves %s links unchanged", (_label, href) => {
    expect(render(`[a](${href})`, base)).toContain(`href="${href}"`);
  });

  it("normalizes a base without a trailing slash", () => {
    expect(render("[a](/mysql/intro)", "/kb")).toContain('href="/kb/mysql/intro/"');
  });

  it("only adds the trailing slash for the root base", () => {
    expect(render("[a](/mysql/intro)", "/")).toContain('href="/mysql/intro/"');
  });
});
