/**
 * Tests for canonical URL and sitemap options
 * @vitest-environment node
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  OFFICIAL_CANONICAL_URL,
  createSitemapOptions,
  isCanonicalDeployment,
  resolveCanonicalBase,
} from "../../../src/plugins/site-options.mjs";

describe("resolveCanonicalBase", () => {
  it("defaults to the official websec.ca URL", () => {
    expect(resolveCanonicalBase(undefined)).toBe(OFFICIAL_CANONICAL_URL);
    expect(resolveCanonicalBase("")).toBe(OFFICIAL_CANONICAL_URL);
  });

  it("normalizes a custom URL to end with a slash", () => {
    expect(resolveCanonicalBase("https://kb.example.com")).toBe("https://kb.example.com/");
  });

  it("rejects non-http(s) URLs", () => {
    expect(() => resolveCanonicalBase("javascript:alert(1)")).toThrow(/http\(s\)/);
  });
});

describe("isCanonicalDeployment", () => {
  it("recognizes the official integrated build", () => {
    expect(
      isCanonicalDeployment(
        "https://websec.ca",
        "/sql-injection-knowledge-base/",
        OFFICIAL_CANONICAL_URL
      )
    ).toBe(true);
  });

  it("treats other hosts as mirrors", () => {
    expect(isCanonicalDeployment("https://mirror.example.org", "/", OFFICIAL_CANONICAL_URL)).toBe(
      false
    );
  });
});

describe("createSitemapOptions", () => {
  let contentDir: string;

  afterEach(() => rmSync(contentDir, { recursive: true, force: true }));

  function setup() {
    contentDir = mkdtempSync(path.join(tmpdir(), "sitemap-"));
    mkdirSync(path.join(contentDir, "mysql"));
    writeFileSync(
      path.join(contentDir, "mysql", "intro.md"),
      "---\ntitle: Intro\nlastUpdated: 2025-12-16\n---\n"
    );
    return createSitemapOptions({ site: "https://websec.ca", base: "/kb/", contentDir });
  }

  it("excludes redirect and error pages", () => {
    const { filter } = setup();

    expect(filter("https://websec.ca/kb/mysql/")).toBe(false);
    expect(filter("https://websec.ca/kb/404/")).toBe(false);
    expect(filter("https://websec.ca/kb/mysql/intro/")).toBe(true);
    expect(filter("https://websec.ca/kb/search/")).toBe(true);
  });

  it("reports each entry's lastUpdated date as lastmod", () => {
    const { serialize } = setup();

    expect(serialize({ url: "https://websec.ca/kb/mysql/intro/" })).toEqual({
      url: "https://websec.ca/kb/mysql/intro/",
      lastmod: "2025-12-16T00:00:00.000Z",
    });
    expect(serialize({ url: "https://websec.ca/kb/" })).toEqual({ url: "https://websec.ca/kb/" });
  });
});
