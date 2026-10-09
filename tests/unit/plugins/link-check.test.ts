/**
 * Tests for the build-time internal link checker
 * @vitest-environment node
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { findBrokenLinks } from "../../../src/plugins/link-check-integration.mjs";

const BASE = "/kb/";
let outDir: string;

function page(sitePath: string, html: string): [string, string] {
  const file = path.join(outDir, sitePath, "index.html");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, html);
  return [file, html];
}

beforeEach(() => {
  outDir = mkdtempSync(path.join(tmpdir(), "link-check-"));
  writeFileSync(path.join(outDir, "og-image.png"), "");
});

afterEach(() => {
  rmSync(outDir, { recursive: true, force: true });
});

describe("findBrokenLinks", () => {
  it("accepts links to existing pages, headings and files", () => {
    const pages = new Map([
      page("mysql/intro", '<h2 id="comments">C</h2><a href="#comments">x</a>'),
      page(
        "mysql/timing",
        '<a href="/kb/mysql/intro/">a</a><a href="/kb/mysql/intro/#comments">b</a>' +
          '<a href="/kb/og-image.png">c</a><a href="https://example.com/missing">d</a>'
      ),
    ]);

    expect(findBrokenLinks(pages, outDir, BASE)).toEqual([]);
  });

  it("reports links to missing pages", () => {
    const pages = new Map([
      page("mysql/intro", '<a href="/kb/postgresql/operations-syntax/">x</a>'),
    ]);

    expect(findBrokenLinks(pages, outDir, BASE)).toEqual([
      "mysql/intro/index.html: /kb/postgresql/operations-syntax/ (no such page)",
    ]);
  });

  it("reports links to missing headings on another page", () => {
    const pages = new Map([
      page("mysql/fuzzing", '<h3 id="comment-variations">C</h3>'),
      page("postgresql/fuzzing", '<a href="/kb/mysql/fuzzing/#keyword-splitting-myth">x</a>'),
    ]);

    expect(findBrokenLinks(pages, outDir, BASE)).toEqual([
      'postgresql/fuzzing/index.html: /kb/mysql/fuzzing/#keyword-splitting-myth (no element with id "keyword-splitting-myth")',
    ]);
  });

  it("resolves relative links against the page URL", () => {
    const pages = new Map([
      page("mysql/password-hashing", ""),
      page(
        "mysql/credentials",
        '<a href="password-hashing">x</a><a href="../password-hashing/">y</a>'
      ),
    ]);

    expect(findBrokenLinks(pages, outDir, BASE)).toEqual([
      "mysql/credentials/index.html: /kb/mysql/credentials/password-hashing (no such page)",
    ]);
  });

  it("reports missing same-page fragments", () => {
    const pages = new Map([page("mysql/intro", '<a href="#nowhere">x</a>')]);

    expect(findBrokenLinks(pages, outDir, BASE)).toHaveLength(1);
  });

  it("reports page links missing the trailing slash", () => {
    const pages = new Map([
      page("mysql/intro", ""),
      page("mysql/timing", '<a href="/kb/mysql/intro">x</a>'),
    ]);

    expect(findBrokenLinks(pages, outDir, BASE)).toEqual([
      "mysql/timing/index.html: /kb/mysql/intro (missing trailing slash)",
    ]);
  });
});
