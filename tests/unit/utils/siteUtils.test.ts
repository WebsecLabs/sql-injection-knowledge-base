import { describe, it, expect } from "vitest";
import { requireSiteUrl, toCanonicalUrl } from "../../../src/utils/siteUtils";

const OFFICIAL = "https://websec.ca/sql-injection-knowledge-base/";

describe("requireSiteUrl", () => {
  it("returns the configured site", () => {
    const site = new URL("https://websec.ca");
    expect(requireSiteUrl(site)).toBe(site);
  });

  it("throws when the site is not configured", () => {
    expect(() => requireSiteUrl(undefined)).toThrow(/Astro.site must be configured/);
  });
});

describe("toCanonicalUrl", () => {
  it("maps integrated-mode paths onto the canonical base", () => {
    expect(
      toCanonicalUrl(
        "/sql-injection-knowledge-base/mysql/intro/",
        "/sql-injection-knowledge-base/",
        OFFICIAL
      )
    ).toBe(`${OFFICIAL}mysql/intro/`);
  });

  it("maps standalone paths onto the official base", () => {
    expect(toCanonicalUrl("/mysql/intro/", "/", OFFICIAL)).toBe(`${OFFICIAL}mysql/intro/`);
  });

  it("maps the home page to the canonical base", () => {
    expect(toCanonicalUrl("/", "/", OFFICIAL)).toBe(OFFICIAL);
    expect(
      toCanonicalUrl("/sql-injection-knowledge-base/", "/sql-injection-knowledge-base/", OFFICIAL)
    ).toBe(OFFICIAL);
  });

  it("honours a custom canonical base without a trailing slash", () => {
    expect(toCanonicalUrl("/oracle/timing/", "/", "https://kb.example.com")).toBe(
      "https://kb.example.com/oracle/timing/"
    );
  });

  it("handles a base path without a trailing slash", () => {
    expect(toCanonicalUrl("/kb/extras/about/", "/kb", "https://example.com/docs/")).toBe(
      "https://example.com/docs/extras/about/"
    );
  });
});
