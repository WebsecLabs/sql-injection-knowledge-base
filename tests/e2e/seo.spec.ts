import { test, expect } from "@playwright/test";

/**
 * Search-engine signals: canonical URLs point at the official home on
 * websec.ca, internal links never go through a redirect, and pages that must
 * not be indexed say so.
 */

const OFFICIAL_BASE = "https://websec.ca/sql-injection-knowledge-base/";

test.describe("SEO", () => {
  test("article canonical and og:url point at the official page", async ({ page }) => {
    await page.goto("mysql/intro/");

    const canonical = await page.locator('link[rel="canonical"]').getAttribute("href");
    expect(canonical).toBe(`${OFFICIAL_BASE}mysql/intro/`);
    await expect(page.locator('meta[property="og:url"]')).toHaveAttribute("content", canonical!);
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", "index, follow");
  });

  test("structured data describes the official site", async ({ page }) => {
    await page.goto("mysql/intro/");

    const schemas = await page
      .locator('script[type="application/ld+json"]')
      .evaluateAll((nodes) => nodes.map((node) => JSON.parse(node.textContent ?? "{}")));
    const article = schemas.find((s) => s["@type"] === "TechArticle");
    const breadcrumbs = schemas.find((s) => s["@type"] === "BreadcrumbList");

    expect(article.mainEntityOfPage["@id"]).toBe(`${OFFICIAL_BASE}mysql/intro/`);
    expect(article.image).toBe(`${OFFICIAL_BASE}og-image.png`);
    expect(breadcrumbs.itemListElement[0].item).toBe(OFFICIAL_BASE);
  });

  test("internal links end with a slash so they never redirect", async ({ page, baseURL }) => {
    await page.goto("mysql/intro/");
    const basePath = new URL(baseURL ?? "http://localhost/").pathname;

    const hrefs = await page
      .locator(`a[href^="${basePath}"]`)
      .evaluateAll((links) => links.map((link) => link.getAttribute("href") ?? ""));
    const pageLinks = hrefs.filter((href) => !/\.[a-z0-9]+(?:[?#]|$)/i.test(href));

    expect(pageLinks.length).toBeGreaterThan(20);
    for (const href of pageLinks) {
      expect(href, href).toMatch(/\/(?:[?#].*)?$/);
    }
  });

  test("search results consolidate onto the search page", async ({ page }) => {
    await page.goto("search/?q=union");

    // Query variants are not separate pages: they all canonicalize to /search/
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
      "href",
      `${OFFICIAL_BASE}search/`
    );
  });

  test("unknown pages return 404 with a helpful page", async ({ page }) => {
    const response = await page.goto("this-page-does-not-exist/");

    expect(response?.status()).toBe(404);
    await expect(page.locator("h1")).toHaveText("Page not found");
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", "noindex, follow");
    await expect(page.locator(".not-found-links a").first()).toBeVisible();
  });

  test("robots.txt advertises the sitemap", async ({ request }) => {
    const response = await request.get("robots.txt");

    expect(response.ok()).toBe(true);
    expect(await response.text()).toContain(`Sitemap: ${OFFICIAL_BASE}sitemap-index.xml`);
  });
});
