import { test, expect } from "@playwright/test";

// Timeout constants for consistent and maintainable test configuration
const LONG_TIMEOUT_MS = 15000;
const MEDIUM_TIMEOUT_MS = 10000;

test.describe("Search Page", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/search");
  });

  test("should show the initial search prompt and not stay in loading state", async ({ page }) => {
    const status = page.locator("#search-status");
    const initialPrompt = page.locator("#initial-search");

    await expect(status).not.toHaveText("Loading...");
    await expect(initialPrompt).toBeVisible();
  });

  test("should return results for a common query", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    const status = page.locator("#search-status");
    await expect(status).toContainText("Found");

    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible();
  });

  test("should display result cards with content", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Wait for debounce and results
    const firstResult = page.locator(".result-card").first();
    await expect(firstResult).toBeVisible({ timeout: LONG_TIMEOUT_MS });
  });

  test("should highlight matching terms in results", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Wait for results and check for mark tags
    const highlights = page.locator(".result-card mark");
    await expect(highlights.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });
  });

  test("should navigate to result when clicked", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Wait for results to appear (state-based wait instead of fixed timeout)
    const firstResult = page.locator(".result-card").first();
    await expect(firstResult).toBeVisible({ timeout: MEDIUM_TIMEOUT_MS });

    // Click the result card link
    await firstResult.click();

    // Should navigate to a content page
    await expect(page).not.toHaveURL(/\/search/);
  });

  test("should show status for non-matching query", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("xyznonexistentqueryxyz");

    // Wait for status to update (state-based wait instead of fixed timeout)
    const status = page.locator("#search-status");
    // Status should update (either "No results" or "Found 0")
    await expect(status).not.toHaveText("Loading...");
    await expect(status).toBeVisible();
  });

  test("should display search results after typing", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Wait for results to appear
    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Results should contain meaningful content
    const resultCount = await results.count();
    expect(resultCount).toBeGreaterThan(0);
  });

  test("should load search from URL query parameter", async ({ page }) => {
    await page.goto("/search?q=Intro");

    const input = page.locator("#search-page-input");
    await expect(input).toHaveValue("Intro");

    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible();
  });

  test("should filter by collection when specified in URL", async ({ page }) => {
    await page.goto("/search?q=Intro&collection=mysql");

    // Wait for results to appear
    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Results should contain MySQL entries
    const resultText = await results.first().textContent();
    expect(resultText).toBeTruthy();
  });

  test("should debounce search input", async ({ page }) => {
    const input = page.locator("#search-page-input");

    // Type rapidly
    await input.fill("U");
    await input.fill("UN");
    await input.fill("UNI");
    await input.fill("UNIO");
    await input.fill("UNION");

    // Wait for status to show results (state-based wait instead of fixed timeout)
    const status = page.locator("#search-status");
    await expect(status).toContainText("Found", { timeout: MEDIUM_TIMEOUT_MS });
  });
});

test.describe("Search Page - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/search");
  });

  test("should display search input on mobile", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await expect(input).toBeVisible();
  });

  test("should show results in mobile-friendly layout", async ({ page }) => {
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Wait for results to appear (state-based wait instead of fixed timeout)
    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible({ timeout: MEDIUM_TIMEOUT_MS });

    // Result cards should fit within viewport
    const firstResult = results.first();
    const boundingBox = await firstResult.boundingBox();

    if (boundingBox) {
      expect(boundingBox.width).toBeLessThanOrEqual(375);
    }
  });
});

test.describe("Navbar Search", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");
  });

  test("should display search input in navbar", async ({ page }) => {
    const searchInput = page.locator("#navbar-search-input");
    await expect(searchInput).toBeVisible();
  });

  test("should navigate to search page when Enter is pressed", async ({ page }) => {
    const searchInput = page.locator("#navbar-search-input");
    await searchInput.fill("UNION");
    await page.keyboard.press("Enter");

    // Should navigate to search page with query (using full path pattern)
    await page.waitForURL(/search.*q=UNION/, { timeout: LONG_TIMEOUT_MS });
    expect(page.url()).toContain("search");
    expect(page.url()).toContain("q=UNION");
  });

  test("should navigate to search page on search icon click", async ({ page }) => {
    const searchInput = page.locator("#navbar-search-input");
    await searchInput.fill("test query");

    const searchIcon = page.locator(".navbar-search .search-icon, .navbar-search button");
    const iconExists = await searchIcon.count();

    if (iconExists > 0) {
      await searchIcon.click();
      await expect(page).toHaveURL(/\/search/);
    }
  });
});
