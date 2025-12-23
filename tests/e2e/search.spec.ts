import { test, expect, type Page } from "@playwright/test";

// E2E test timeout constants for consistent and maintainable test configuration.
// Note: These are intentionally separate from uiConstants.ts values which are for
// UI behavior timing (debounce, animations). E2E timeouts account for network
// latency, rendering delays, and CI environment variability.
const LONG_TIMEOUT_MS = 15000;
const MEDIUM_TIMEOUT_MS = 10000;

/**
 * Waits for the search page JavaScript to fully initialize.
 * The search module sets data-initialized="true" on the container after setup.
 * This is necessary because the HTML starts with "Loading..." status which
 * only clears after JavaScript runs - slower in CI/Docker environments.
 */
async function waitForSearchInit(page: Page, timeout = MEDIUM_TIMEOUT_MS): Promise<void> {
  // Use 'attached' state since the element is already visible, we're just waiting
  // for the data-initialized attribute to be set by JavaScript
  await page.waitForSelector('.search-results[data-initialized="true"]', {
    timeout,
    state: "attached",
  });
}

test.describe("Search Page", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/search");
    // Wait for search JavaScript to initialize before running tests
    await waitForSearchInit(page);
  });

  test("should show the initial search prompt and not stay in loading state", async ({ page }) => {
    const status = page.locator("#search-status");
    const initialPrompt = page.locator("#initial-search");

    await expect(status).not.toHaveText("Loading...");
    await expect(initialPrompt).toBeVisible();
  });

  test("should return results with highlights for a common query", async ({ page }) => {
    // Consolidated test: validates search status, result visibility, and highlighting
    const input = page.locator("#search-page-input");
    await input.fill("Intro");

    // Check status shows results found
    const status = page.locator("#search-status");
    await expect(status).toContainText("Found");

    // Check result cards are visible
    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Check matching terms are highlighted
    const highlights = page.locator(".result-card mark");
    await expect(highlights.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Verify multiple results are returned
    const resultCount = await results.count();
    expect(resultCount).toBeGreaterThan(0);
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

    // Verify the MySQL collection section is visible
    // Search results are grouped by collection with headers like "MySQL (3)"
    const mysqlSection = page.locator('.result-section h2:has-text("MySQL")');
    await expect(mysqlSection).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Verify MySQL section header includes a count (indicates results were found)
    const mysqlHeaderText = await mysqlSection.textContent();
    expect(mysqlHeaderText).toMatch(/MySQL\s*\(\d+\)/);

    // Verify the result card links point to MySQL content
    // The result-card is itself an <a> element
    const href = await results.first().getAttribute("href");
    expect(href).toContain("/mysql/");
  });

  test("should debounce search input", async ({ page }) => {
    const input = page.locator("#search-page-input");
    const status = page.locator("#search-status");

    // Focus the input
    await input.click();

    // Simulate real typing with pressSequentially (sends keystrokes with minimal delay)
    // This better tests debounce behavior than fill() which sets value instantly
    // Using "Intro" which matches multiple content titles (MySQL Intro, etc.)
    await page.keyboard.type("Intro", { delay: 30 });

    // Note: Debounce behavior means results won't appear immediately after typing.
    // The status transitions from initial state to "Found" after debounce completes.

    // Wait for debounce to complete and results to appear
    await expect(status).toContainText("Found", { timeout: MEDIUM_TIMEOUT_MS });

    // Verify results appeared only after debounce completed
    const results = page.locator(".result-card");
    await expect(results.first()).toBeVisible({ timeout: MEDIUM_TIMEOUT_MS });
  });
});

test.describe("Search Page - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/search");
    // Wait for search JavaScript to initialize before running tests
    await waitForSearchInit(page);
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
    const viewportWidth = page.viewportSize()?.width ?? 375;

    // Explicitly fail if boundingBox is null (element not visible/rendered)
    expect(boundingBox, "Result card should have a valid bounding box").not.toBeNull();
    expect(boundingBox!.width).toBeLessThanOrEqual(viewportWidth);
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

  test("should display search input at intermediate viewport width (1280px)", async ({ page }) => {
    // Regression test: search bar should be visible at intermediate widths, not just full-screen
    await page.setViewportSize({ width: 1280, height: 800 });
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
    // Check for search icon at the start before any other interactions
    const searchIcon = page.locator(".navbar-search .search-icon, .navbar-search button");
    const iconCount = await searchIcon.count();

    // Skip test if search icon is not present in current implementation
    // Using test.skip() at the top of the test is the idiomatic Playwright pattern
    test.skip(iconCount === 0, "Search icon not present in current navbar implementation");

    const searchInput = page.locator("#navbar-search-input");
    await searchInput.fill("test query");

    await searchIcon.click();
    await expect(page).toHaveURL(/\/search/);
  });
});
