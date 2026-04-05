import { test, expect } from "@playwright/test";

// E2E test timeout constants for consistent and maintainable test configuration.
const LONG_TIMEOUT_MS = 15000;
const MEDIUM_TIMEOUT_MS = 10000;

test.describe("Search Modal", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/");
  });

  test("should open with Ctrl+K shortcut", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const modal = page.locator("#search-modal");
    await expect(modal).toBeVisible();

    const input = page.locator("#search-modal-input");
    await expect(input).toBeFocused();
  });

  test("should show initial prompt before typing", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const initial = page.locator("#search-modal-initial");
    await expect(initial).toBeVisible();
    await expect(initial).toContainText("Start typing to search");
  });

  test("should return results for a common query", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    // Wait for results to appear
    const results = page.locator("#search-modal-results [role='option']");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Should have multiple results (one Intro per database)
    const count = await results.count();
    expect(count).toBeGreaterThan(0);

    // Initial prompt should be hidden
    const initial = page.locator("#search-modal-initial");
    await expect(initial).toBeHidden();
  });

  test("should show result titles and database badges", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const firstResult = page.locator("#search-modal-results [role='option']").first();
    await expect(firstResult).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Result should have a title
    const title = firstResult.locator(".search-result-title");
    await expect(title).toBeVisible();

    // Result should have a database badge
    const badge = firstResult.locator(".search-result-badge");
    await expect(badge).toBeVisible();
  });

  test("should navigate to result when clicked", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const firstResult = page.locator("#search-modal-results [role='option']").first();
    await expect(firstResult).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    await firstResult.click();

    // Should navigate to a content page (URL contains /intro or similar)
    await page.waitForURL(/\/\w+\/\w+/, { timeout: MEDIUM_TIMEOUT_MS });
  });

  test("should close with Escape key from empty input", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const modal = page.locator("#search-modal");
    await expect(modal).toBeVisible();

    // With empty input, Escape closes the modal (with animation delay)
    await page.keyboard.press("Escape");
    await expect(modal).not.toHaveAttribute("open", { timeout: MEDIUM_TIMEOUT_MS });
  });

  test("should clear input on first Escape, close on second", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const modal = page.locator("#search-modal");
    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const results = page.locator("#search-modal-results [role='option']");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // First Escape clears the search input (native <input type="search"> behavior)
    await page.keyboard.press("Escape");
    await expect(modal).toBeVisible();
    await expect(input).toHaveValue("");

    // Second Escape closes the modal
    await page.keyboard.press("Escape");
    await expect(modal).not.toHaveAttribute("open", { timeout: MEDIUM_TIMEOUT_MS });
  });

  test("should navigate results with arrow keys", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const results = page.locator("#search-modal-results [role='option']");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Press down arrow to select first result
    await page.keyboard.press("ArrowDown");

    const firstResult = results.first();
    await expect(firstResult).toHaveAttribute("aria-selected", "true");

    // Input should reference active descendant
    await expect(input).toHaveAttribute("aria-activedescendant", "search-result-0");
  });

  test("should announce results to screen readers", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const srStatus = page.locator("#search-modal-sr-status");
    await expect(srStatus).toContainText(/\d+ results? found/, { timeout: LONG_TIMEOUT_MS });
  });

  test("should reset state when reopened", async ({ page }) => {
    // Open and type
    await page.keyboard.press("Control+k");
    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const results = page.locator("#search-modal-results [role='option']");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });

    // Close
    await page.keyboard.press("Escape");

    // Reopen — should be reset
    await page.keyboard.press("Control+k");
    await expect(input).toHaveValue("");

    const initial = page.locator("#search-modal-initial");
    await expect(initial).toBeVisible();
  });
});

test.describe("Search Modal - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
  });

  test("should open with Ctrl+K on mobile", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const modal = page.locator("#search-modal");
    await expect(modal).toBeVisible();

    const input = page.locator("#search-modal-input");
    await expect(input).toBeVisible();
  });

  test("should show results on mobile", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const input = page.locator("#search-modal-input");
    await input.fill("Intro");

    const results = page.locator("#search-modal-results [role='option']");
    await expect(results.first()).toBeVisible({ timeout: LONG_TIMEOUT_MS });
  });
});

test.describe("Navbar Search Trigger", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");
  });

  test("should display search trigger button in navbar", async ({ page }) => {
    const searchTrigger = page.locator("#search-trigger");
    await expect(searchTrigger).toBeVisible();
  });

  test("should display search trigger at intermediate viewport width (1280px)", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    const searchTrigger = page.locator("#search-trigger");
    await expect(searchTrigger).toBeVisible();
  });

  test("should open search modal when trigger is clicked", async ({ page }) => {
    const searchTrigger = page.locator("#search-trigger");
    await searchTrigger.click();

    const searchModal = page.locator("#search-modal");
    await expect(searchModal).toBeVisible();
  });

  test("should open search modal with Ctrl+K shortcut", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const searchModal = page.locator("#search-modal");
    await expect(searchModal).toBeVisible();
  });
});
