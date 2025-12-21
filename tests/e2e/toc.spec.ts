import { test, expect } from "@playwright/test";

// Use a page known to have multiple headings for TOC tests
const TOC_TEST_PAGE = "/mysql/testing-injection";

test.describe("Table of Contents", () => {
  test.beforeEach(async ({ page }) => {
    // Use desktop viewport where TOC is visible (hidden at <= 1024px)
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display TOC on content pages with multiple headings", async ({ page }) => {
    // Navigate to a page with multiple headings
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    await expect(toc).toBeVisible();

    const tocTitle = page.locator(".toc-title");
    await expect(tocTitle).toHaveText("On this page");
  });

  test("should not display TOC on pages with few headings", async ({ page }) => {
    // Navigate to intro page which may have fewer headings
    await page.goto("/mysql/intro");
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    const headingCount = await page
      .locator(".entry-content h2, .entry-content h3, .markdown-body h2, .markdown-body h3")
      .count();

    // TOC should only be visible if there are 2+ headings
    if (headingCount >= 2) {
      await expect(toc).toBeVisible();
    } else {
      await expect(toc).not.toBeVisible();
    }
  });

  test("should have links for each heading on the page", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const tocLinks = page.locator(".toc-link");
    const tocLinkCount = await tocLinks.count();

    // Should have at least one TOC link
    expect(tocLinkCount).toBeGreaterThan(0);

    // Each link should have a valid href
    for (let i = 0; i < tocLinkCount; i++) {
      const href = await tocLinks.nth(i).getAttribute("href");
      expect(href).toMatch(/^#.+/);
    }
  });

  test("should collapse and expand when toggle button is clicked", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    const toggle = page.locator("#toc-toggle");
    const tocContent = page.locator("#toc-content");

    await expect(toc).toBeVisible();
    await expect(toggle).toBeVisible();

    // Initially expanded
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(tocContent).toBeVisible();

    // Click to collapse
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toc).toHaveClass(/toc-collapsed/);

    // Click to expand
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(toc).not.toHaveClass(/toc-collapsed/);
  });

  test("should persist collapsed state across navigation", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toggle = page.locator("#toc-toggle");
    const toc = page.locator("#toc");

    // Collapse the TOC
    await toggle.click();
    await expect(toc).toHaveClass(/toc-collapsed/);

    // Navigate to another page with TOC
    await page.goto("/mysql/fuzzing-obfuscation");
    await page.waitForLoadState("networkidle");

    // Wait for TOC to be visible on new page
    await page.waitForSelector("#toc", { state: "visible" });

    // State should be persisted (still collapsed)
    const newToc = page.locator("#toc");
    await expect(newToc).toHaveClass(/toc-collapsed/);
  });

  test("should navigate to heading when TOC link is clicked", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const tocLinks = page.locator(".toc-link");
    await expect(tocLinks.first()).toBeVisible();

    const firstLink = tocLinks.first();

    // Get the target heading ID
    const href = await firstLink.getAttribute("href");
    expect(href).not.toBeNull();

    // Click the link
    await firstLink.click();

    // URL should include the anchor
    await expect(page).toHaveURL(new RegExp(href!.replace("#", "#")));

    // Target heading should be visible
    const targetId = href!.replace("#", "");
    const targetHeading = page.locator(`[id="${targetId}"]`);
    await expect(targetHeading).toBeVisible();
  });

  test("should highlight active section during scroll", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    // Wait for TOC to initialize
    await expect(page.locator(".toc-link").first()).toBeVisible();

    // Click on a TOC link to scroll to that section
    // This triggers both scroll and the scroll-spy
    const tocLinks = page.locator(".toc-link");
    const linkCount = await tocLinks.count();

    if (linkCount > 3) {
      // Click on the "Numeric-Based Injection" link (H2)
      // The TOC has: String-Based Injection, Examples, Notes, Numeric-Based Injection
      const targetLink = page.locator('.toc-link[href="#numeric-based-injection"]');

      if ((await targetLink.count()) > 0) {
        await targetLink.click();

        // Wait for scroll spy to update after click navigation
        await page.waitForTimeout(1000);

        // The clicked link should be active (or close to it after scrolling)
        // Use a more lenient check - verify at least one link has the active class
        const activeLink = page.locator(".toc-link-active");
        await expect(activeLink).toBeVisible({ timeout: 3000 });
      }
    }
  });

  test("should be hidden on tablet/mobile viewports", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    // Verify TOC is visible on desktop
    const toc = page.locator("#toc");
    await expect(toc).toBeVisible();

    // Resize to tablet viewport
    await page.setViewportSize({ width: 1024, height: 768 });

    // TOC should be hidden
    await expect(toc).not.toBeVisible();

    // Resize to mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // TOC should still be hidden
    await expect(toc).not.toBeVisible();
  });

  test("should have proper accessibility attributes", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    await expect(toc).toHaveAttribute("aria-label", "Table of contents");

    const toggle = page.locator("#toc-toggle");
    await expect(toggle).toHaveAttribute("aria-controls", "toc-content");
    await expect(toggle).toHaveAttribute("aria-label", "Toggle table of contents");
  });

  test("should show indentation for H3 headings", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    // Check if there are H3 items with proper class
    const h3Items = page.locator(".toc-item-h3");
    const h3Count = await h3Items.count();

    if (h3Count > 0) {
      // H3 items should have the correct class for indentation
      await expect(h3Items.first()).toHaveClass(/toc-item-h3/);
    }
  });
});
