import { test, expect, type Page } from "@playwright/test";

// Use a page known to have multiple headings for TOC tests
const TOC_TEST_PAGE = "/mysql/testing-injection";

// TOC width constants (must match values in toc.css)
const TOC_EXPANDED_WIDTH = "250px";
const TOC_COLLAPSED_WIDTH = "48px";

/**
 * Waits for scroll position to stabilize (stop changing).
 * Uses requestAnimationFrame to detect when scrollY remains constant for 3 frames.
 */
async function waitForScrollToStabilize(page: Page, timeout = 5000): Promise<void> {
  await page.waitForFunction(
    () => {
      return new Promise<boolean>((resolve) => {
        let lastY = window.scrollY;
        let stableFrames = 0;

        const checkScroll = () => {
          if (window.scrollY === lastY) {
            stableFrames++;
            if (stableFrames >= 3) {
              resolve(true);
              return;
            }
          } else {
            stableFrames = 0;
            lastY = window.scrollY;
          }
          requestAnimationFrame(checkScroll);
        };
        requestAnimationFrame(checkScroll);
      });
    },
    { timeout }
  );
}

/**
 * Waits for a specified number of animation frames to pass.
 * Useful for waiting for layout/rendering to settle after DOM changes.
 */
async function waitForAnimationFrames(page: Page, frameCount = 3, timeout = 1000): Promise<void> {
  await page.waitForFunction(
    (frames: number) => {
      return new Promise<boolean>((resolve) => {
        let count = 0;
        const waitFrames = () => {
          count++;
          if (count >= frames) {
            resolve(true);
          } else {
            requestAnimationFrame(waitFrames);
          }
        };
        requestAnimationFrame(waitFrames);
      });
    },
    frameCount,
    { timeout }
  );
}

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
    // DEPENDENCY: This test relies on /mssql/default-databases having < 2 h2/h3 headings.
    // As of 2025-03-16, this page contains only a table and one paragraph (no h2/h3 headings).
    // If this test fails, either update the expected page or find another page with < 2 headings.
    await page.goto("/mssql/default-databases");
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    const headingCount = await page
      .locator(".entry-content h2, .entry-content h3, .markdown-body h2, .markdown-body h3")
      .count();

    // Assert the precondition: this page should have fewer than 2 headings
    // If this fails, the page content has changed and a different test page is needed
    expect(headingCount).toBeLessThan(2);

    // TOC should not be visible when there are fewer than 2 headings
    await expect(toc).not.toBeVisible();
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

  test("should collapse and expand horizontally when toggle button is clicked", async ({
    page,
  }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    const toggle = page.locator("#toc-toggle");
    const tocContent = page.locator("#toc-content");

    await expect(toc).toBeVisible();
    await expect(toggle).toBeVisible();

    // Initially expanded with full width
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(toggle).toHaveAttribute("aria-label", "Collapse table of contents");
    await expect(tocContent).toBeVisible();
    await expect(toc).toHaveCSS("width", TOC_EXPANDED_WIDTH);

    // Click to collapse horizontally
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toHaveAttribute("aria-label", "Expand table of contents");
    await expect(toc).toHaveClass(/toc-collapsed/);
    // Width should shrink when collapsed (horizontal collapse)
    await expect(toc).toHaveCSS("width", TOC_COLLAPSED_WIDTH);

    // Click to expand
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(toggle).toHaveAttribute("aria-label", "Collapse table of contents");
    await expect(toc).not.toHaveClass(/toc-collapsed/);
    await expect(toc).toHaveCSS("width", TOC_EXPANDED_WIDTH);
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

    // Wait for persisted collapsed state to be applied from localStorage.
    // State is restored during client-side hydration which may occur after element visibility.
    const newToc = page.locator("#toc");
    await expect(newToc).toHaveClass(/toc-collapsed/, { timeout: 5000 });
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

    // URL should include the anchor - use string containment for simpler assertion
    expect(page.url()).toContain(href!);

    // Target heading should be visible
    const targetId = href!.replace("#", "");
    const targetHeading = page.locator(`[id="${targetId}"]`);
    await expect(targetHeading).toBeVisible();
  });

  test("should not have heading covered by navbar after TOC navigation", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const tocLinks = page.locator(".toc-link");
    await expect(tocLinks.first()).toBeVisible();

    // Get navbar height for reference
    const navbar = page.locator(".navbar");
    const navbarBox = await navbar.boundingBox();
    expect(navbarBox).not.toBeNull();
    const navbarHeight = navbarBox!.height;

    // Click on a TOC link that requires scrolling (not the first one)
    const linkCount = await tocLinks.count();
    const linkIndex = Math.min(2, linkCount - 1); // Use 3rd link if available
    const targetLink = tocLinks.nth(linkIndex);

    const href = await targetLink.getAttribute("href");
    expect(href).not.toBeNull();

    await targetLink.click();

    // Wait for smooth scroll to complete by detecting when scroll position stabilizes
    await waitForScrollToStabilize(page);

    // Get the target heading position
    const targetId = href!.replace("#", "");
    const targetHeading = page.locator(`[id="${targetId}"]`);
    await expect(targetHeading).toBeVisible();

    const headingBox = await targetHeading.boundingBox();
    expect(headingBox).not.toBeNull();

    // The heading's top position should be at or below the navbar bottom
    // (with some tolerance for the breathing room we added)
    expect(headingBox!.y).toBeGreaterThanOrEqual(navbarHeight - 5);
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

    // Require sufficient TOC links for meaningful scroll-spy test
    expect(linkCount).toBeGreaterThan(3);

    // Dynamically select a TOC link from the discovered links (not the first few)
    // This avoids hardcoding specific anchor values that may change
    const targetIndex = Math.min(3, linkCount - 1); // Use 4th link if available
    const targetLink = tocLinks.nth(targetIndex);
    await expect(targetLink).toBeVisible();

    await targetLink.click();

    // Wait for scroll spy to update after click navigation (state-based wait)
    // The clicked link should be active (or close to it after scrolling)
    await expect(page.locator(".toc-link-active")).toBeVisible({ timeout: 3000 });
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
    // aria-label changes based on state: "Collapse..." when expanded, "Expand..." when collapsed
    await expect(toggle).toHaveAttribute("aria-label", "Collapse table of contents");
  });

  test("should show indentation for H3 headings", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    // Check if there are H3 items with proper indentation
    const h3Items = page.locator(".toc-item-h3");
    const h3Count = await h3Items.count();

    // Assert precondition: test page must have H3 headings to validate indentation.
    // If this fails, either add H3 content to TOC_TEST_PAGE or use a different test page.
    expect(h3Count).toBeGreaterThan(0);

    // H3 items should have visual indentation via padding-left on the link
    // CSS: .toc-item-h3 .toc-link { padding-left: 1.75rem; } = 28px
    const firstH3Link = h3Items.first().locator(".toc-link");
    await expect(firstH3Link).toHaveCSS("padding-left", "28px");
  });

  test("should remain sticky/fixed when scrolling down the page", async ({ page }) => {
    await page.goto(TOC_TEST_PAGE);
    await page.waitForLoadState("networkidle");

    const toc = page.locator("#toc");
    await expect(toc).toBeVisible();

    // Get initial TOC position relative to viewport
    const initialBoundingBox = await toc.boundingBox();
    expect(initialBoundingBox).not.toBeNull();

    // TOC should start at sticky position (top: 70px)
    expect(initialBoundingBox!.y).toBeGreaterThanOrEqual(60);
    expect(initialBoundingBox!.y).toBeLessThanOrEqual(80);

    // Scroll down significantly
    await page.evaluate(() => window.scrollBy(0, 500));

    // Wait for layout to settle after scroll (3 animation frames)
    await waitForAnimationFrames(page);

    // Get TOC position after scrolling
    const afterScrollBoundingBox = await toc.boundingBox();
    expect(afterScrollBoundingBox).not.toBeNull();

    // TOC should still be at sticky position (~70px from viewport top)
    expect(afterScrollBoundingBox!.y).toBeGreaterThanOrEqual(60);
    expect(afterScrollBoundingBox!.y).toBeLessThanOrEqual(80);

    // Scroll down even more
    await page.evaluate(() => window.scrollBy(0, 500));

    // Wait for layout to settle after scroll (3 animation frames)
    await waitForAnimationFrames(page);

    const finalBoundingBox = await toc.boundingBox();
    expect(finalBoundingBox).not.toBeNull();

    // TOC should still be at sticky position
    expect(finalBoundingBox!.y).toBeGreaterThanOrEqual(60);
    expect(finalBoundingBox!.y).toBeLessThanOrEqual(80);

    // Verify TOC is still visible
    await expect(toc).toBeVisible();
  });
});
