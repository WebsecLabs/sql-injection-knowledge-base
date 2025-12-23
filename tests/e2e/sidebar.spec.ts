import { test, expect, type Locator } from "@playwright/test";

/** Maximum iterations for collapse loop to prevent infinite hangs */
const MAX_COLLAPSE_ATTEMPTS = 10;

/**
 * Checks if a sidebar element is hidden on mobile viewport.
 * Detects various hiding mechanisms: CSS display/visibility, off-screen positioning,
 * zero dimensions, or CSS transform.
 */
async function isSidebarHiddenOnMobile(
  sidebar: Locator,
  viewport: { width: number; height: number } | null
): Promise<boolean> {
  // Check if hidden via CSS display/visibility
  const isHidden = await sidebar.isHidden();
  if (isHidden) {
    return true;
  }

  // Check multiple hiding mechanisms
  const boundingBox = await sidebar.boundingBox();

  // Check if sidebar uses CSS transform to hide (common mobile pattern)
  // The sidebar uses translateX(-100%) when hidden, which becomes matrix(1, 0, 0, 1, -width, 0)
  // Parse matrix to specifically detect significant negative horizontal translation
  const transform = await sidebar.evaluate((el) => window.getComputedStyle(el).transform);
  let isTransformedOffScreen = false;
  if (transform && transform !== "none") {
    // Parse matrix(a, b, c, d, tx, ty) - tx is the horizontal translation (5th value)
    const matrixMatch = transform.match(
      /matrix\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)/
    );
    if (matrixMatch) {
      const tx = parseFloat(matrixMatch[5]);
      // Significant negative X translation indicates off-screen to the left
      isTransformedOffScreen = tx < -10;
    }
  }

  // Element is considered hidden if:
  // - boundingBox is null (not rendered)
  // - width or height is 0 (zero dimensions)
  // - positioned completely off-screen via position
  // - transformed off-screen via CSS transform
  return (
    boundingBox === null ||
    boundingBox.width === 0 ||
    boundingBox.height === 0 ||
    boundingBox.x + boundingBox.width <= 0 ||
    (viewport !== null && boundingBox.x >= viewport.width) ||
    boundingBox.y + boundingBox.height <= 0 ||
    (viewport !== null && boundingBox.y >= viewport.height) ||
    isTransformedOffScreen
  );
}

test.describe("Sidebar - Desktop", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/mysql/intro");
  });

  test("should display sidebar on content pages", async ({ page }) => {
    const sidebar = page.locator(".sidebar");
    await expect(sidebar).toBeVisible();
  });

  test("should show sidebar sections with headings", async ({ page }) => {
    const sidebarHeadings = page.locator(".sidebar-heading");
    const count = await sidebarHeadings.count();
    expect(count).toBeGreaterThan(0);
  });

  test("should toggle section when heading is clicked", async ({ page }) => {
    const firstSection = page.locator(".sidebar-section").first();
    const firstHeading = firstSection.locator(".sidebar-heading");

    // Get initial state
    const initiallyActive = await firstSection.evaluate((el) => el.classList.contains("active"));

    // Click to toggle
    await firstHeading.click();

    // Check state changed
    const afterClickActive = await firstSection.evaluate((el) => el.classList.contains("active"));
    expect(afterClickActive).toBe(!initiallyActive);
  });

  test("should update aria-expanded when section is toggled", async ({ page }) => {
    const firstSection = page.locator(".sidebar-section").first();
    const firstHeading = firstSection.locator(".sidebar-heading");

    // Get initial aria-expanded
    const initialExpanded = await firstHeading.getAttribute("aria-expanded");

    // Click to toggle
    await firstHeading.click();

    // Check aria-expanded changed
    const afterClickExpanded = await firstHeading.getAttribute("aria-expanded");
    expect(afterClickExpanded).not.toBe(initialExpanded);
  });

  test("should navigate to correct page when sidebar link is clicked", async ({ page }) => {
    // NOTE: Skip decision requires runtime evaluation because link availability depends on page content.
    // Per Playwright docs, conditional skipping inside test body is valid for runtime conditions.

    const currentUrl = page.url();
    const currentPathname = new URL(currentUrl).pathname.replace(/\/$/, "");
    const sidebarLinks = page.locator(".sidebar-nav a");
    const count = await sidebarLinks.count();

    // Early skip check: if no sidebar links exist at all, skip immediately
    if (count === 0) {
      test.skip(true, "No sidebar links found - cannot test navigation");
      return;
    }

    // Helper to normalize pathname (remove trailing slash for comparison)
    const normalizePath = (path: string): string => path.replace(/\/$/, "");

    // Find a link that points to a different page by comparing normalized pathnames
    let targetLink = null;
    let targetHref = "";
    for (let i = 0; i < count; i++) {
      const link = sidebarLinks.nth(i);
      const href = await link.getAttribute("href");

      // Skip null hrefs and external/non-relative links
      if (
        !href ||
        href.startsWith("http://") ||
        href.startsWith("https://") ||
        href.startsWith("//")
      ) {
        continue;
      }

      // Resolve the href to a full pathname using the current URL as base
      const resolvedPathname = normalizePath(new URL(href, currentUrl).pathname);

      // Select this link only if the normalized pathnames differ
      if (resolvedPathname !== currentPathname) {
        targetLink = link;
        targetHref = href;
        break;
      }
    }

    // Skip test if no different link found - cannot verify navigation to same page
    if (!targetLink) {
      test.skip(true, "No sidebar link to a different page found - cannot test navigation");
      return;
    }

    // Click and wait for navigation
    await targetLink.click();
    await page.waitForURL((url) => url.href !== currentUrl, { timeout: 5000 });

    // Get the expected pathname from the clicked link's href
    // Ensure it begins with a leading slash for proper comparison
    const expectedPathname = normalizePath(new URL(targetHref, currentUrl).pathname);

    // Get the actual pathname from the navigated URL
    const actualPathname = normalizePath(new URL(page.url()).pathname);

    // Assert exact pathname match (allowing for optional trailing slash)
    expect(actualPathname).toBe(expectedPathname);
  });

  test("should highlight current page in sidebar", async ({ page }) => {
    // Look for active/current link indicator
    const activeLink = page.locator('.sidebar-nav a[aria-current="page"], .sidebar-nav a.active');
    const count = await activeLink.count();

    // Active link indicator must exist on content pages - fail if missing
    expect(count).toBeGreaterThan(0);

    // Verify the active link is visible
    await expect(activeLink.first()).toBeVisible();
  });
});

test.describe("Sidebar - Search", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/mysql/intro");
  });

  test("should display sidebar search input", async ({ page }) => {
    const searchInput = page.locator("#sidebar-search-input");
    await expect(searchInput).toBeVisible();
  });

  test("should filter sidebar items when searching", async ({ page }) => {
    const searchInput = page.locator("#sidebar-search-input");
    await searchInput.fill("Intro");

    // Wait for filtering - use state-based wait for matching links to become visible
    const matchingLinks = page.locator('.sidebar-nav a:has-text("Intro")');
    await expect(matchingLinks.first()).toBeVisible();
  });

  test("should show all items when search is cleared", async ({ page }) => {
    const searchInput = page.locator("#sidebar-search-input");
    const sidebarLinks = page.locator(".sidebar-nav a");

    // Capture the initial link count before filtering
    await expect(sidebarLinks.first()).toBeVisible();
    const initialCount = await sidebarLinks.count();

    // First filter - use "Password" which appears in entry titles like "Password Cracking"
    await searchInput.fill("Password");
    // Wait for filtering to complete by checking a specific filtered result
    const passwordLinks = page.locator('.sidebar-nav a:has-text("Password")');
    await expect(passwordLinks.first()).toBeVisible();

    // Then clear
    await searchInput.fill("");

    // All items should be visible again - wait for sidebar to have multiple links
    await expect(sidebarLinks.first()).toBeVisible();
    const restoredCount = await sidebarLinks.count();
    // Expect restored count to be at least the initial count (all sections restored)
    expect(restoredCount).toBeGreaterThanOrEqual(initialCount);
  });

  test("should expand all sections during search", async ({ page }) => {
    const searchInput = page.locator("#sidebar-search-input");

    // Collapse all active sections first using a stable approach:
    // Keep clicking the first active heading until none remain
    const activeHeadings = page.locator(".sidebar-section.active .sidebar-heading");
    let collapseAttempts = 0;
    while ((await activeHeadings.count()) > 0) {
      if (collapseAttempts >= MAX_COLLAPSE_ATTEMPTS) {
        throw new Error(
          `Failed to collapse all sidebar sections after ${MAX_COLLAPSE_ATTEMPTS} attempts. ` +
            `${await activeHeadings.count()} sections still active.`
        );
      }
      const previousCount = await activeHeadings.count();
      await activeHeadings.first().click();
      // Wait for count to decrease using state-based assertion instead of fixed timeout
      await expect
        .poll(async () => activeHeadings.count(), { timeout: 2000 })
        .toBeLessThan(previousCount);
      collapseAttempts++;
    }

    // Now search
    await searchInput.fill("test");

    // Wait for sections to expand - use state-based wait for first section to be active
    const allSections = page.locator(".sidebar-section");
    await expect(allSections.first()).toHaveClass(/active/);

    // Verify all sections are expanded
    const allCount = await allSections.count();
    for (let i = 0; i < allCount; i++) {
      const section = allSections.nth(i);
      await expect(section).toHaveClass(/active/);
    }
  });
});

test.describe("Sidebar - Keyboard Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/mysql/intro");
  });

  test("should toggle section with Enter key", async ({ page }) => {
    const firstSection = page.locator(".sidebar-section").first();
    const firstHeading = firstSection.locator(".sidebar-heading");

    // Get initial state
    const initiallyActive = await firstSection.evaluate((el) => el.classList.contains("active"));

    // Focus and press Enter
    await firstHeading.focus();
    await page.keyboard.press("Enter");

    // Check state changed
    const afterKeyActive = await firstSection.evaluate((el) => el.classList.contains("active"));
    expect(afterKeyActive).toBe(!initiallyActive);
  });

  test("should toggle section with Space key", async ({ page }) => {
    const firstSection = page.locator(".sidebar-section").first();
    const firstHeading = firstSection.locator(".sidebar-heading");

    // Get initial state
    const initiallyActive = await firstSection.evaluate((el) => el.classList.contains("active"));

    // Focus and press Space
    await firstHeading.focus();
    await page.keyboard.press("Space");

    // Check state changed
    const afterKeyActive = await firstSection.evaluate((el) => el.classList.contains("active"));
    expect(afterKeyActive).toBe(!initiallyActive);
  });
});

test.describe("Sidebar - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/mysql/intro");
  });

  test("should be hidden on mobile by default", async ({ page }) => {
    const sidebar = page.locator(".sidebar");
    const viewport = page.viewportSize();

    // Use helper to check if sidebar is hidden on mobile
    const isHiddenOnMobile = await isSidebarHiddenOnMobile(sidebar, viewport);
    expect(isHiddenOnMobile).toBe(true);
  });
});
