import { test, expect } from "@playwright/test";

test.describe("Content Pages", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display content page with title", async ({ page }) => {
    await page.goto("/mysql/intro");

    const title = page.locator("h1");
    await expect(title).toBeVisible();
    await expect(title).toContainText("Intro");
  });

  test("should have proper heading hierarchy", async ({ page }) => {
    await page.goto("/mysql/intro");

    // Page should have exactly one h1
    const h1Count = await page.locator("h1").count();
    expect(h1Count).toBe(1);
  });

  test("should display main content area", async ({ page }) => {
    await page.goto("/mysql/intro");

    // Content pages should have main content area
    const main = page.locator("#main-content");
    await expect(main).toBeVisible();
  });

  test("should have code blocks with proper formatting", async ({ page }) => {
    await page.goto("/mysql/union-based");

    const codeBlocks = page.locator("pre code, .code-block");
    const count = await codeBlocks.count();

    if (count > 0) {
      await expect(codeBlocks.first()).toBeVisible();
    }
  });

  test("should have working internal links", async ({ page }) => {
    await page.goto("/mysql/intro");

    // Find first internal link
    const internalLinks = page.locator('#main-content a[href^="/mysql/"]');
    const exists = await internalLinks.count();

    if (exists > 0) {
      const internalLink = internalLinks.first();
      await internalLink.scrollIntoViewIfNeeded();
      await expect(internalLink).toBeVisible();
      const href = await internalLink.getAttribute("href");
      expect(href).not.toBeNull();
      await internalLink.click();
      const escapedHref = href!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      await expect(page).toHaveURL(new RegExp(escapedHref));
    }
  });
});

test.describe("Code Tabs", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display tab container on pages with code examples", async ({ page }) => {
    // Navigate to a page with code examples
    await page.goto("/mysql/union-based");

    const tabContainers = page.locator(".tab-container, .code-tabs");
    const count = await tabContainers.count();

    // If tabs exist, they should be functional
    if (count > 0) {
      await expect(tabContainers.first()).toBeVisible();
    }
  });

  test("should switch content when tab is clicked", async ({ page }) => {
    await page.goto("/mysql/union-based");

    const tabs = page.locator(".tab-button, [role='tab']");
    const count = await tabs.count();

    if (count > 1) {
      // Get first tab content
      const firstTab = tabs.first();
      await expect(firstTab).toBeVisible();

      // Click second tab
      const secondTab = tabs.nth(1);
      await secondTab.click();

      // Second tab should now be active
      await expect(secondTab).toHaveAttribute("aria-selected", "true");
    }
  });
});

test.describe("Collection Pages", () => {
  test("should navigate to MySQL content", async ({ page }) => {
    // Collection URLs may redirect to first entry
    await page.goto("/mysql/intro");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to MariaDB content", async ({ page }) => {
    await page.goto("/mariadb/intro");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to MSSQL content", async ({ page }) => {
    await page.goto("/mssql/intro");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to Oracle content", async ({ page }) => {
    await page.goto("/oracle/intro");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to PostgreSQL content", async ({ page }) => {
    await page.goto("/postgresql/intro");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should have sidebar with entries on content pages", async ({ page }) => {
    await page.goto("/mysql/intro");

    const sidebarLinks = page.locator(".sidebar-nav a");
    const count = await sidebarLinks.count();
    expect(count).toBeGreaterThan(0);
  });
});

test.describe("Home Page", () => {
  test("should display home page with proper structure", async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");

    const navbar = page.locator(".navbar, nav");
    await expect(navbar).toBeVisible();
  });

  test("should have working navigation to collections", async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");

    // Open Databases dropdown and navigate
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")');
    await mysqlHeader.click();

    // Wait for the database section to expand and show content
    const introLink = page
      .locator('.database-section[data-database="mysql"] .dropdown-list a:has-text("Intro")')
      .first();
    await expect(introLink).toBeVisible();
    await introLink.click();

    await expect(page).toHaveURL(/\/mysql\/intro/);
  });
});

test.describe("Navigation", () => {
  test("should navigate between pages using sidebar", async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/mysql/intro");

    // Find and click a sidebar link
    const sidebarLink = page.locator(".sidebar-nav a").nth(1);
    const linkCount = await sidebarLink.count();

    if (linkCount > 0) {
      await sidebarLink.click();
      // Should navigate without errors
      await expect(page.locator("h1")).toBeVisible();
    }
  });
});
