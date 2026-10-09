import { test, expect, type Page } from "@playwright/test";

/** Assert navigation reached href, allowing the server's trailing-slash redirect */
async function expectNavigatedTo(page: Page, href: string): Promise<void> {
  const pathname = new URL(href, page.url()).pathname.replace(/\/$/, "");
  const escaped = pathname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  await expect(page).toHaveURL(new RegExp(`${escaped}/?$`));
}

test.describe("Content Pages", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display content page with title", async ({ page }) => {
    await page.goto("mysql/intro/");

    const title = page.locator("h1");
    await expect(title).toBeVisible();
    await expect(title).toContainText("Intro");
  });

  test("should have proper heading hierarchy", async ({ page }) => {
    await page.goto("mysql/intro/");

    // Page should have exactly one h1
    const h1Count = await page.locator("h1").count();
    expect(h1Count).toBe(1);
  });

  test("should display main content area", async ({ page }) => {
    await page.goto("mysql/intro/");

    // Content pages should have main content area
    const main = page.locator("#main-content");
    await expect(main).toBeVisible();
  });

  test("should have code blocks with proper formatting", async ({ page }) => {
    await page.goto("mysql/stacked-queries/");

    const codeBlocks = page.locator("#main-content pre code");
    await expect(codeBlocks.first()).toBeVisible();
  });

  test("should have working internal links", async ({ page, baseURL }) => {
    await page.goto("mysql/intro/");

    // Markdown links are prefixed with the site base path at build time
    const basePath = new URL(baseURL ?? "http://localhost/").pathname;
    const internalLink = page.locator(`#main-content article a[href^="${basePath}mysql/"]`).first();

    await internalLink.scrollIntoViewIfNeeded();
    await expect(internalLink).toBeVisible();
    const href = await internalLink.getAttribute("href");
    expect(href).toBeTruthy();

    await internalLink.click();
    await expectNavigatedTo(page, href!);
    await expect(page.locator("h1")).toBeVisible();
    await expect(page.locator("#main-content")).toBeVisible();
  });
});

test.describe("Home Page Tabs", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  // The home page groups entries by database in a tab list
  test("should display the database tab list on the home page", async ({ page }) => {
    await page.goto("./");

    const tabList = page.locator(".tab-list[role='tablist']").first();
    await expect(tabList).toBeVisible();
    expect(await tabList.locator("[role='tab']").count()).toBeGreaterThan(1);
  });

  test("should switch content when tab is clicked", async ({ page }) => {
    await page.goto("./");

    const tabs = page.locator(".tab-list [role='tab']");
    await expect(tabs.first()).toBeVisible();

    const secondTab = tabs.nth(1);
    await secondTab.click();

    await expect(secondTab).toHaveAttribute("aria-selected", "true");
    await expect(tabs.first()).toHaveAttribute("aria-selected", "false");
  });
});

test.describe("Collection Pages", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should navigate to MySQL content", async ({ page }) => {
    // Collection URLs may redirect to first entry
    await page.goto("mysql/intro/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to MariaDB content", async ({ page }) => {
    await page.goto("mariadb/intro/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to MSSQL content", async ({ page }) => {
    await page.goto("mssql/intro/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to Oracle content", async ({ page }) => {
    await page.goto("oracle/intro/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should navigate to PostgreSQL content", async ({ page }) => {
    await page.goto("postgresql/intro/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();
  });

  test("should have sidebar with entries on content pages", async ({ page }) => {
    await page.goto("mysql/intro/");

    const sidebarLinks = page.locator(".sidebar-nav a");
    const count = await sidebarLinks.count();
    expect(count).toBeGreaterThan(0);
  });
});

test.describe("Home Page", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display home page with proper structure", async ({ page }) => {
    await page.goto("./");

    const navbar = page.locator(".navbar, nav");
    await expect(navbar).toBeVisible();
  });

  test("should have working navigation to collections", async ({ page }) => {
    await page.goto("./");

    // Open Databases dropdown and navigate
    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await databasesButton.hover();

    // Wait for dropdown to be visible after hover
    const dropdownMenu = page.locator(".dropdown-menu-databases");
    await expect(dropdownMenu).toBeVisible();

    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")');
    await expect(mysqlHeader).toBeVisible();
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
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should navigate between pages using sidebar", async ({ page }) => {
    await page.goto("mysql/intro/");

    const sidebarLinks = page.locator(".sidebar-nav a");
    expect(await sidebarLinks.count()).toBeGreaterThan(1);

    const target = sidebarLinks.nth(1);
    const href = await target.getAttribute("href");
    await target.click();

    await expectNavigatedTo(page, href!);
    await expect(page.locator("h1")).toBeVisible();
  });
});
