import { test, expect } from "@playwright/test";

test.describe("Navbar - Desktop", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should display single 'Databases' dropdown instead of individual database menus", async ({
    page,
  }) => {
    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await expect(databasesButton).toBeVisible();

    const mysqlButton = page.locator('button.dropdown-toggle:has-text("MySQL")');
    await expect(mysqlButton).not.toBeVisible();

    const mariadbButton = page.locator('button.dropdown-toggle:has-text("MariaDB")');
    await expect(mariadbButton).not.toBeVisible();
  });

  test("should show all database sections when Databases dropdown is opened", async ({ page }) => {
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    await expect(page.locator('.database-section-header:has-text("MySQL")')).toBeVisible();
    await expect(page.locator('.database-section-header:has-text("MariaDB")')).toBeVisible();
    await expect(page.locator('.database-section-header:has-text("MSSQL")')).toBeVisible();
    await expect(page.locator('.database-section-header:has-text("Oracle")')).toBeVisible();
    await expect(page.locator('.database-section-header:has-text("PostgreSQL")')).toBeVisible();
  });

  test("should have database sections collapsed by default", async ({ page }) => {
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const mysqlSection = page.locator('.database-section[data-database="mysql"]');
    await expect(mysqlSection).not.toHaveClass(/expanded/);

    const mysqlContent = mysqlSection.locator(".database-section-content");
    await expect(mysqlContent).toHaveCSS("max-height", "0px");
  });

  test("should expand database section when clicked", async ({ page }) => {
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")');
    await mysqlHeader.click();

    const mysqlSection = page.locator('.database-section[data-database="mysql"]');
    await expect(mysqlSection).toHaveClass(/expanded/);

    const basicsHeader = mysqlSection.locator('.dropdown-header:has-text("Basics")');
    await expect(basicsHeader).toBeVisible();
  });

  test("should navigate to correct page when clicking category link", async ({ page }) => {
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")');
    await mysqlHeader.click();

    // Wait for the database section to expand and show content
    const basicsLink = page
      .locator('.database-section[data-database="mysql"] .dropdown-list a:has-text("Intro")')
      .first();
    await expect(basicsLink).toBeVisible();
    await basicsLink.click();

    await expect(page).toHaveURL(/\/mysql\/intro/);
  });

  test("should display Extras dropdown separately", async ({ page }) => {
    const extrasButton = page.locator('button.dropdown-toggle:has-text("Extras")');
    await expect(extrasButton).toBeVisible();

    await page.hover('button.dropdown-toggle:has-text("Extras")');
    await expect(page.locator('.dropdown-item:has-text("About")')).toBeVisible();
  });

  test("should show search bar on desktop", async ({ page }) => {
    const searchInput = page.locator("#navbar-search-input");
    await expect(searchInput).toBeVisible();
  });

  test("should show GitHub link on desktop", async ({ page }) => {
    const githubLink = page.locator('a.github-link:has-text("GitHub")');
    await expect(githubLink).toBeVisible();
  });

  test("should show theme toggle on desktop", async ({ page }) => {
    const themeToggle = page.locator("#theme-toggle");
    await expect(themeToggle).toBeVisible();
  });

  test("chevron should rotate when database section is expanded", async ({ page }) => {
    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")');
    const chevron = mysqlHeader.locator(".database-chevron");

    const initialTransform = await chevron.evaluate((el) =>
      window.getComputedStyle(el).getPropertyValue("transform")
    );

    await mysqlHeader.click();
    // Wait for the section to expand (indicated by expanded class)
    const mysqlSection = page.locator('.database-section[data-database="mysql"]');
    await expect(mysqlSection).toHaveClass(/expanded/);

    const expandedTransform = await chevron.evaluate((el) =>
      window.getComputedStyle(el).getPropertyValue("transform")
    );

    expect(initialTransform).not.toBe(expandedTransform);
  });
});

test.describe("Navbar - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });
  });

  test("should show hamburger menu toggle on mobile", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await expect(mobileToggle).toBeVisible();
  });

  test("should hide mobile menu by default (off-screen)", async ({ page }) => {
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).not.toHaveClass(/active/);

    const transform = await navbarMenu.evaluate((el) =>
      window.getComputedStyle(el).getPropertyValue("transform")
    );

    expect(transform).toContain("matrix");
  });

  test("should open mobile menu when hamburger is clicked", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).toHaveClass(/active/);

    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await expect(databasesButton).toBeVisible();
  });

  test("should show search, GitHub, and theme toggle inside mobile menu", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).toHaveClass(/active/);

    const searchInput = navbarMenu.locator("#navbar-search-input");
    await expect(searchInput).toBeVisible();

    const githubLink = navbarMenu.locator('a.github-link:has-text("GitHub")');
    await expect(githubLink).toBeVisible();

    const themeToggle = navbarMenu.locator("#theme-toggle");
    await expect(themeToggle).toBeVisible();
  });

  test("should expand Databases dropdown in mobile menu", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    // Wait for mobile menu to become active
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).toHaveClass(/active/);

    const databasesDropdownItem = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdownItem.locator("button.dropdown-toggle");

    await expect(databasesButton).toBeVisible();
    await databasesButton.click();

    // Wait for dropdown menu to be visible
    const databasesMenu = databasesDropdownItem.locator(".dropdown-menu-databases");
    await expect(databasesMenu).toBeVisible();

    const mysqlHeader = databasesMenu.locator('.database-section-header:has-text("MySQL")').first();
    const mariadbHeader = databasesMenu
      .locator('.database-section-header:has-text("MariaDB")')
      .first();

    await expect(mysqlHeader).toBeVisible({ timeout: 5000 });
    await expect(mariadbHeader).toBeVisible();
  });

  test("should expand individual database sections in mobile menu", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    // Wait for mobile menu to become active
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).toHaveClass(/active/);

    const databasesDropdownItem = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdownItem.locator("button.dropdown-toggle");

    await expect(databasesButton).toBeVisible();
    await databasesButton.click();

    // Wait for dropdown menu to be visible
    const databasesMenu = databasesDropdownItem.locator(".dropdown-menu-databases");
    await expect(databasesMenu).toBeVisible();

    const mysqlHeader = databasesMenu.locator('.database-section-header:has-text("MySQL")').first();

    await expect(mysqlHeader).toBeVisible({ timeout: 5000 });
    await mysqlHeader.click();

    // Wait for section to expand
    const mysqlSection = databasesMenu.locator('.database-section[data-database="mysql"]');
    await expect(mysqlSection).toHaveClass(/expanded/);

    const basicsHeader = mysqlSection.locator('.dropdown-header:has-text("Basics")').first();
    await expect(basicsHeader).toBeVisible();
  });
});

test.describe("Navbar - Tablet/Intermediate", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 1024, height: 768 });
  });

  test("should handle intermediate screen sizes without overflow", async ({ page }) => {
    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await expect(databasesButton).toBeVisible();

    const extrasButton = page.locator('button.dropdown-toggle:has-text("Extras")');
    await expect(extrasButton).toBeVisible();

    const boundingBox = await page.locator(".navbar").boundingBox();
    expect(boundingBox).not.toBeNull();
    if (boundingBox) {
      expect(boundingBox.width).toBeLessThanOrEqual(1024);
    }
  });
});

test.describe("Navbar - Scalability", () => {
  test("should maintain compact layout regardless of database count", async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 1920, height: 1080 });

    const navLinks = page.locator(".nav-links > .nav-item");
    const count = await navLinks.count();

    expect(count).toBeLessThanOrEqual(5);

    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await expect(databasesButton).toBeVisible();

    await page.hover('button.dropdown-toggle:has-text("Databases")');

    const databaseSections = page.locator(".database-section");
    const sectionCount = await databaseSections.count();

    expect(sectionCount).toBeGreaterThanOrEqual(5);
  });
});

test.describe("Navbar - Dropdown Switching", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 1920, height: 1080 });
  });

  test("should open Databases dropdown when clicked", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    await databasesButton.click();

    // Verify dropdown is open
    await expect(databasesDropdown).toHaveClass(/show/);
    await expect(page.locator('.database-section-header:has-text("MySQL")')).toBeVisible();
  });

  test("should open Extras dropdown when clicked", async ({ page }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    await extrasButton.click();

    // Verify dropdown is open
    await expect(extrasDropdown).toHaveClass(/show/);
    await expect(page.locator('.dropdown-item:has-text("About")')).toBeVisible();
  });

  test("should close Databases when clicking Extras", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    // Open Databases first
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click Extras - should close Databases and open Extras
    await extrasButton.click();

    await expect(extrasDropdown).toHaveClass(/show/);
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });

  test("should close Extras when clicking Databases", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    // Open Extras first
    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);

    // Click Databases - should close Extras and open Databases
    await databasesButton.click();

    await expect(databasesDropdown).toHaveClass(/show/);
    await expect(extrasDropdown).not.toHaveClass(/show/);
  });

  test("should consistently switch between dropdowns multiple times", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    // Cycle 1: Databases -> Extras
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(extrasDropdown).not.toHaveClass(/show/);

    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Cycle 2: Databases -> Extras
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(extrasDropdown).not.toHaveClass(/show/);

    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Cycle 3: Databases -> Extras
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(extrasDropdown).not.toHaveClass(/show/);

    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/, { timeout: 1000 });
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });

  test("should close dropdown when clicking outside", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    // Open Databases
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click outside (on body/main content area)
    await page.locator("body").click({ position: { x: 500, y: 500 } });

    // Dropdown should close
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });

  test("should keep dropdown open on repeated clicks (close via click outside)", async ({
    page,
  }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    // Click to open
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click again - should stay open (on desktop, clicking always ensures open)
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click outside to close
    await page.locator("body").click({ position: { x: 500, y: 500 } });
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });
});

test.describe("Navbar - Dropdown Switching on Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });
    // Open mobile menu first
    await page.locator("#mobile-toggle").click();
    await expect(page.locator("#navbar-menu")).toHaveClass(/active/);
  });

  test("should open Databases dropdown when clicked on mobile", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    await databasesButton.click();

    await expect(databasesDropdown).toHaveClass(/show/);
  });

  test("should switch between Databases and Extras on mobile", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    // Open Databases
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Switch to Extras
    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Switch back to Databases
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);
    await expect(extrasDropdown).not.toHaveClass(/show/);
  });
});
