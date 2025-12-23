import { test, expect, type Page } from "@playwright/test";

/** Maximum expected gap in pixels between adjacent navbar elements */
const MAX_EXPECTED_GAP_PX = 100;

/**
 * Clicks outside the navbar to close any open dropdowns.
 * Tries main content area first, falls back to body click below navbar.
 */
async function clickOutsideNavbar(page: Page): Promise<void> {
  const mainContent = page.locator("main").first();
  if ((await mainContent.count()) > 0) {
    await mainContent.click({ force: true });
  } else {
    // Fallback: click on body at a position below the navbar
    const navbar = page.locator(".navbar");
    const navbarBounds = await navbar.boundingBox();
    const clickY = navbarBounds ? navbarBounds.y + navbarBounds.height + 100 : 300;
    await page.locator("body").click({ position: { x: 100, y: clickY } });
  }
}

test.describe("Navbar - Desktop", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");
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

    await expect
      .poll(
        async () =>
          chevron.evaluate((el) => window.getComputedStyle(el).getPropertyValue("transform")),
        { timeout: 2000 }
      )
      .not.toBe(initialTransform);
  });
});

test.describe("Navbar - Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
  });

  test("should show hamburger menu toggle on mobile", async ({ page }) => {
    const mobileToggle = page.locator("#mobile-toggle");
    await expect(mobileToggle).toBeVisible();
  });

  test("should hide mobile menu by default (off-screen)", async ({ page }) => {
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).not.toHaveClass(/active/);

    // Verify menu is positioned off-screen by checking its bounding box
    const viewportWidth = page.viewportSize()?.width ?? 375;
    const menuBounds = await navbarMenu.evaluate((el) => {
      const rect = el.getBoundingClientRect();
      return { right: rect.right, left: rect.left, width: rect.width };
    });

    // Menu should be off-screen to the right (left edge >= viewport width)
    // or have a negative translateX pushing it off-screen
    expect(menuBounds.left).toBeGreaterThanOrEqual(viewportWidth);
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
    await page.setViewportSize({ width: 1024, height: 768 });
    await page.goto("/");
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
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");

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
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/");
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

    // Test 2 complete cycles of switching between Databases and Extras dropdowns
    // (reduced from 3 to improve CI runtime while maintaining coverage)
    for (let i = 0; i < 2; i++) {
      // Click Databases - should open Databases and close Extras
      await databasesButton.click();
      await expect(databasesDropdown).toHaveClass(/show/, { timeout: 2000 });
      await expect(extrasDropdown).not.toHaveClass(/show/);

      // Click Extras - should open Extras and close Databases
      await extrasButton.click();
      await expect(extrasDropdown).toHaveClass(/show/, { timeout: 2000 });
      await expect(databasesDropdown).not.toHaveClass(/show/);
    }
  });

  test("should close dropdown when clicking outside", async ({ page }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    // Open Databases
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click outside to close dropdown
    await clickOutsideNavbar(page);
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });

  test("should toggle dropdown on repeated clicks and close via click outside", async ({
    page,
  }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    // Click to open
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click again - should toggle closed (aria-expanded allows toggle behavior)
    await databasesButton.click();
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Click to re-open
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Click outside to close
    await clickOutsideNavbar(page);
    await expect(databasesDropdown).not.toHaveClass(/show/);
  });
});

test.describe("Navbar - Dropdown Switching on Mobile", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
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

test.describe("Navbar - Resize Transitions", () => {
  test("should keep Databases dropdown working after mobile toggle and resize to desktop", async ({
    page,
  }, _testInfo) => {
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });

    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    await databasesButton.click();
    await expect(databasesDropdown).not.toHaveClass(/show/);

    await page.setViewportSize({ width: 1280, height: 800 });

    // Wait for layout to stabilize after viewport resize using state-based assertions
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).not.toHaveClass(/active/, { timeout: 2000 });
    await expect(databasesButton).toBeVisible({ timeout: 2000 });

    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);
    await expect(page.locator('.database-section-header:has-text("MySQL")')).toBeVisible();

    // Only capture screenshots when PLAYWRIGHT_DEBUG is enabled to avoid CI slowdown
    if (process.env.PLAYWRIGHT_DEBUG) {
      await page.screenshot({
        path: _testInfo.outputPath("resize-databases-desktop.png"),
        fullPage: true,
      });
    }
  });

  test("should keep Extras dropdown working after mobile toggle and resize to desktop", async ({
    page,
  }, _testInfo) => {
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });

    const mobileToggle = page.locator("#mobile-toggle");
    await mobileToggle.click();

    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");

    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);

    await extrasButton.click();
    await expect(extrasDropdown).not.toHaveClass(/show/);

    await page.setViewportSize({ width: 1280, height: 800 });

    // Wait for layout to stabilize after viewport resize using state-based assertions
    const navbarMenu = page.locator("#navbar-menu");
    await expect(navbarMenu).not.toHaveClass(/active/, { timeout: 2000 });
    await expect(extrasButton).toBeVisible({ timeout: 2000 });

    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);
    await expect(page.locator('.dropdown-item:has-text("About")')).toBeVisible();

    // Only capture screenshots when PLAYWRIGHT_DEBUG is enabled to avoid CI slowdown
    if (process.env.PLAYWRIGHT_DEBUG) {
      await page.screenshot({
        path: _testInfo.outputPath("resize-extras-desktop.png"),
        fullPage: true,
      });
    }
  });

  test("should not have menu-transitioning class when resizing from desktop to mobile", async ({
    page,
  }) => {
    // Start at desktop width
    await page.goto("/");
    await page.setViewportSize({ width: 1280, height: 800 });

    const navbarMenu = page.locator("#navbar-menu");

    // Verify menu doesn't have transitioning class on desktop
    await expect(navbarMenu).not.toHaveClass(/menu-transitioning/);

    // Resize to mobile - this should NOT add the transitioning class
    // (transitioning class is only added on user click, not on resize)
    await page.setViewportSize({ width: 375, height: 667 });

    // Verify menu doesn't have transitioning class after resize
    // Use state-based assertion instead of fixed timeout
    await expect(navbarMenu).not.toHaveClass(/menu-transitioning/);

    // Verify menu is not active (closed state)
    await expect(navbarMenu).not.toHaveClass(/active/);

    // Verify the menu has translateX(100%) applied (hidden off-screen)
    // This confirms no transition occurred - the transform is immediately applied
    const transform = await navbarMenu.evaluate((el) => window.getComputedStyle(el).transform);

    // Ensure transform is not "none" (which would mean no positioning)
    expect(transform).not.toBe("none");

    // CSS transform: translateX(100%) on a 375px wide element = matrix(1, 0, 0, 1, 375, 0)
    // CSS matrix format: matrix(a, b, c, d, tx, ty) where:
    //   a, b, c, d = scale/rotation values (identity: 1, 0, 0, 1)
    //   tx = horizontal translation (x offset) - captured in group 5
    //   ty = vertical translation (y offset) - captured in group 6
    // We assert tx > 0 to confirm menu is positioned off-screen to the right
    const matrixMatch = transform.match(
      /matrix\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)/
    );
    expect(matrixMatch).not.toBeNull();
    if (matrixMatch) {
      const tx = parseFloat(matrixMatch[5]);
      // Positive X translation indicates menu is positioned off-screen to the right
      expect(tx).toBeGreaterThan(0);
    }
  });

  test("should have menu-transitioning class only during user-initiated menu toggle", async ({
    page,
  }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });

    const navbarMenu = page.locator("#navbar-menu");
    const mobileToggle = page.locator("#mobile-toggle");

    // Initially, no transitioning class
    await expect(navbarMenu).not.toHaveClass(/menu-transitioning/);

    // Click hamburger to open menu
    await mobileToggle.click();

    // During or immediately after click, the transitioning class should be present
    // (it gets removed after transition completes, so we check for the active class instead
    // which confirms the toggle worked)
    await expect(navbarMenu).toHaveClass(/active/);

    // Wait for transitioning class to be removed after CSS transition completes
    // Using poll instead of fixed timeout for more robust testing
    await expect
      .poll(
        async () => {
          const classes = await navbarMenu.getAttribute("class");
          return !classes?.includes("menu-transitioning");
        },
        { timeout: 1000 }
      )
      .toBe(true);

    // Verify menu is still active after transition
    await expect(navbarMenu).toHaveClass(/active/);

    // Close the menu
    await mobileToggle.click();
    await expect(navbarMenu).not.toHaveClass(/active/);

    // Wait for transitioning class to be removed after close transition
    await expect
      .poll(
        async () => {
          const classes = await navbarMenu.getAttribute("class");
          return !classes?.includes("menu-transitioning");
        },
        { timeout: 1000 }
      )
      .toBe(true);
  });

  test("should not have dropdown-transitioning class when resizing from mobile to desktop", async ({
    page,
  }) => {
    // Start at mobile width
    await page.goto("/");
    await page.setViewportSize({ width: 375, height: 667 });

    // Open mobile menu and expand Databases dropdown
    await page.locator("#mobile-toggle").click();
    await expect(page.locator("#navbar-menu")).toHaveClass(/active/);

    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    await databasesDropdown.locator(".dropdown-toggle").click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Verify dropdown doesn't have transitioning class on mobile
    await expect(databasesDropdown).not.toHaveClass(/dropdown-transitioning/);

    // Resize to desktop - this should NOT cause any visible flash
    await page.setViewportSize({ width: 1280, height: 800 });

    // Verify dropdown doesn't have transitioning class after resize
    // Use state-based assertion instead of fixed timeout
    await expect(databasesDropdown).not.toHaveClass(/dropdown-transitioning/);

    // Verify dropdown is not shown (closed state on desktop)
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Verify the dropdown menu is hidden (no flash)
    const dropdownMenu = databasesDropdown.locator(".dropdown-menu");
    const visibility = await dropdownMenu.evaluate((el) => window.getComputedStyle(el).visibility);
    expect(visibility).toBe("hidden");
  });

  test("should show dropdown smoothly on hover without transitioning class getting stuck", async ({
    page,
  }) => {
    await page.goto("/");
    await page.setViewportSize({ width: 1280, height: 800 });

    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');

    // Initially, no transitioning class and no show class
    await expect(databasesDropdown).not.toHaveClass(/dropdown-transitioning/);
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Hover over dropdown to trigger transition
    await databasesDropdown.hover();

    // Dropdown should show after hover
    await expect(databasesDropdown).toHaveClass(/show/);

    // Move mouse away
    await page.locator(".navbar-logo").hover();

    // Wait for transition to complete using poll instead of fixed timeout
    await expect
      .poll(
        async () => {
          const classes = await databasesDropdown.getAttribute("class");
          return !classes?.includes("dropdown-transitioning") && !classes?.includes("show");
        },
        { timeout: 1000 }
      )
      .toBe(true);

    // Verify both classes are removed after transition
    await expect(databasesDropdown).not.toHaveClass(/dropdown-transitioning/);
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Verify dropdown is actually hidden (the main goal of the fix)
    const dropdownMenu = databasesDropdown.locator(".dropdown-menu");
    const visibility = await dropdownMenu.evaluate((el) => window.getComputedStyle(el).visibility);
    expect(visibility).toBe("hidden");
  });
});

test.describe("Navbar - Mobile Menu Visual Integrity", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
    // Open mobile menu first
    await page.locator("#mobile-toggle").click();
    await expect(page.locator("#navbar-menu")).toHaveClass(/active/);
  });

  test("should hide database items when Databases dropdown is initially collapsed", async ({
    page,
  }) => {
    // The Databases dropdown should NOT be expanded initially
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // The dropdown menu should have overflow:hidden and max-height:0 when collapsed
    const databasesMenu = databasesDropdown.locator(".dropdown-menu-databases");
    const menuStyles = await databasesMenu.evaluate((el) => {
      const computed = window.getComputedStyle(el);
      return {
        maxHeight: computed.maxHeight,
        overflow: computed.overflow,
      };
    });
    expect(menuStyles.maxHeight).toBe("0px");
    expect(menuStyles.overflow).toBe("hidden");

    // The Extras button should be visible and properly positioned (not overlapped)
    const extrasButton = page.locator('button.dropdown-toggle:has-text("Extras")');
    await expect(extrasButton).toBeVisible();

    // Get positions to verify no overlap - Extras should be directly below Databases
    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    const databasesBox = await databasesButton.boundingBox();
    const extrasBox = await extrasButton.boundingBox();

    expect(databasesBox).not.toBeNull();
    expect(extrasBox).not.toBeNull();
    if (databasesBox && extrasBox) {
      // Extras should be right below Databases button (with some small gap)
      // Not hundreds of pixels below (which would indicate database items showing through)
      const gap = extrasBox.y - (databasesBox.y + databasesBox.height);
      expect(gap).toBeLessThan(MAX_EXPECTED_GAP_PX); // Should be a small gap, not a huge one
      expect(gap).toBeGreaterThanOrEqual(0); // Should not overlap
    }
  });

  test("should not have Extras/GitHub elements overlapping database sections when dropdown is expanded", async ({
    page,
  }) => {
    // Open Databases dropdown
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Wait for dropdown animation to complete (max-height transition is 400ms)
    const databasesMenu = databasesDropdown.locator(".dropdown-menu-databases");
    await expect(databasesMenu).toBeVisible();
    // Wait for the dropdown to have expanded (height > 100px indicates it's expanded)
    await expect(async () => {
      const box = await databasesMenu.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.height).toBeGreaterThan(100);
    }).toPass({ timeout: 2000 });

    // Get the MySQL section header
    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")').first();
    await expect(mysqlHeader).toBeVisible();

    // Get the Extras button (should be below the database sections)
    const extrasButton = page.locator('button.dropdown-toggle:has-text("Extras")');
    await expect(extrasButton).toBeVisible();

    // Get bounding boxes
    const mysqlBox = await mysqlHeader.boundingBox();
    const extrasBox = await extrasButton.boundingBox();

    // Verify Extras button is positioned BELOW the MySQL header (no overlap)
    expect(mysqlBox).not.toBeNull();
    expect(extrasBox).not.toBeNull();
    if (mysqlBox && extrasBox) {
      // Extras should be below MySQL (extrasBox.y should be greater than mysqlBox.y + mysqlBox.height)
      expect(extrasBox.y).toBeGreaterThan(mysqlBox.y);
    }
  });

  test("should have database sections stacked correctly without overlap", async ({ page }) => {
    // Open Databases dropdown
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Get all database section headers
    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")').first();
    const mariadbHeader = page.locator('.database-section-header:has-text("MariaDB")').first();
    const mssqlHeader = page.locator('.database-section-header:has-text("MSSQL")').first();

    await expect(mysqlHeader).toBeVisible();
    await expect(mariadbHeader).toBeVisible();
    await expect(mssqlHeader).toBeVisible();

    // Get bounding boxes
    const mysqlBox = await mysqlHeader.boundingBox();
    const mariadbBox = await mariadbHeader.boundingBox();
    const mssqlBox = await mssqlHeader.boundingBox();

    // Verify proper vertical ordering (MySQL -> MariaDB -> MSSQL)
    expect(mysqlBox).not.toBeNull();
    expect(mariadbBox).not.toBeNull();
    expect(mssqlBox).not.toBeNull();
    if (mysqlBox && mariadbBox && mssqlBox) {
      expect(mariadbBox.y).toBeGreaterThan(mysqlBox.y);
      expect(mssqlBox.y).toBeGreaterThan(mariadbBox.y);
    }
  });

  test("should have mobile menu with proper z-index stacking", async ({ page }) => {
    // Open Databases dropdown
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Verify the navbar-menu has z-index set
    const navbarMenu = page.locator("#navbar-menu");
    const zIndex = await navbarMenu.evaluate((el) => window.getComputedStyle(el).zIndex);
    expect(parseInt(zIndex)).toBeGreaterThan(0);

    // Verify the dropdown.show has position relative for stacking context
    const position = await databasesDropdown.evaluate((el) => window.getComputedStyle(el).position);
    expect(position).toBe("relative");
  });

  test("should have visible and clickable database section headers when dropdown is expanded", async ({
    page,
  }) => {
    // Open Databases dropdown
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Try to click on MySQL header - should be clickable (not blocked by other elements)
    const mysqlHeader = page.locator('.database-section-header:has-text("MySQL")').first();
    await expect(mysqlHeader).toBeVisible();
    await mysqlHeader.click();

    // Verify section expanded (clicking worked, element wasn't blocked)
    const mysqlSection = page.locator('.database-section[data-database="mysql"]');
    await expect(mysqlSection).toHaveClass(/expanded/);
  });

  test("should hide Databases dropdown content when collapsed after being expanded", async ({
    page,
  }) => {
    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");
    const databasesMenu = databasesDropdown.locator(".dropdown-menu-databases");

    // Expand Databases dropdown
    await databasesButton.click();
    await expect(databasesDropdown).toHaveClass(/show/);

    // Wait for expansion animation
    await expect(async () => {
      const box = await databasesMenu.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.height).toBeGreaterThan(100);
    }).toPass({ timeout: 2000 });

    // Collapse Databases dropdown
    await databasesButton.click();
    await expect(databasesDropdown).not.toHaveClass(/show/);

    // Wait for collapse animation and verify content is hidden
    await expect(async () => {
      const styles = await databasesMenu.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return {
          maxHeight: computed.maxHeight,
          overflow: computed.overflow,
        };
      });
      expect(styles.maxHeight).toBe("0px");
      expect(styles.overflow).toBe("hidden");
    }).toPass({ timeout: 2000 });
  });
});

test.describe("Navbar - Mobile Extras Dropdown", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
    // Open mobile menu first
    await page.locator("#mobile-toggle").click();
    await expect(page.locator("#navbar-menu")).toHaveClass(/active/);
  });

  test("should hide Extras dropdown content when initially collapsed", async ({ page }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    await expect(extrasDropdown).not.toHaveClass(/show/);

    // The dropdown menu should have overflow:hidden and max-height:0 when collapsed
    const extrasMenu = extrasDropdown.locator(".dropdown-menu");
    const menuStyles = await extrasMenu.evaluate((el) => {
      const computed = window.getComputedStyle(el);
      return {
        maxHeight: computed.maxHeight,
        overflow: computed.overflow,
      };
    });
    expect(menuStyles.maxHeight).toBe("0px");
    expect(menuStyles.overflow).toBe("hidden");
  });

  test("should show Extras dropdown content when expanded", async ({ page }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");
    const extrasMenu = extrasDropdown.locator(".dropdown-menu");

    // Expand Extras dropdown
    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);

    // Wait for expansion and verify content is visible
    await expect(async () => {
      const styles = await extrasMenu.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return {
          maxHeight: computed.maxHeight,
          overflow: computed.overflow,
        };
      });
      // maxHeight should be a large value (5000px) when expanded
      expect(parseInt(styles.maxHeight)).toBeGreaterThan(100);
      expect(styles.overflow).toBe("visible");
    }).toPass({ timeout: 2000 });

    // Verify About link is visible
    const aboutLink = extrasMenu.locator('.dropdown-item:has-text("About")');
    await expect(aboutLink).toBeVisible();
  });

  test("should hide Extras dropdown content when collapsed after being expanded", async ({
    page,
  }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");
    const extrasMenu = extrasDropdown.locator(".dropdown-menu");

    // Expand Extras dropdown
    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/);

    // Wait for expansion
    await expect(async () => {
      const styles = await extrasMenu.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return { overflow: computed.overflow };
      });
      expect(styles.overflow).toBe("visible");
    }).toPass({ timeout: 2000 });

    // Collapse Extras dropdown
    await extrasButton.click();
    await expect(extrasDropdown).not.toHaveClass(/show/);

    // Wait for collapse and verify content is hidden
    // This is the key test for the focus-within bug fix
    await expect(async () => {
      const styles = await extrasMenu.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return {
          maxHeight: computed.maxHeight,
          overflow: computed.overflow,
        };
      });
      expect(styles.maxHeight).toBe("0px");
      expect(styles.overflow).toBe("hidden");
    }).toPass({ timeout: 2000 });

    // Verify GitHub link is NOT visible (it should be below Extras and not affected by Extras content)
    // Get positions to verify no content leaking through
    const githubLink = page.locator('a.github-link:has-text("GitHub")');
    const extrasButtonBox = await extrasButton.boundingBox();
    const githubBox = await githubLink.boundingBox();

    expect(extrasButtonBox).not.toBeNull();
    expect(githubBox).not.toBeNull();
    if (extrasButtonBox && githubBox) {
      // GitHub should be close to Extras (not pushed down by visible dropdown content)
      const gap = githubBox.y - (extrasButtonBox.y + extrasButtonBox.height);
      expect(gap).toBeLessThan(MAX_EXPECTED_GAP_PX);
    }
  });

  test("should toggle Extras dropdown multiple times correctly", async ({ page }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");
    const extrasMenu = extrasDropdown.locator(".dropdown-menu");

    // Toggle 3 times to ensure consistent behavior
    for (let i = 0; i < 3; i++) {
      // Expand
      await extrasButton.click();
      await expect(extrasDropdown).toHaveClass(/show/);
      await expect(async () => {
        const styles = await extrasMenu.evaluate((el) => ({
          overflow: window.getComputedStyle(el).overflow,
        }));
        expect(styles.overflow).toBe("visible");
      }).toPass({ timeout: 2000 });

      // Collapse
      await extrasButton.click();
      await expect(extrasDropdown).not.toHaveClass(/show/);
      await expect(async () => {
        const styles = await extrasMenu.evaluate((el) => ({
          overflow: window.getComputedStyle(el).overflow,
        }));
        expect(styles.overflow).toBe("hidden");
      }).toPass({ timeout: 2000 });
    }
  });

  test("should not have Extras dropdown content overlapping GitHub link when collapsed", async ({
    page,
  }) => {
    const extrasDropdown = page.locator('.nav-item.dropdown:has(button:text("Extras"))');
    const extrasButton = extrasDropdown.locator("button.dropdown-toggle");
    const githubLink = page.locator('a.github-link:has-text("GitHub")');

    // Initially collapsed - GitHub should be positioned right after Extras button
    const extrasButtonBox = await extrasButton.boundingBox();
    const githubBoxInitial = await githubLink.boundingBox();

    expect(extrasButtonBox).not.toBeNull();
    expect(githubBoxInitial).not.toBeNull();

    // Expand Extras
    await extrasButton.click();
    await expect(extrasDropdown).toHaveClass(/show/, { timeout: 2000 });

    // Collapse Extras
    await extrasButton.click();
    await expect(extrasDropdown).not.toHaveClass(/show/, { timeout: 2000 });

    // Wait for GitHub button position to stabilize after collapse animation
    // Using expect.poll to wait until position is stable (within tolerance of initial position)
    await expect
      .poll(
        async () => {
          const currentBox = await githubLink.boundingBox();
          if (!currentBox || !githubBoxInitial) return false;
          return Math.abs(currentBox.y - githubBoxInitial.y) < 25;
        },
        { timeout: 2000, message: "GitHub button should return to approximately initial position" }
      )
      .toBe(true);
  });
});
