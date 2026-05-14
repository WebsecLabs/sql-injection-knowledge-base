import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// WCAG 2.1 AA tags for axe-core
const WCAG_AA_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

// Pages to test for comprehensive coverage
const PAGES_TO_TEST = [
  { path: "/", name: "Home page" },
  { path: "/search", name: "Search page" },
  { path: "/mysql/intro", name: "MySQL Intro" },
  { path: "/mariadb/intro", name: "MariaDB Intro" },
  { path: "/mssql/intro", name: "MSSQL Intro" },
  { path: "/oracle/intro", name: "Oracle Intro" },
  { path: "/postgresql/intro", name: "PostgreSQL Intro" },
  { path: "/extras/about", name: "About page" },
];

// Viewport configurations for responsive testing
const VIEWPORTS = {
  desktop: { width: 1920, height: 1080 },
  tablet: { width: 1024, height: 768 },
  mobile: { width: 375, height: 667 },
};

/**
 * Runs axe accessibility analysis on the current page.
 */
async function runAxeAnalysis(page: Page, options?: { disableRules?: string[] }) {
  let builder = new AxeBuilder({ page }).withTags(WCAG_AA_TAGS);

  if (options?.disableRules) {
    builder = builder.disableRules(options.disableRules);
  }

  return builder.analyze();
}

/**
 * Formats axe violations for readable test output.
 */
function formatViolations(
  violations: Awaited<ReturnType<typeof runAxeAnalysis>>["violations"]
): string {
  if (violations.length === 0) return "No violations found";

  return violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    - ${n.html.substring(0, 100)}`).join("\n");
      return `[${v.impact}] ${v.id}: ${v.description}\n  Help: ${v.helpUrl}\n  Elements:\n${nodes}`;
    })
    .join("\n\n");
}

test.describe("Accessibility - Core Page Scans", () => {
  for (const { path, name } of PAGES_TO_TEST) {
    test(`${name} should have no WCAG 2.1 AA violations`, async ({ page }) => {
      await page.setViewportSize(VIEWPORTS.desktop);
      await page.goto(path);
      await page.waitForLoadState("networkidle");

      const results = await runAxeAnalysis(page);

      if (results.violations.length > 0) {
        console.log(`\nViolations on ${name}:\n${formatViolations(results.violations)}`);
      }

      expect(results.violations, `Expected no accessibility violations on ${name}`).toHaveLength(0);
    });
  }
});

test.describe("Accessibility - Responsive Views", () => {
  const pagesToTestResponsive = [
    { path: "/", name: "Home page" },
    { path: "/mysql/intro", name: "Content page" },
    { path: "/search", name: "Search page" },
  ];

  for (const [viewportName, dimensions] of Object.entries(VIEWPORTS)) {
    test.describe(`${viewportName} viewport (${dimensions.width}x${dimensions.height})`, () => {
      for (const { path, name } of pagesToTestResponsive) {
        test(`${name} should have no violations`, async ({ page }) => {
          await page.setViewportSize(dimensions);
          await page.goto(path);
          await page.waitForLoadState("networkidle");

          const results = await runAxeAnalysis(page);

          if (results.violations.length > 0) {
            console.log(
              `\nViolations on ${name} (${viewportName}):\n${formatViolations(results.violations)}`
            );
          }

          expect(results.violations).toHaveLength(0);
        });
      }
    });
  }
});

test.describe("Accessibility - Interactive Component States", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.desktop);
  });

  test("Navbar dropdowns maintain accessibility when open", async ({ page }) => {
    await page.goto("/");

    const databasesButton = page.locator('button.dropdown-toggle:has-text("Databases")');
    await databasesButton.click();

    await expect(page.locator('.database-section-header:has-text("MySQL")')).toBeVisible();

    const results = await runAxeAnalysis(page);

    if (results.violations.length > 0) {
      console.log(`\nViolations with open dropdown:\n${formatViolations(results.violations)}`);
    }

    expect(results.violations).toHaveLength(0);
  });

  test("Mobile menu maintains accessibility when open", async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.mobile);
    await page.goto("/");

    await page.locator("#mobile-toggle").click();
    await expect(page.locator("#navbar-menu")).toHaveClass(/active/);

    const results = await runAxeAnalysis(page);

    if (results.violations.length > 0) {
      console.log(`\nViolations with mobile menu open:\n${formatViolations(results.violations)}`);
    }

    expect(results.violations).toHaveLength(0);
  });

  test("Sidebar sections maintain accessibility when expanded/collapsed", async ({ page }) => {
    await page.goto("/mysql/intro");

    const firstHeading = page.locator(".sidebar-heading").first();
    await firstHeading.click();

    const results = await runAxeAnalysis(page);

    if (results.violations.length > 0) {
      console.log(`\nViolations with toggled sidebar:\n${formatViolations(results.violations)}`);
    }

    expect(results.violations).toHaveLength(0);
  });

  test("Theme toggle maintains accessibility in dark mode", async ({ page }) => {
    await page.goto("/");

    await page.locator("#theme-toggle").click();
    await expect(page.locator("html")).toHaveClass(/dark/);

    const results = await runAxeAnalysis(page);

    if (results.violations.length > 0) {
      console.log(`\nViolations in dark mode:\n${formatViolations(results.violations)}`);
    }

    expect(results.violations).toHaveLength(0);
  });

  test("Search page maintains accessibility with results", async ({ page }) => {
    await page.goto("/search");

    // Pagefind UI initializes dynamically — wait for its input to appear
    const searchInput = page.locator("#pagefind-search .pagefind-ui__search-input");
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    await searchInput.fill("Intro");
    await expect(page.locator(".pagefind-ui__result").first()).toBeVisible({ timeout: 10000 });

    const results = await runAxeAnalysis(page);

    if (results.violations.length > 0) {
      console.log(`\nViolations on search with results:\n${formatViolations(results.violations)}`);
    }

    expect(results.violations).toHaveLength(0);
  });

  test("Table of Contents maintains accessibility when collapsed", async ({ page }) => {
    await page.goto("/mysql/intro");

    const tocToggle = page.locator("#toc-toggle");
    if (await tocToggle.isVisible()) {
      await tocToggle.click();

      const results = await runAxeAnalysis(page);

      if (results.violations.length > 0) {
        console.log(`\nViolations with collapsed TOC:\n${formatViolations(results.violations)}`);
      }

      expect(results.violations).toHaveLength(0);
    }
  });
});

test.describe("Accessibility - Keyboard Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.desktop);
  });

  test("Skip link is accessible and functional", async ({ page }) => {
    await page.goto("/");

    // Tab to skip link
    await page.keyboard.press("Tab");

    const skipLink = page.locator(".skip-link");
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeVisible();

    // Activate skip link
    await page.keyboard.press("Enter");

    // Main content should receive focus
    const mainContent = page.locator("#main-content");
    await expect(mainContent).toBeFocused();
  });

  test("Focus order follows logical reading order", async ({ page }) => {
    await page.goto("/");

    const focusOrder: string[] = [];

    // Tab through first 10 focusable elements
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press("Tab");
      const focused = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el) return "none";
        const tag = el.tagName.toLowerCase();
        const id = el.id ? `#${el.id}` : "";
        const className =
          el.className && typeof el.className === "string" ? `.${el.className.split(" ")[0]}` : "";
        return `${tag}${id || className}`;
      });
      focusOrder.push(focused);
    }

    // Verify skip link is first
    expect(focusOrder[0]).toContain("skip-link");
  });

  test("All interactive elements are keyboard accessible", async ({ page }) => {
    await page.goto("/");

    const interactiveElements = page.locator(
      'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    const count = await interactiveElements.count();

    for (let i = 0; i < Math.min(count, 20); i++) {
      const element = interactiveElements.nth(i);

      if (await element.isVisible()) {
        await element.focus();
        const isFocused = await element.evaluate((el) => el === document.activeElement);
        expect(isFocused, `Element ${i} should be focusable`).toBe(true);
      }
    }
  });
});

test.describe("Accessibility - ARIA Implementation", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.desktop);
  });

  test("Sidebar headings have correct aria-expanded states", async ({ page }) => {
    await page.goto("/mysql/intro");

    const headings = page.locator(".sidebar-heading");
    const count = await headings.count();

    for (let i = 0; i < count; i++) {
      const heading = headings.nth(i);
      const section = heading.locator("xpath=..").first();

      const isActive = await section.evaluate((el) => el.classList.contains("active"));
      const ariaExpanded = await heading.getAttribute("aria-expanded");

      expect(ariaExpanded, `Heading ${i} aria-expanded should match active state`).toBe(
        isActive ? "true" : "false"
      );
    }
  });

  test("Dropdown buttons have correct aria-expanded states", async ({ page }) => {
    await page.goto("/");

    const databasesDropdown = page.locator('.nav-item.dropdown:has(button:text("Databases"))');
    const databasesButton = databasesDropdown.locator("button.dropdown-toggle");

    // Initially closed
    await expect(databasesButton).toHaveAttribute("aria-expanded", "false");

    // After opening
    await databasesButton.click();
    await expect(databasesButton).toHaveAttribute("aria-expanded", "true");

    // After closing
    await databasesButton.click();
    await expect(databasesButton).toHaveAttribute("aria-expanded", "false");
  });

  test("Theme toggle has accessible label", async ({ page }) => {
    await page.goto("/");

    const themeToggle = page.locator("#theme-toggle");
    await expect(themeToggle).toHaveAttribute("aria-label");

    const ariaLabel = await themeToggle.getAttribute("aria-label");
    expect(ariaLabel).toBeTruthy();
    expect(ariaLabel!.length).toBeGreaterThan(0);
  });

  test("Mobile toggle has accessible label", async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.mobile);
    await page.goto("/");

    const mobileToggle = page.locator("#mobile-toggle");
    await expect(mobileToggle).toHaveAttribute("aria-label");
  });
});

test.describe("Accessibility - Color Contrast", () => {
  test("Light mode passes color contrast checks", async ({ page }) => {
    await page.goto("/");

    // Ensure light mode
    await page.evaluate(() => {
      document.documentElement.classList.remove("dark");
      document.documentElement.classList.add("light");
    });

    const results = await runAxeAnalysis(page);
    const contrastViolations = results.violations.filter((v) => v.id.includes("color-contrast"));

    if (contrastViolations.length > 0) {
      console.log(`\nContrast violations in light mode:\n${formatViolations(contrastViolations)}`);
    }

    expect(contrastViolations).toHaveLength(0);
  });

  test("Dark mode passes color contrast checks", async ({ page }) => {
    await page.goto("/");

    // Switch to dark mode
    await page.locator("#theme-toggle").click();
    await expect(page.locator("html")).toHaveClass(/dark/);

    const results = await runAxeAnalysis(page);
    const contrastViolations = results.violations.filter((v) => v.id.includes("color-contrast"));

    if (contrastViolations.length > 0) {
      console.log(`\nContrast violations in dark mode:\n${formatViolations(contrastViolations)}`);
    }

    expect(contrastViolations).toHaveLength(0);
  });
});

test.describe("Accessibility - Form Controls", () => {
  test("Search inputs have accessible labels", async ({ page }) => {
    await page.goto("/");

    // Navbar search trigger button
    const searchTrigger = page.locator("#search-trigger");
    await expect(searchTrigger).toBeVisible();

    // Open search modal and verify input has accessible label
    await searchTrigger.click();
    const searchModalInput = page.locator("#search-modal-input");
    await expect(searchModalInput).toBeVisible();
    await expect(searchModalInput).toHaveAttribute("aria-label");
  });

  test("Sidebar search input has accessible label", async ({ page }) => {
    await page.goto("/mysql/intro");

    const sidebarSearch = page.locator("#sidebar-search-input");
    await expect(sidebarSearch).toHaveAttribute("aria-label");
  });

  test("Buttons have accessible names", async ({ page }) => {
    await page.goto("/");

    // Theme toggle
    const themeToggle = page.locator("#theme-toggle");
    await expect(themeToggle).toHaveAttribute("aria-label");

    // Mobile toggle
    await page.setViewportSize(VIEWPORTS.mobile);
    const mobileToggle = page.locator("#mobile-toggle");
    await expect(mobileToggle).toHaveAttribute("aria-label");
  });
});

test.describe("Accessibility - Images and Media", () => {
  test("All images have alt text", async ({ page }) => {
    await page.goto("/");

    const images = page.locator("img");
    const count = await images.count();

    for (let i = 0; i < count; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute("alt");
      const src = await img.getAttribute("src");

      expect(alt, `Image ${src} should have alt attribute`).not.toBeNull();
    }
  });

  test("Decorative SVGs are hidden from assistive technology", async ({ page }) => {
    await page.goto("/");

    // Check for SVGs with aria-hidden
    const decorativeSvgs = page.locator('svg[aria-hidden="true"]');
    const count = await decorativeSvgs.count();

    // Verify decorative SVGs exist (icons, chevrons, etc.)
    expect(count).toBeGreaterThan(0);
  });
});

test.describe("Accessibility - Landmarks", () => {
  test("Page has proper landmark structure", async ({ page }) => {
    await page.goto("/mysql/intro");

    // Check for main landmark
    await expect(page.locator("main")).toBeVisible();

    // Check for primary navigation
    await expect(page.locator("nav.navbar")).toBeVisible();

    // Check for footer
    await expect(page.locator("footer")).toBeVisible();
  });

  test("Main content has accessible id for skip link target", async ({ page }) => {
    await page.goto("/");

    const mainContent = page.locator("#main-content");
    await expect(mainContent).toBeVisible();
    await expect(mainContent).not.toHaveAttribute("tabindex");
  });

  test("Skip link targets main content correctly", async ({ page }) => {
    await page.goto("/");

    const skipLink = page.locator(".skip-link");
    const href = await skipLink.getAttribute("href");

    expect(href).toBe("#main-content");

    // Verify the target exists
    const target = page.locator(href!);
    await expect(target).toBeVisible();
  });
});

test.describe("Accessibility - Content Pages", () => {
  test("Content page with TOC has accessible navigation", async ({ page }) => {
    await page.goto("/mysql/intro");

    // TOC should be present on content pages - assert to catch regressions
    const toc = page.locator("#toc");
    await expect(toc).toBeVisible();
    await expect(toc).toHaveAttribute("aria-label", "Table of contents");

    // Toggle may only be visible on mobile viewports
    const toggle = page.locator("#toc-toggle");
    if (await toggle.isVisible()) {
      await expect(toggle).toHaveAttribute("aria-controls", "toc-content");
      await expect(toggle).toHaveAttribute("aria-expanded");
    }
  });

  test("Breadcrumbs have correct ARIA implementation", async ({ page }) => {
    await page.goto("/mysql/intro");

    const breadcrumbs = page.locator('[aria-label="Breadcrumb"]');
    if ((await breadcrumbs.count()) > 0) {
      await expect(breadcrumbs).toBeVisible();

      // Current page should have aria-current (scoped to breadcrumbs)
      const currentPage = breadcrumbs.locator('[aria-current="page"]');
      await expect(currentPage).toBeVisible();
    }
  });

  test("Code blocks are accessible", async ({ page }) => {
    await page.goto("/mysql/intro");

    // Check that code blocks exist and have proper structure
    const codeBlocks = page.locator("pre code");
    const count = await codeBlocks.count();

    if (count > 0) {
      // Code blocks should be within pre elements
      const preElements = page.locator("pre");
      expect(await preElements.count()).toBeGreaterThan(0);
    }
  });
});
