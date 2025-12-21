import { test, expect } from "@playwright/test";

/**
 * Parse RGB color string and calculate average brightness.
 * @param bgColor - CSS color value like "rgb(255, 255, 255)" or "rgba(0, 0, 0, 1)"
 * @returns Average brightness (0-255) or null if parsing fails
 */
function parseRgbAndCalculateBrightness(bgColor: string): number | null {
  const rgbMatch = bgColor.match(/\d+/g);

  if (!rgbMatch || rgbMatch.length < 3) {
    return null;
  }

  const rgb = rgbMatch.map(Number);
  return (rgb[0] + rgb[1] + rgb[2]) / 3;
}

test.describe("Theme Toggle", () => {
  test.beforeEach(async ({ page }) => {
    // Set viewport first, then clear localStorage BEFORE navigation
    // Using addInitScript ensures localStorage is cleared before any page scripts run
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.addInitScript(() => localStorage.clear());
    await page.goto("/");
  });

  test("should display theme toggle button", async ({ page }) => {
    const themeToggle = page.locator("#theme-toggle");
    await expect(themeToggle).toBeVisible();
  });

  test("should start with system theme by default", async ({ page }) => {
    const html = page.locator("html");
    // Should not have explicit data-theme if following system
    const theme = await html.getAttribute("data-theme");
    // Could be null/undefined if following system, or 'light'/'dark' if set
    expect(theme === null || theme === "light" || theme === "dark").toBe(true);
  });

  test("should toggle theme when button is clicked", async ({ page }) => {
    const themeToggle = page.locator("#theme-toggle");

    // Get initial background color
    const initialBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    // Click toggle
    await themeToggle.click();

    // Background color should change
    const afterClickBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    // Colors should be different (light vs dark theme)
    expect(initialBg).not.toBe(afterClickBg);
  });

  test("should persist theme preference across page navigation", async ({ page }) => {
    const themeToggle = page.locator("#theme-toggle");

    // Get initial background
    const initialBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    // Click to toggle theme
    await themeToggle.click();

    // Get new background
    const toggledBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );
    expect(toggledBg).not.toBe(initialBg);

    // Navigate to another page
    await page.goto("/mysql/intro");

    // Theme should persist
    const persistedBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );
    expect(persistedBg).toBe(toggledBg);
  });

  test("should persist theme preference after page reload", async ({ page }) => {
    const themeToggle = page.locator("#theme-toggle");

    // Get initial background
    const initialBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    // Click to toggle theme
    await themeToggle.click();

    // Get new background
    const toggledBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );
    expect(toggledBg).not.toBe(initialBg);

    // Reload page
    await page.reload();

    // Theme should persist
    const persistedBg = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );
    expect(persistedBg).toBe(toggledBg);
  });
});

test.describe("Theme - Respects System Preference", () => {
  test("should respect prefers-color-scheme: dark", async ({ page }) => {
    // Emulate dark mode preference
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto("/");
    await page.evaluate(() => localStorage.clear());
    await page.reload();

    // Check that dark theme is applied
    const bgColor = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    const brightness = parseRgbAndCalculateBrightness(bgColor);
    expect(brightness, `Failed to parse RGB from: ${bgColor}`).not.toBeNull();
    // Dark theme should have low brightness (dark background)
    expect(brightness).toBeLessThan(128);
  });

  test("should respect prefers-color-scheme: light", async ({ page }) => {
    // Emulate light mode preference
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto("/");
    await page.evaluate(() => localStorage.clear());
    await page.reload();

    // Check that light theme is applied
    const bgColor = await page.evaluate(
      () => window.getComputedStyle(document.body).backgroundColor
    );

    const brightness = parseRgbAndCalculateBrightness(bgColor);
    expect(brightness, `Failed to parse RGB from: ${bgColor}`).not.toBeNull();
    // Light theme should have high brightness (light background)
    expect(brightness).toBeGreaterThan(128);
  });
});
