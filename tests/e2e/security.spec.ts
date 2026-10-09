import { test, expect, type Page } from "@playwright/test";

/**
 * Content-Security-Policy checks. The policy is generated at build time,
 * embedded in every page as a <meta> element and, in the production
 * container, also sent by nginx as a header with frame-ancestors and reporting.
 */

/** Record CSP violations reported by the browser, including after navigation */
async function trackCspViolations(page: Page): Promise<string[]> {
  const violations: string[] = [];
  await page.exposeFunction("__reportCspViolation", (detail: string) => {
    violations.push(detail);
  });
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      const report = (window as unknown as { __reportCspViolation: (d: string) => void })
        .__reportCspViolation;
      report(`${event.violatedDirective} blocked ${event.blockedURI || "inline"}`);
    });
  });
  return violations;
}

function expectStrictScriptPolicy(csp: string): void {
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).toMatch(/script-src 'self'[^;]* 'sha256-/);
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-eval'/);
  expect(csp).not.toMatch(/script-src[^;]*\bdata:/);
}

test.describe("Content-Security-Policy", () => {
  test("is embedded in the page ahead of any script", async ({ page }) => {
    await page.goto("mysql/intro");
    const meta = page.locator('head meta[http-equiv="Content-Security-Policy"]');

    await expect(meta).toHaveCount(1);
    expectStrictScriptPolicy((await meta.getAttribute("content")) ?? "");

    const precedesScripts = await page.evaluate(() => {
      const policy = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      const firstScript = document.querySelector("script");
      return (
        !!policy &&
        (!firstScript ||
          !!(policy.compareDocumentPosition(firstScript) & Node.DOCUMENT_POSITION_FOLLOWING))
      );
    });
    expect(precedesScripts).toBe(true);
  });

  test("is sent as a header with framing protection", async ({ page }) => {
    const response = await page.goto("mysql/intro");
    const csp = response?.headers()["content-security-policy"] ?? "";

    // CI serves the production container and must send the header; other
    // static hosts rely on the <meta> policy alone
    test.skip(!csp && !process.env.EXPECT_CSP_HEADER, "Served without nginx headers");
    expectStrictScriptPolicy(csp);
    expect(csp).toContain("frame-ancestors 'none'");
  });

  test("allows article pages and client-side navigation", async ({ page }) => {
    const violations = await trackCspViolations(page);

    await page.goto("mysql/intro");
    await page.waitForLoadState("networkidle");

    // Navigate through the ClientRouter to the home page, whose tabs use
    // page-specific inline scripts
    await page.locator(".navbar-brand, a[href$='/sql-injection-knowledge-base/']").first().click();
    await expect(page.locator(".tab-list").first()).toBeVisible();
    await page.locator(".tab-list [role='tab']").nth(1).click();

    expect(violations).toEqual([]);
  });

  test("allows the search modal to load and query the index", async ({ page }) => {
    const violations = await trackCspViolations(page);

    await page.goto("./");
    await page.keyboard.press("Control+k");
    await page.locator("#search-modal-input").fill("union");
    await expect(page.locator("#search-modal-results [role='option']").first()).toBeVisible({
      timeout: 10000,
    });

    expect(violations).toEqual([]);
  });

  test("allows the search page to load and query the index", async ({ page }) => {
    const violations = await trackCspViolations(page);

    await page.goto("search?q=union");
    await expect(page.locator(".pagefind-ui__result").first()).toBeVisible({ timeout: 10000 });

    expect(violations).toEqual([]);
  });

  test("allows theme toggling", async ({ page }) => {
    const violations = await trackCspViolations(page);

    await page.goto("mysql/intro");
    const toggle = page.locator("#theme-toggle:visible, #mobile-theme-toggle:visible").first();
    await toggle.click();

    expect(violations).toEqual([]);
  });
});
