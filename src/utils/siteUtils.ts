/**
 * Site URL utilities for Astro pages
 */

/**
 * Ensures Astro.site is configured and returns it.
 * Throws an error with a helpful message if site is not configured.
 *
 * @param site - The Astro.site value from the page context
 * @returns The validated site URL
 * @throws Error if site is undefined
 */
export function requireSiteUrl(site: URL | undefined): URL {
  if (!site) {
    throw new Error(
      "Astro.site must be configured. Set 'site' in astro.config.mjs or SITE_URL environment variable."
    );
  }
  return site;
}

/**
 * Map a page path on this deployment to its canonical URL.
 *
 * The path is taken relative to the site's base path and resolved against the
 * canonical base (by default the official websec.ca URL), so mirrors and
 * standalone builds point search engines at the official page.
 *
 * @param pathname - The page path, e.g. Astro.url.pathname
 * @param baseUrl - The site base path, e.g. import.meta.env.BASE_URL
 * @param canonicalBase - The canonical base URL, e.g. CANONICAL_URL from astro:env
 * @returns The absolute canonical URL
 *
 * @example
 * toCanonicalUrl("/mysql/intro/", "/", "https://websec.ca/sql-injection-knowledge-base/")
 * // Returns: "https://websec.ca/sql-injection-knowledge-base/mysql/intro/"
 */
export function toCanonicalUrl(pathname: string, baseUrl: string, canonicalBase: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const root = canonicalBase.endsWith("/") ? canonicalBase : `${canonicalBase}/`;
  const relative = pathname.startsWith(base)
    ? pathname.slice(base.length)
    : pathname.replace(/^\/+/, "");
  return new URL(relative, root).href;
}
