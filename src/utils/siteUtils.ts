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
