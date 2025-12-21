/**
 * Path utilities for URL handling and active state detection.
 * Provides functions for normalizing paths and checking active navigation states.
 */

/**
 * Normalize a path by removing trailing slashes.
 * Handles both single and multiple trailing slashes.
 *
 * @param path - The path to normalize
 * @returns Path without trailing slashes
 */
export function normalizePath(path: string): string {
  return path.replace(/\/+$/, "");
}

/**
 * Build an entry URL from components.
 * Combines base URL, section, and slug into a normalized path.
 * Handles trailing slash normalization to ensure proper path construction
 * regardless of whether baseUrl ends with a slash.
 *
 * @param baseUrl - The base URL (e.g., from import.meta.env.BASE_URL)
 * @param section - The collection/section name (e.g., "mysql", "postgresql")
 * @param slug - The entry slug
 * @returns The full normalized entry path
 */
export function buildEntryPath(baseUrl: string, section: string, slug: string): string {
  // Ensure baseUrl ends with exactly one slash
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  // Trim leading/trailing slashes from section and slug
  const normalizedSection = section.replace(/^\/+|\/+$/g, "");
  const normalizedSlug = slug.replace(/^\/+|\/+$/g, "");
  return normalizePath(`${normalizedBase}${normalizedSection}/${normalizedSlug}`);
}

/**
 * Check if the current path matches an entry path.
 * Handles trailing slash normalization automatically.
 *
 * @param currentPath - The current browser path (e.g., Astro.url.pathname)
 * @param baseUrl - The base URL for the site
 * @param section - The collection/section name
 * @param slug - The entry slug
 * @returns True if paths match
 */
export function isActivePath(
  currentPath: string,
  baseUrl: string,
  section: string,
  slug: string
): boolean {
  return normalizePath(currentPath) === buildEntryPath(baseUrl, section, slug);
}

/**
 * Create a curried isActivePath checker that takes section and slug.
 * Useful for NavBar/NavDropdown where the section varies per item.
 *
 * @param currentPath - The current browser path
 * @param baseUrl - The base URL for the site
 * @returns A function that takes section and slug and returns active status
 *
 * @example
 * const checkActive = createActiveChecker(Astro.url.pathname, import.meta.env.BASE_URL);
 * const isActive = checkActive("mysql", "intro"); // true or false
 */
export function createActiveChecker(
  currentPath: string,
  baseUrl: string
): (section: string, slug: string) => boolean {
  return (section: string, slug: string) => isActivePath(currentPath, baseUrl, section, slug);
}

/**
 * Create a curried isActivePath checker for a specific section.
 * Useful for SidebarSection where section is known at component level.
 *
 * @param currentPath - The current browser path
 * @param baseUrl - The base URL for the site
 * @param section - The collection/section name
 * @returns A function that takes only slug and returns active status
 *
 * @example
 * const checkActive = createSectionActiveChecker(currentPath, baseUrl, "mysql");
 * const isActive = checkActive("intro"); // true or false
 */
export function createSectionActiveChecker(
  currentPath: string,
  baseUrl: string,
  section: string
): (slug: string) => boolean {
  return (slug: string) => isActivePath(currentPath, baseUrl, section, slug);
}
