/**
 * Generate a URL for a content entry
 */
export function getEntryURL(
  collection: 'mysql' | 'mssql' | 'oracle' | 'extras',
  slug: string
): string {
  return `/${collection}/${slug}`;
}