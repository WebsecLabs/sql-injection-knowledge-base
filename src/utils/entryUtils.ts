/**
 * Generate a URL for a content entry
 */
export function getEntryURL(
  collection: "mysql" | "mssql" | "oracle" | "postgresql" | "extras",
  slug: string,
  baseUrl: string = "/"
): string {
  return `${baseUrl}${collection}/${slug}`;
}
