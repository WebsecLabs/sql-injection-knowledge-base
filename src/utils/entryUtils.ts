import type { AnyEntry, AdjacentEntry } from "./types";
import type { ValidCollection } from "./constants";

// Re-export types for backward compatibility
export type { AnyEntry, AdjacentEntry };

export interface AdjacentEntries {
  previous: AdjacentEntry | null;
  next: AdjacentEntry | null;
}

/**
 * Category display order by learning progression/complexity.
 * Lower numbers appear first. Unknown categories sort to the end.
 */
export const CATEGORY_ORDER: Record<string, number> = {
  Basics: 1,
  "Information Gathering": 2,
  "Injection Techniques": 3,
  Authentication: 4,
  "File Operations": 5,
  "Advanced Techniques": 6,
  Reference: 7,
};

const DEFAULT_CATEGORY_ORDER = 99;

/**
 * Generate a URL for a content entry
 */
export function getEntryURL(
  collection: ValidCollection,
  slug: string,
  baseUrl: string = "/"
): string {
  return `${baseUrl}${collection}/${slug}`;
}

/**
 * Sort entries by category (by learning progression) then by order within each category.
 * This creates a consistent reading order across all entries.
 */
export function sortEntriesByCategory(entries: AnyEntry[]): AnyEntry[] {
  return [...entries].sort((a, b) => {
    const aOrder = CATEGORY_ORDER[a.data.category] ?? DEFAULT_CATEGORY_ORDER;
    const bOrder = CATEGORY_ORDER[b.data.category] ?? DEFAULT_CATEGORY_ORDER;
    if (aOrder !== bOrder) return aOrder - bOrder;
    if (a.data.order !== b.data.order) return a.data.order - b.data.order;
    return a.slug.localeCompare(b.slug); // Stable tiebreaker
  });
}

/**
 * Get adjacent (previous/next) entries for navigation.
 * Entries are ordered by category then by order field, enabling
 * continuous navigation across category boundaries.
 *
 * @param allEntries - The entries to search (will be sorted if sortedEntries not provided)
 * @param currentSlug - The slug of the current entry
 * @param sortedEntries - Optional pre-sorted entries to avoid re-sorting
 */
export function getAdjacentEntries(
  allEntries: AnyEntry[],
  currentSlug: string,
  sortedEntries?: AnyEntry[]
): AdjacentEntries {
  const sorted = sortedEntries ?? sortEntriesByCategory(allEntries);
  const currentIndex = sorted.findIndex((e) => e.slug === currentSlug);

  if (currentIndex === -1) {
    return { previous: null, next: null };
  }

  const previous =
    currentIndex > 0
      ? {
          slug: sorted[currentIndex - 1].slug,
          title: sorted[currentIndex - 1].data.title,
          category: sorted[currentIndex - 1].data.category,
        }
      : null;

  const next =
    currentIndex < sorted.length - 1
      ? {
          slug: sorted[currentIndex + 1].slug,
          title: sorted[currentIndex + 1].data.title,
          category: sorted[currentIndex + 1].data.category,
        }
      : null;

  return { previous, next };
}

/**
 * Get the first (canonical) entry slug for a collection.
 * Returns the slug of the first entry after sorting by category/order,
 * or null if the collection is empty.
 *
 * @param entries - The entries to search (will be sorted if sortedEntries not provided)
 * @param sortedEntries - Optional pre-sorted entries to avoid re-sorting
 */
export function getFirstEntrySlug(entries: AnyEntry[], sortedEntries?: AnyEntry[]): string | null {
  if (entries.length === 0) return null;
  const sorted = sortedEntries ?? sortEntriesByCategory(entries);
  return sorted[0].slug;
}

/**
 * Group entries by their category field.
 * Returns a record where keys are category names and values are arrays of entries.
 *
 * @param entries - Array of collection entries to group
 * @returns Record mapping category names to entry arrays
 */
export function groupByCategory<T extends AnyEntry>(entries: T[]): Record<string, T[]> {
  return entries.reduce<Record<string, T[]>>((acc, entry) => {
    const category = entry.data.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(entry);
    return acc;
  }, {});
}

/**
 * Comparator for sorting entries by order field, with slug as tiebreaker.
 * Ensures deterministic ordering when entries have the same order value.
 */
function compareEntriesByOrder<T extends AnyEntry>(a: T, b: T): number {
  return a.data.order - b.data.order || a.slug.localeCompare(b.slug);
}

/**
 * Sort entries within each category by their order field.
 * **Mutates the input record in place** for performance.
 *
 * @param grouped - Record of category -> entries from groupByCategory (will be mutated)
 * @returns The same record reference with entries sorted within each category
 */
export function sortGroupedEntriesInPlace<T extends AnyEntry>(
  grouped: Record<string, T[]>
): Record<string, T[]> {
  for (const category of Object.keys(grouped)) {
    grouped[category].sort(compareEntriesByOrder);
  }
  return grouped;
}

/**
 * Sort entries within each category by their order field.
 * Returns a new record without mutating the input.
 *
 * @param grouped - Record of category -> entries from groupByCategory
 * @returns A new record with entries sorted within each category
 */
export function sortGroupedEntries<T extends AnyEntry>(
  grouped: Record<string, T[]>
): Record<string, T[]> {
  const result: Record<string, T[]> = {};
  for (const category of Object.keys(grouped)) {
    result[category] = [...grouped[category]].sort(compareEntriesByOrder);
  }
  return result;
}

/**
 * Get category names sorted by learning progression order.
 * Uses CATEGORY_ORDER for known categories, unknown categories sort last alphabetically.
 *
 * @param grouped - Record of category -> entries
 * @returns Sorted array of category names
 */
export function getSortedCategories(grouped: Record<string, unknown[]>): string[] {
  return Object.keys(grouped).sort((a, b) => {
    const aOrder = CATEGORY_ORDER[a] ?? DEFAULT_CATEGORY_ORDER;
    const bOrder = CATEGORY_ORDER[b] ?? DEFAULT_CATEGORY_ORDER;
    return aOrder !== bOrder ? aOrder - bOrder : a.localeCompare(b);
  });
}
