import type { CollectionEntry } from "astro:content";
import type { ValidCollection } from "./constants";

type AnyEntry = CollectionEntry<ValidCollection>;

export interface AdjacentEntry {
  slug: string;
  title: string;
  category: string;
}

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
 */
export function getAdjacentEntries(allEntries: AnyEntry[], currentSlug: string): AdjacentEntries {
  const sorted = sortEntriesByCategory(allEntries);
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
 */
export function getFirstEntrySlug(entries: AnyEntry[]): string | null {
  if (entries.length === 0) return null;
  const sorted = sortEntriesByCategory(entries);
  return sorted[0].slug;
}
