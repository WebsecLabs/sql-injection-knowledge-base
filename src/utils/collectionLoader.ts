/**
 * Collection loading utilities for the SQL Injection Knowledge Base
 * Provides centralized functions for loading and mapping content collections
 * @module collectionLoader
 */

import { getCollection, type CollectionEntry } from "astro:content";
import { COLLECTION_TYPES, type ValidCollection } from "./constants";
import type { CollectionEntriesMap, SearchEntry } from "./types";

/**
 * Load all collections in parallel
 * Returns a map of collection entries keyed by `${collectionName}Entries`
 *
 * @returns Promise resolving to a CollectionEntriesMap
 *
 * @example
 * ```typescript
 * const collections = await loadAllCollections();
 * // collections.mysqlEntries, collections.mariadbEntries, etc.
 * ```
 */
export async function loadAllCollections(): Promise<CollectionEntriesMap> {
  const results = await Promise.all(
    COLLECTION_TYPES.map(async (collection) => {
      try {
        const entries = await getCollection(collection);
        return [collection, entries] as const;
      } catch (error) {
        throw new Error(
          `Failed to load collection "${collection}": ${error instanceof Error ? error.message : String(error)}`
        );
      }
    })
  );

  const map: CollectionEntriesMap = {};
  for (const [collection, entries] of results) {
    const key = `${collection}Entries` as keyof CollectionEntriesMap;
    // Type assertion needed due to TypeScript limitation with mapped types
    (map as Record<string, unknown>)[key] = entries;
  }

  return map;
}

/**
 * Map collection entries to search data format
 * Transforms a CollectionEntriesMap into a flat array of SearchEntry objects
 *
 * @param entries - The CollectionEntriesMap from loadAllCollections
 * @returns Array of SearchEntry objects ready for client-side search
 *
 * @example
 * ```typescript
 * const collections = await loadAllCollections();
 * const searchData = mapToSearchEntries(collections);
 * ```
 */
export function mapToSearchEntries(entries: CollectionEntriesMap): SearchEntry[] {
  const result: SearchEntry[] = [];

  for (const collection of COLLECTION_TYPES) {
    const key = `${collection}Entries` as keyof CollectionEntriesMap;
    const collectionEntries = entries[key];

    if (collectionEntries) {
      for (const entry of collectionEntries) {
        result.push({
          slug: entry.slug,
          title: entry.data.title,
          description: entry.data.description,
          category: entry.data.category,
          tags: entry.data.tags,
          collection,
        });
      }
    }
  }

  return result;
}

/**
 * Load a single collection by name
 * Wrapper around getCollection with proper typing
 *
 * @param collection - The collection name to load
 * @returns Promise resolving to the collection entries
 */
export async function loadCollection<T extends ValidCollection>(
  collection: T
): Promise<CollectionEntry<T>[]> {
  return getCollection(collection);
}
