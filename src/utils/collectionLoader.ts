/**
 * Collection loading utilities for the SQL Injection Knowledge Base
 * Provides centralized functions for loading and mapping content collections
 * @module collectionLoader
 */

import { getCollection, type CollectionEntry } from "astro:content";
import { COLLECTION_TYPES, type ValidCollection } from "./constants";
import type { CollectionEntriesMap } from "./types";

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
 * Load a single collection by name
 * Wrapper around getCollection with proper typing and error handling
 *
 * @param collection - The collection name to load
 * @returns Promise resolving to the collection entries
 * @throws Error with descriptive message if collection fails to load
 */
export async function loadCollection<T extends ValidCollection>(
  collection: T
): Promise<CollectionEntry<T>[]> {
  try {
    return await getCollection(collection);
  } catch (error) {
    throw new Error(
      `Failed to load collection "${collection}": ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
}
