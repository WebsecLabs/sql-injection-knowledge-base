/**
 * Centralized type definitions for the SQL Injection Knowledge Base
 * @module types
 */

import type { CollectionEntry } from "astro:content";
import type { ValidCollection, DatabaseCollection } from "./constants";

/**
 * Generic collection entry that works with any valid collection
 */
export type AnyEntry = CollectionEntry<ValidCollection>;

/**
 * Database-specific collection entry (excludes extras)
 */
export type DatabaseEntry = CollectionEntry<DatabaseCollection>;

/**
 * Search entry structure for client-side search
 */
export interface SearchEntry {
  slug: string;
  title: string;
  description?: string;
  category: string;
  tags?: string[];
  collection: ValidCollection;
}

/**
 * Adjacent entry for prev/next navigation
 * Note: collection is not included as adjacent entries are within the same collection context
 */
export interface AdjacentEntry {
  slug: string;
  title: string;
  category: string;
}

/**
 * Type helper to generate collection entries map keys
 * Maps collection names to their entry array property names
 */
export type CollectionEntriesKey<T extends ValidCollection> = `${T}Entries`;

/**
 * Collection entries map for component props
 * Each key is `${collectionName}Entries` with optional array of entries
 */
export type CollectionEntriesMap = {
  [K in ValidCollection as CollectionEntriesKey<K>]?: CollectionEntry<K>[];
};
