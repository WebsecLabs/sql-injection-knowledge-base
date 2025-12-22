/**
 * Mock module for astro:content virtual module
 * Used in unit tests to avoid Astro build-time dependencies
 */
import { vi } from "vitest";

// Mock getCollection function - can be overridden in tests
export const getCollection = vi.fn();

// Re-export type for type-checking (no runtime impact)
export type CollectionEntry<T extends string> = {
  id: string;
  slug: string;
  collection: T;
  data: {
    title: string;
    description?: string;
    category: string;
    order: number;
    tags?: string[];
  };
  body: string;
  render: () => Promise<{
    Content: () => null;
    headings: { depth: number; slug: string; text: string }[];
    remarkPluginFrontmatter: Record<string, unknown>;
  }>;
};
