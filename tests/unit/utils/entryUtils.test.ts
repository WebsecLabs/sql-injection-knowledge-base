import { describe, it, expect } from "vitest";
import {
  getEntryURL,
  sortEntriesByCategory,
  getAdjacentEntries,
  getFirstEntrySlug,
  groupByCategory,
  sortGroupedEntriesInPlace,
  getSortedCategories,
  CATEGORY_ORDER,
} from "../../../src/utils/entryUtils";
import type { AnyEntry } from "../../../src/utils/entryUtils";

// Mock entry factory for testing
function createMockEntry(slug: string, title: string, category: string, order: number): AnyEntry {
  return {
    id: slug,
    slug,
    collection: "mysql",
    data: {
      title,
      description: `Description for ${title}`,
      category,
      order,
      tags: [],
    },
    body: "",
    render: async () => ({
      Content: () => null,
      headings: [],
      remarkPluginFrontmatter: {},
    }),
  } as unknown as AnyEntry;
}

describe("entryUtils", () => {
  describe("getEntryURL", () => {
    it("generates URL with root base", () => {
      expect(getEntryURL("mysql", "intro", "/")).toBe("/mysql/intro");
    });

    it("generates URL with custom base", () => {
      expect(getEntryURL("mysql", "intro", "/sql-injection-knowledge-base/")).toBe(
        "/sql-injection-knowledge-base/mysql/intro"
      );
    });

    it("generates URL with default base when not provided", () => {
      expect(getEntryURL("oracle", "timing")).toBe("/oracle/timing");
    });

    it("handles different collection types", () => {
      expect(getEntryURL("extras", "about", "/")).toBe("/extras/about");
    });
  });

  describe("CATEGORY_ORDER", () => {
    it("has Basics as the first category", () => {
      expect(CATEGORY_ORDER["Basics"]).toBe(1);
    });

    it("has Reference as the last defined category", () => {
      expect(CATEGORY_ORDER["Reference"]).toBe(7);
    });

    it("follows logical learning progression", () => {
      expect(CATEGORY_ORDER["Basics"]).toBeLessThan(CATEGORY_ORDER["Information Gathering"]);
      expect(CATEGORY_ORDER["Information Gathering"]).toBeLessThan(
        CATEGORY_ORDER["Injection Techniques"]
      );
      expect(CATEGORY_ORDER["Injection Techniques"]).toBeLessThan(
        CATEGORY_ORDER["Advanced Techniques"]
      );
    });
  });

  describe("sortEntriesByCategory", () => {
    it("sorts entries by category order", () => {
      const entries = [
        createMockEntry("adv", "Advanced", "Advanced Techniques", 1),
        createMockEntry("basics", "Basics", "Basics", 1),
        createMockEntry("info", "Info Gathering", "Information Gathering", 1),
      ];

      const sorted = sortEntriesByCategory(entries);

      expect(sorted[0].data.category).toBe("Basics");
      expect(sorted[1].data.category).toBe("Information Gathering");
      expect(sorted[2].data.category).toBe("Advanced Techniques");
    });

    it("sorts by order within same category", () => {
      const entries = [
        createMockEntry("third", "Third", "Basics", 3),
        createMockEntry("first", "First", "Basics", 1),
        createMockEntry("second", "Second", "Basics", 2),
      ];

      const sorted = sortEntriesByCategory(entries);

      expect(sorted.map((e) => e.slug)).toEqual(["first", "second", "third"]);
    });

    it("uses slug as tiebreaker for same order", () => {
      const entries = [
        createMockEntry("zzz", "ZZZ", "Basics", 1),
        createMockEntry("aaa", "AAA", "Basics", 1),
      ];

      const sorted = sortEntriesByCategory(entries);

      expect(sorted[0].slug).toBe("aaa");
      expect(sorted[1].slug).toBe("zzz");
    });

    it("puts unknown categories at the end", () => {
      const entries = [
        createMockEntry("unknown", "Unknown", "Unknown Category", 1),
        createMockEntry("basics", "Basics", "Basics", 1),
      ];

      const sorted = sortEntriesByCategory(entries);

      expect(sorted[0].data.category).toBe("Basics");
      expect(sorted[1].data.category).toBe("Unknown Category");
    });

    it("does not mutate the original array", () => {
      const entries = [
        createMockEntry("second", "Second", "Basics", 2),
        createMockEntry("first", "First", "Basics", 1),
      ];
      const original = [...entries];

      sortEntriesByCategory(entries);

      expect(entries).toEqual(original);
    });
  });

  describe("getAdjacentEntries", () => {
    const entries = [
      createMockEntry("first", "First", "Basics", 1),
      createMockEntry("second", "Second", "Basics", 2),
      createMockEntry("third", "Third", "Basics", 3),
    ];

    it("returns previous and next entries for middle item", () => {
      const result = getAdjacentEntries(entries, "second");

      expect(result.previous?.slug).toBe("first");
      expect(result.next?.slug).toBe("third");
    });

    it("returns null for previous when at first entry", () => {
      const result = getAdjacentEntries(entries, "first");

      expect(result.previous).toBeNull();
      expect(result.next?.slug).toBe("second");
    });

    it("returns null for next when at last entry", () => {
      const result = getAdjacentEntries(entries, "third");

      expect(result.previous?.slug).toBe("second");
      expect(result.next).toBeNull();
    });

    it("returns both null for non-existent entry", () => {
      const result = getAdjacentEntries(entries, "nonexistent");

      expect(result.previous).toBeNull();
      expect(result.next).toBeNull();
    });

    it("includes category information in adjacent entries", () => {
      const result = getAdjacentEntries(entries, "second");

      expect(result.previous?.category).toBe("Basics");
      expect(result.next?.category).toBe("Basics");
    });

    it("uses pre-sorted entries when provided", () => {
      const unsorted = [
        createMockEntry("second", "Second", "Basics", 2),
        createMockEntry("first", "First", "Basics", 1),
        createMockEntry("third", "Third", "Basics", 3),
      ];
      const preSorted = sortEntriesByCategory(unsorted);

      const result = getAdjacentEntries(unsorted, "second", preSorted);

      expect(result.previous?.slug).toBe("first");
      expect(result.next?.slug).toBe("third");
    });
  });

  describe("getFirstEntrySlug", () => {
    it("returns first entry slug after sorting", () => {
      const entries = [
        createMockEntry("second", "Second", "Basics", 2),
        createMockEntry("first", "First", "Basics", 1),
      ];

      expect(getFirstEntrySlug(entries)).toBe("first");
    });

    it("returns null for empty array", () => {
      expect(getFirstEntrySlug([])).toBeNull();
    });

    it("uses pre-sorted entries when provided", () => {
      const unsorted = [
        createMockEntry("second", "Second", "Basics", 2),
        createMockEntry("first", "First", "Basics", 1),
      ];
      const preSorted = sortEntriesByCategory(unsorted);

      expect(getFirstEntrySlug(unsorted, preSorted)).toBe("first");
    });
  });

  describe("groupByCategory", () => {
    it("groups entries by their category", () => {
      const entries = [
        createMockEntry("a", "A", "Basics", 1),
        createMockEntry("b", "B", "Advanced Techniques", 1),
        createMockEntry("c", "C", "Basics", 2),
      ];

      const grouped = groupByCategory(entries);

      expect(Object.keys(grouped)).toHaveLength(2);
      expect(grouped["Basics"]).toHaveLength(2);
      expect(grouped["Advanced Techniques"]).toHaveLength(1);
    });

    it("returns empty object for empty input", () => {
      expect(groupByCategory([])).toEqual({});
    });

    it("preserves entry order within category", () => {
      const entries = [
        createMockEntry("first", "First", "Basics", 1),
        createMockEntry("second", "Second", "Basics", 2),
      ];

      const grouped = groupByCategory(entries);

      expect(grouped["Basics"][0].slug).toBe("first");
      expect(grouped["Basics"][1].slug).toBe("second");
    });
  });

  describe("sortGroupedEntriesInPlace", () => {
    it("sorts entries within each category by order", () => {
      const grouped = {
        Basics: [
          createMockEntry("second", "Second", "Basics", 2),
          createMockEntry("first", "First", "Basics", 1),
        ],
      };

      const sorted = sortGroupedEntriesInPlace(grouped);

      expect(sorted["Basics"][0].slug).toBe("first");
      expect(sorted["Basics"][1].slug).toBe("second");
    });

    it("mutates the input object (in-place sort)", () => {
      const grouped = {
        Basics: [
          createMockEntry("second", "Second", "Basics", 2),
          createMockEntry("first", "First", "Basics", 1),
        ],
      };

      const result = sortGroupedEntriesInPlace(grouped);

      expect(result).toBe(grouped);
    });

    it("handles multiple categories", () => {
      const grouped = {
        Basics: [
          createMockEntry("b2", "B2", "Basics", 2),
          createMockEntry("b1", "B1", "Basics", 1),
        ],
        Advanced: [
          createMockEntry("a2", "A2", "Advanced", 2),
          createMockEntry("a1", "A1", "Advanced", 1),
        ],
      };

      const sorted = sortGroupedEntriesInPlace(grouped);

      expect(sorted["Basics"].map((e) => e.slug)).toEqual(["b1", "b2"]);
      expect(sorted["Advanced"].map((e) => e.slug)).toEqual(["a1", "a2"]);
    });
  });

  describe("getSortedCategories", () => {
    it("sorts categories by CATEGORY_ORDER", () => {
      const grouped = {
        "Advanced Techniques": [],
        Basics: [],
        "Information Gathering": [],
      };

      const sorted = getSortedCategories(grouped);

      expect(sorted).toEqual(["Basics", "Information Gathering", "Advanced Techniques"]);
    });

    it("puts unknown categories at the end alphabetically", () => {
      const grouped = {
        "Zebra Category": [],
        "Alpha Category": [],
        Basics: [],
      };

      const sorted = getSortedCategories(grouped);

      expect(sorted).toEqual(["Basics", "Alpha Category", "Zebra Category"]);
    });

    it("returns empty array for empty input", () => {
      expect(getSortedCategories({})).toEqual([]);
    });
  });
});
