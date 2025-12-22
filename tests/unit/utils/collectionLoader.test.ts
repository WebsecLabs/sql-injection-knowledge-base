import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ValidCollection } from "../../../src/utils/constants";
import type { CollectionEntriesMap } from "../../../src/utils/types";

// Import the mock module (aliased in vitest.config.ts)
import { getCollection, type CollectionEntry } from "astro:content";
import {
  loadAllCollections,
  mapToSearchEntries,
  loadCollection,
} from "../../../src/utils/collectionLoader";

// Type the mocked function
const mockGetCollection = vi.mocked(getCollection);

// Factory to create mock collection entries
function createMockEntry<T extends ValidCollection>(
  collection: T,
  slug: string,
  title: string,
  category: string,
  order: number = 1,
  description: string = `Description for ${title}`,
  tags: string[] = []
): CollectionEntry<T> {
  return {
    id: slug,
    slug,
    collection,
    data: {
      title,
      description,
      category,
      order,
      tags,
    },
    body: "",
    render: async () => ({
      Content: () => null,
      headings: [],
      remarkPluginFrontmatter: {},
    }),
  } as unknown as CollectionEntry<T>;
}

describe("collectionLoader", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("loadAllCollections", () => {
    it("loads all collections in parallel", async () => {
      const mockMysqlEntries = [createMockEntry("mysql", "intro", "Introduction", "Basics")];
      const mockMariadbEntries = [createMockEntry("mariadb", "setup", "Setup", "Basics")];
      const mockMssqlEntries = [createMockEntry("mssql", "auth", "Authentication", "Basics")];
      const mockOracleEntries = [createMockEntry("oracle", "plsql", "PL/SQL", "Basics")];
      const mockPostgresqlEntries = [
        createMockEntry("postgresql", "functions", "Functions", "Basics"),
      ];
      const mockExtrasEntries = [createMockEntry("extras", "about", "About", "Reference")];

      mockGetCollection.mockImplementation(async (name: ValidCollection) => {
        const collections: Record<ValidCollection, CollectionEntry<ValidCollection>[]> = {
          mysql: mockMysqlEntries,
          mariadb: mockMariadbEntries,
          mssql: mockMssqlEntries,
          oracle: mockOracleEntries,
          postgresql: mockPostgresqlEntries,
          extras: mockExtrasEntries,
        };
        return collections[name] || [];
      });

      const result = await loadAllCollections();

      expect(mockGetCollection).toHaveBeenCalledTimes(6);
      expect(result.mysqlEntries).toEqual(mockMysqlEntries);
      expect(result.mariadbEntries).toEqual(mockMariadbEntries);
      expect(result.mssqlEntries).toEqual(mockMssqlEntries);
      expect(result.oracleEntries).toEqual(mockOracleEntries);
      expect(result.postgresqlEntries).toEqual(mockPostgresqlEntries);
      expect(result.extrasEntries).toEqual(mockExtrasEntries);
    });

    it("throws error when a collection fails to load", async () => {
      mockGetCollection.mockImplementation(async (name: ValidCollection) => {
        if (name === "mysql") {
          throw new Error("Network error");
        }
        return [];
      });

      await expect(loadAllCollections()).rejects.toThrow(
        'Failed to load collection "mysql": Network error'
      );
    });

    it("handles empty collections", async () => {
      mockGetCollection.mockResolvedValue([]);

      const result = await loadAllCollections();

      expect(result.mysqlEntries).toEqual([]);
      expect(result.mariadbEntries).toEqual([]);
    });
  });

  describe("mapToSearchEntries", () => {
    it("transforms collection entries to search entries", () => {
      const entries: CollectionEntriesMap = {
        mysqlEntries: [
          createMockEntry("mysql", "intro", "Introduction", "Basics", 1, "MySQL intro", [
            "getting-started",
          ]),
        ],
        mariadbEntries: [
          createMockEntry("mariadb", "setup", "Setup Guide", "Basics", 1, "MariaDB setup", [
            "installation",
          ]),
        ],
      };

      const result = mapToSearchEntries(entries);

      expect(result).toHaveLength(2);
      expect(result).toContainEqual({
        slug: "intro",
        title: "Introduction",
        description: "MySQL intro",
        category: "Basics",
        tags: ["getting-started"],
        collection: "mysql",
      });
      expect(result).toContainEqual({
        slug: "setup",
        title: "Setup Guide",
        description: "MariaDB setup",
        category: "Basics",
        tags: ["installation"],
        collection: "mariadb",
      });
    });

    it("handles empty collections map", () => {
      const entries: CollectionEntriesMap = {};
      const result = mapToSearchEntries(entries);
      expect(result).toEqual([]);
    });

    it("handles undefined collection entries", () => {
      const entries: CollectionEntriesMap = {
        mysqlEntries: undefined,
      };
      const result = mapToSearchEntries(entries);
      expect(result).toEqual([]);
    });

    it("preserves all entry metadata", () => {
      const entries: CollectionEntriesMap = {
        oracleEntries: [
          createMockEntry(
            "oracle",
            "plsql-injection",
            "PL/SQL Injection",
            "Injection Techniques",
            5,
            "Advanced PL/SQL injection techniques",
            ["oracle", "plsql", "advanced"]
          ),
        ],
      };

      const result = mapToSearchEntries(entries);

      expect(result).toHaveLength(1);
      const entry = result[0];
      expect(entry.slug).toBe("plsql-injection");
      expect(entry.title).toBe("PL/SQL Injection");
      expect(entry.description).toBe("Advanced PL/SQL injection techniques");
      expect(entry.category).toBe("Injection Techniques");
      expect(entry.tags).toEqual(["oracle", "plsql", "advanced"]);
      expect(entry.collection).toBe("oracle");
    });

    it("processes multiple entries from multiple collections", () => {
      const entries: CollectionEntriesMap = {
        mysqlEntries: [
          createMockEntry("mysql", "a", "A", "Basics"),
          createMockEntry("mysql", "b", "B", "Basics"),
        ],
        postgresqlEntries: [
          createMockEntry("postgresql", "c", "C", "Advanced Techniques"),
          createMockEntry("postgresql", "d", "D", "Advanced Techniques"),
        ],
        extrasEntries: [createMockEntry("extras", "e", "E", "Reference")],
      };

      const result = mapToSearchEntries(entries);

      expect(result).toHaveLength(5);
      expect(result.filter((e) => e.collection === "mysql")).toHaveLength(2);
      expect(result.filter((e) => e.collection === "postgresql")).toHaveLength(2);
      expect(result.filter((e) => e.collection === "extras")).toHaveLength(1);
    });

    it("handles entries with optional fields missing", () => {
      const entryWithMinimalData = {
        id: "minimal",
        slug: "minimal",
        collection: "mysql",
        data: {
          title: "Minimal Entry",
          category: "Basics",
          order: 1,
          // description and tags are optional
        },
        body: "",
        render: async () => ({
          Content: () => null,
          headings: [],
          remarkPluginFrontmatter: {},
        }),
      } as unknown as CollectionEntry<"mysql">;

      const entries: CollectionEntriesMap = {
        mysqlEntries: [entryWithMinimalData],
      };

      const result = mapToSearchEntries(entries);

      expect(result).toHaveLength(1);
      expect(result[0].slug).toBe("minimal");
      expect(result[0].description).toBeUndefined();
      expect(result[0].tags).toBeUndefined();
    });
  });

  describe("loadCollection", () => {
    it("loads a single collection by name", async () => {
      const mockEntries = [
        createMockEntry("postgresql", "intro", "Introduction", "Basics"),
        createMockEntry("postgresql", "advanced", "Advanced", "Advanced Techniques"),
      ];

      mockGetCollection.mockResolvedValue(mockEntries);

      const result = await loadCollection("postgresql");

      expect(mockGetCollection).toHaveBeenCalledWith("postgresql");
      expect(result).toEqual(mockEntries);
    });

    it("returns empty array for empty collection", async () => {
      mockGetCollection.mockResolvedValue([]);

      const result = await loadCollection("mssql");

      expect(result).toEqual([]);
    });

    it("propagates errors from getCollection", async () => {
      mockGetCollection.mockRejectedValue(new Error("Collection not found"));

      await expect(loadCollection("oracle")).rejects.toThrow("Collection not found");
    });
  });
});
