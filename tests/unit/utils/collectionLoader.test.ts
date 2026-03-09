import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ValidCollection } from "../../../src/utils/constants";

// Import the mock module (aliased in vitest.config.ts)
import { getCollection, type CollectionEntry } from "astro:content";
import { loadAllCollections } from "../../../src/utils/collectionLoader";

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

});
