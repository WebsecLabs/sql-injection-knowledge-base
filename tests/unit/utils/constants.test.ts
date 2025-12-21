import { describe, it, expect } from "vitest";
import {
  DATABASE_COLLECTION_TYPES,
  COLLECTION_TYPES,
  COLLECTION_LABELS,
  COLLECTION_SEARCH_LABELS,
} from "../../../src/utils/constants";

describe("constants", () => {
  describe("DATABASE_COLLECTION_TYPES", () => {
    it("contains all database types", () => {
      expect(DATABASE_COLLECTION_TYPES).toEqual([
        "mysql",
        "mariadb",
        "mssql",
        "oracle",
        "postgresql",
      ]);
    });

    it("does not include extras", () => {
      expect(DATABASE_COLLECTION_TYPES).not.toContain("extras");
    });
  });

  describe("COLLECTION_TYPES", () => {
    it("contains all database types plus extras", () => {
      expect(COLLECTION_TYPES).toEqual([
        "mysql",
        "mariadb",
        "mssql",
        "oracle",
        "postgresql",
        "extras",
      ]);
    });

    it("includes extras as the last element", () => {
      expect(COLLECTION_TYPES[COLLECTION_TYPES.length - 1]).toBe("extras");
    });

    it("has one more item than DATABASE_COLLECTION_TYPES", () => {
      expect(COLLECTION_TYPES.length).toBe(DATABASE_COLLECTION_TYPES.length + 1);
    });
  });

  describe("COLLECTION_LABELS", () => {
    it("has labels for all collection types", () => {
      for (const type of COLLECTION_TYPES) {
        expect(COLLECTION_LABELS[type]).toBeDefined();
        expect(typeof COLLECTION_LABELS[type]).toBe("string");
      }
    });

    it("has correct label mappings", () => {
      expect(COLLECTION_LABELS.mysql).toBe("MySQL");
      expect(COLLECTION_LABELS.mariadb).toBe("MariaDB");
      expect(COLLECTION_LABELS.mssql).toBe("MSSQL");
      expect(COLLECTION_LABELS.oracle).toBe("Oracle");
      expect(COLLECTION_LABELS.postgresql).toBe("PostgreSQL");
      expect(COLLECTION_LABELS.extras).toBe("Extras");
    });
  });

  describe("COLLECTION_SEARCH_LABELS", () => {
    it("has labels for all collection types", () => {
      for (const type of COLLECTION_TYPES) {
        expect(COLLECTION_SEARCH_LABELS[type]).toBeDefined();
        expect(typeof COLLECTION_SEARCH_LABELS[type]).toBe("string");
      }
    });

    it("uses 'Other Resources' for extras (different from COLLECTION_LABELS)", () => {
      expect(COLLECTION_SEARCH_LABELS.extras).toBe("Other Resources");
      expect(COLLECTION_LABELS.extras).toBe("Extras");
    });

    it("has same labels as COLLECTION_LABELS for database types", () => {
      for (const type of DATABASE_COLLECTION_TYPES) {
        expect(COLLECTION_SEARCH_LABELS[type]).toBe(COLLECTION_LABELS[type]);
      }
    });
  });
});
