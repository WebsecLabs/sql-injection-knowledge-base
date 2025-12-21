import { describe, it, expect } from "vitest";
import {
  normalizePath,
  buildEntryPath,
  isActivePath,
  createActiveChecker,
  createSectionActiveChecker,
} from "../../../src/utils/pathUtils";

describe("pathUtils", () => {
  describe("normalizePath", () => {
    it("removes single trailing slash", () => {
      expect(normalizePath("/mysql/intro/")).toBe("/mysql/intro");
    });

    it("removes multiple trailing slashes", () => {
      expect(normalizePath("/mysql/intro///")).toBe("/mysql/intro");
    });

    it("leaves path without trailing slash unchanged", () => {
      expect(normalizePath("/mysql/intro")).toBe("/mysql/intro");
    });

    it("handles empty string", () => {
      expect(normalizePath("")).toBe("");
    });

    it("handles root path", () => {
      expect(normalizePath("/")).toBe("");
    });

    it("handles base URL with trailing slash", () => {
      expect(normalizePath("/sql-injection-knowledge-base/")).toBe("/sql-injection-knowledge-base");
    });
  });

  describe("buildEntryPath", () => {
    it("builds path with root base URL", () => {
      expect(buildEntryPath("/", "mysql", "intro")).toBe("/mysql/intro");
    });

    it("builds path with trailing slash base URL", () => {
      expect(buildEntryPath("/base/", "mysql", "intro")).toBe("/base/mysql/intro");
    });

    it("builds path without trailing slash base URL", () => {
      // Function now correctly adds slash between baseUrl and section
      expect(buildEntryPath("/base", "mysql", "intro")).toBe("/base/mysql/intro");
    });

    it("handles complex slugs", () => {
      expect(buildEntryPath("/", "mssql", "openrowset-attacks")).toBe("/mssql/openrowset-attacks");
    });
  });

  describe("isActivePath", () => {
    it("returns true for matching paths", () => {
      expect(isActivePath("/mysql/intro", "/", "mysql", "intro")).toBe(true);
    });

    it("returns true when current path has trailing slash", () => {
      expect(isActivePath("/mysql/intro/", "/", "mysql", "intro")).toBe(true);
    });

    it("returns false for non-matching paths", () => {
      expect(isActivePath("/mysql/intro", "/", "mysql", "basics")).toBe(false);
    });

    it("returns false for different sections", () => {
      expect(isActivePath("/mysql/intro", "/", "oracle", "intro")).toBe(false);
    });

    it("works with non-root base URL", () => {
      expect(
        isActivePath(
          "/sql-injection-knowledge-base/mysql/intro/",
          "/sql-injection-knowledge-base/",
          "mysql",
          "intro"
        )
      ).toBe(true);
    });
  });

  describe("createActiveChecker", () => {
    it("creates a function that checks active state", () => {
      const checkActive = createActiveChecker("/mysql/intro", "/");

      expect(checkActive("mysql", "intro")).toBe(true);
      expect(checkActive("mysql", "basics")).toBe(false);
      expect(checkActive("oracle", "intro")).toBe(false);
    });

    it("handles trailing slashes in current path", () => {
      const checkActive = createActiveChecker("/mysql/intro/", "/");

      expect(checkActive("mysql", "intro")).toBe(true);
    });

    it("works with custom base URL", () => {
      const checkActive = createActiveChecker(
        "/sql-injection-knowledge-base/mysql/intro",
        "/sql-injection-knowledge-base/"
      );

      expect(checkActive("mysql", "intro")).toBe(true);
      expect(checkActive("mysql", "basics")).toBe(false);
    });
  });

  describe("createSectionActiveChecker", () => {
    it("creates a function that checks active state for a specific section", () => {
      const checkActive = createSectionActiveChecker("/mysql/intro", "/", "mysql");

      expect(checkActive("intro")).toBe(true);
      expect(checkActive("basics")).toBe(false);
    });

    it("returns false for paths in different sections", () => {
      const checkActive = createSectionActiveChecker("/oracle/intro", "/", "mysql");

      expect(checkActive("intro")).toBe(false);
    });

    it("handles trailing slashes", () => {
      const checkActive = createSectionActiveChecker("/mysql/tables-and-columns/", "/", "mysql");

      expect(checkActive("tables-and-columns")).toBe(true);
    });

    it("works with custom base URL", () => {
      const checkActive = createSectionActiveChecker(
        "/sql-injection-knowledge-base/postgresql/intro",
        "/sql-injection-knowledge-base/",
        "postgresql"
      );

      expect(checkActive("intro")).toBe(true);
      expect(checkActive("timing")).toBe(false);
    });
  });
});
