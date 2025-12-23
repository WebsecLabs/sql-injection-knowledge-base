import { describe, it, expect } from "vitest";
import {
  sanitizeBaseUrl,
  normalizeBaseUrl,
  normalizePath,
  buildEntryPath,
  isActivePath,
  createActiveChecker,
  createSectionActiveChecker,
} from "../../../src/utils/pathUtils";

describe("pathUtils", () => {
  describe("sanitizeBaseUrl", () => {
    it("returns relative paths starting with / unchanged", () => {
      expect(sanitizeBaseUrl("/")).toBe("/");
      expect(sanitizeBaseUrl("/base/")).toBe("/base/");
      expect(sanitizeBaseUrl("/sql-injection-knowledge-base/")).toBe(
        "/sql-injection-knowledge-base/"
      );
    });

    it("allows http:// and https:// protocols", () => {
      expect(sanitizeBaseUrl("https://example.com/")).toBe("https://example.com/");
      expect(sanitizeBaseUrl("http://localhost:3000/")).toBe("http://localhost:3000/");
    });

    it("rejects javascript: protocol", () => {
      expect(sanitizeBaseUrl("javascript:alert(1)")).toBe("/");
    });

    it("rejects data: protocol", () => {
      expect(sanitizeBaseUrl("data:text/html,<script>alert(1)</script>")).toBe("/");
    });

    it("rejects vbscript: protocol", () => {
      expect(sanitizeBaseUrl("vbscript:msgbox(1)")).toBe("/");
    });

    it("returns fallback for empty string", () => {
      expect(sanitizeBaseUrl("")).toBe("/");
      expect(sanitizeBaseUrl("", "/fallback")).toBe("/fallback");
    });

    it("returns fallback for non-string values", () => {
      expect(sanitizeBaseUrl(null)).toBe("/");
      expect(sanitizeBaseUrl(undefined)).toBe("/");
      expect(sanitizeBaseUrl(123)).toBe("/");
      expect(sanitizeBaseUrl({})).toBe("/");
      // Additional non-string coercion edge cases
      expect(sanitizeBaseUrl(NaN)).toBe("/");
      expect(sanitizeBaseUrl([])).toBe("/");
      expect(sanitizeBaseUrl(["/some"])).toBe("/");
      expect(sanitizeBaseUrl(() => {})).toBe("/");
    });

    it("trims whitespace", () => {
      expect(sanitizeBaseUrl("  /base/  ")).toBe("/base/");
    });

    it("prepends / for relative paths without leading slash", () => {
      expect(sanitizeBaseUrl("base")).toBe("/base");
      expect(sanitizeBaseUrl("path/to/something")).toBe("/path/to/something");
    });
  });

  describe("normalizeBaseUrl", () => {
    it("removes trailing slashes from relative paths", () => {
      expect(normalizeBaseUrl("/")).toBe("");
      expect(normalizeBaseUrl("/base/")).toBe("/base");
      expect(normalizeBaseUrl("/path///")).toBe("/path");
    });

    it("sanitizes and normalizes", () => {
      expect(normalizeBaseUrl("javascript:alert(1)")).toBe("");
      expect(normalizeBaseUrl("")).toBe("");
    });

    it("handles absolute URLs", () => {
      expect(normalizeBaseUrl("https://example.com/")).toBe("https://example.com");
    });
  });

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

    it("handles empty string by returning root", () => {
      expect(normalizePath("")).toBe("/");
    });

    it("preserves root path as single slash", () => {
      expect(normalizePath("/")).toBe("/");
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

    it("throws error when both section and slug are empty", () => {
      expect(() => buildEntryPath("/", "", "")).toThrow(
        "buildEntryPath requires at least one of section or slug to be non-empty"
      );
    });

    it("throws error when both section and slug are whitespace-only", () => {
      expect(() => buildEntryPath("/base/", "  ", "  ")).toThrow(
        "buildEntryPath requires at least one of section or slug to be non-empty"
      );
    });

    it("works when only section is provided", () => {
      expect(buildEntryPath("/", "mysql", "")).toBe("/mysql");
    });

    it("works when only slug is provided", () => {
      expect(buildEntryPath("/", "", "intro")).toBe("/intro");
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
