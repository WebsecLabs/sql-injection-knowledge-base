import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { initSearch } from "../../../src/scripts/search";

describe("search.ts", () => {
  let container: HTMLElement;
  let searchInput: HTMLInputElement;
  let searchStatus: HTMLElement;
  let noResults: HTMLElement;
  let initialSearch: HTMLElement;
  let resultsContainer: HTMLElement;

  /**
   * Helper to reset and re-initialize search with new data or URL params.
   * Clears the initialized flag so initSearch() runs fresh.
   */
  function reinitSearch() {
    delete container.dataset.initialized;
    initSearch();
  }

  const mockSearchData = [
    {
      slug: "intro",
      title: "Introduction to SQL Injection",
      description: "Learn the basics of SQL injection attacks",
      category: "Basics",
      tags: ["security", "basics"],
      collection: "mysql",
    },
    {
      slug: "union-attacks",
      title: "UNION-based SQL Injection",
      description: "Exploiting UNION queries",
      category: "Advanced",
      tags: ["union", "advanced"],
      collection: "mysql",
    },
    {
      slug: "blind-injection",
      title: "Blind SQL Injection",
      description: "Techniques for blind SQLi",
      category: "Advanced",
      tags: ["blind", "timing"],
      collection: "postgresql",
    },
    {
      slug: "stored-procedures",
      title: "Stored Procedure Attacks",
      description: "Attacking stored procedures",
      category: "Advanced",
      tags: ["procedures"],
      collection: "mssql",
    },
  ];

  beforeEach(() => {
    // Reset DOM
    document.body.innerHTML = "";

    // Create container with data attributes
    container = document.createElement("div");
    container.className = "search-results";
    container.dataset.baseUrl = "/";
    container.dataset.searchEntries = JSON.stringify(mockSearchData);

    // Create search input
    searchInput = document.createElement("input");
    searchInput.name = "q";
    searchInput.type = "text";

    // Create status elements
    searchStatus = document.createElement("div");
    searchStatus.id = "search-status";

    noResults = document.createElement("div");
    noResults.id = "no-results";
    noResults.style.display = "none";

    initialSearch = document.createElement("div");
    initialSearch.id = "initial-search";
    initialSearch.style.display = "block";

    resultsContainer = document.createElement("div");
    resultsContainer.id = "results-container";

    // Append elements to container
    container.appendChild(searchInput);
    container.appendChild(searchStatus);
    container.appendChild(noResults);
    container.appendChild(initialSearch);
    container.appendChild(resultsContainer);

    // Append container to body
    document.body.appendChild(container);

    // Mock window.location with only the 'search' property.
    // This partial mock is intentional - the search functionality only uses
    // window.location.search. Other Location properties (href, pathname, etc.)
    // are not accessed by the code under test.
    delete (window as { location?: Location }).location;
    (window as { location: Location }).location = {
      search: "",
    } as Location;
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  describe("initSearch", () => {
    it("initializes search functionality when container exists", () => {
      initSearch();

      expect(container.dataset.initialized).toBe("true");
      expect(searchStatus.getAttribute("aria-live")).toBe("polite");
    });

    it("does not initialize when container is missing", () => {
      document.body.innerHTML = "";
      const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

      initSearch();

      expect(consoleError).not.toHaveBeenCalled();
    });

    it("prevents duplicate initialization on same container", () => {
      initSearch();
      expect(container.dataset.initialized).toBe("true");

      // Modify something that would be reset on re-init
      searchStatus.setAttribute("aria-live", "assertive");

      initSearch();

      // Should not re-initialize, so aria-live should remain "assertive"
      expect(searchStatus.getAttribute("aria-live")).toBe("assertive");
    });

    it("logs error when search DOM elements are missing", () => {
      resultsContainer.remove();
      const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

      initSearch();

      expect(consoleError).toHaveBeenCalledWith("Missing search DOM elements");
      expect(container.dataset.initialized).toBeUndefined();
    });

    it("handles invalid JSON in search data gracefully", () => {
      container.dataset.searchEntries = "invalid json";
      const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

      initSearch();

      expect(consoleError).toHaveBeenCalledWith("Failed to parse search data");
      expect(container.dataset.initialized).toBe("true");
    });

    it("uses default base URL when not specified", () => {
      delete container.dataset.baseUrl;
      // Use URL parameter to trigger search immediately (bypasses debounce)
      (window as { location: Location }).location.search = "?q=intro";

      initSearch();

      // Verify the generated result links use "/" as the default base URL
      const html = resultsContainer.innerHTML;
      expect(html).toContain('href="/mysql/intro"');
    });

    it("sets aria-live attribute on search status element", () => {
      initSearch();

      expect(searchStatus.getAttribute("aria-live")).toBe("polite");
    });
  });

  describe("URL parameter parsing", () => {
    it("performs search when query parameter exists in URL", () => {
      (window as { location: Location }).location.search = "?q=union";

      initSearch();

      expect(searchInput.value).toBe("union");
      expect(searchStatus.textContent).toContain("Found 1 result");
      expect(initialSearch.style.display).toBe("none");
    });

    it("updates document title when query parameter exists", () => {
      (window as { location: Location }).location.search = "?q=injection";

      initSearch();

      expect(document.title).toContain('Search Results for "injection"');
      expect(document.title).toContain("SQL Injection KB");
    });

    it("truncates long queries in document title", () => {
      const longQuery = "a".repeat(60);
      (window as { location: Location }).location.search = `?q=${longQuery}`;

      initSearch();

      expect(document.title).toContain("…");
      // Title format: Search Results for "...truncated..." - SQL Injection KB
      // Just verify it's shorter than having the full query
      expect(document.title.length).toBeLessThan(longQuery.length + 35);
    });

    it("escapes control characters in document title", () => {
      (window as { location: Location }).location.search = "?q=test\x00\x1F\x7F";

      initSearch();

      expect(document.title).toBe('Search Results for "test" - SQL Injection KB');
    });

    it("performs initial empty search when no query parameter", () => {
      initSearch();

      expect(searchInput.value).toBe("");
      expect(initialSearch.style.display).toBe("block");
      expect(resultsContainer.innerHTML).toBe("");
    });
  });

  describe("performSearch", () => {
    it("displays initial search state when query is empty", () => {
      vi.useFakeTimers();
      initSearch();
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      // Trigger immediately without debounce
      vi.runAllTimers();

      expect(searchStatus.textContent).toBe("");
      expect(noResults.style.display).toBe("none");
      expect(initialSearch.style.display).toBe("block");
      expect(resultsContainer.innerHTML).toBe("");
    });

    it("finds results matching title", () => {
      (window as { location: Location }).location.search = "?q=UNION";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
      // Title will have highlighting: <mark>UNION</mark>-based SQL Injection
      expect(resultsContainer.innerHTML).toContain("-based SQL Injection");
    });

    it("finds results matching description", () => {
      (window as { location: Location }).location.search = "?q=basics";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
      expect(resultsContainer.innerHTML).toContain("Introduction to SQL Injection");
    });

    it("finds results matching category", () => {
      (window as { location: Location }).location.search = "?q=Advanced";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 3 result");
    });

    it("finds results matching tags", () => {
      (window as { location: Location }).location.search = "?q=timing";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
      expect(resultsContainer.innerHTML).toContain("Blind SQL Injection");
    });

    it("performs case-insensitive search", () => {
      (window as { location: Location }).location.search = "?q=BLIND";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
    });

    it("trims whitespace from query", () => {
      (window as { location: Location }).location.search = "?q=  union  ";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
    });

    it("displays no results when no matches found", () => {
      (window as { location: Location }).location.search = "?q=nonexistent";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 0 results");
      expect(noResults.style.display).toBe("block");
      expect(resultsContainer.innerHTML).toBe("");
    });

    it("uses singular 'result' for single match", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
      expect(searchStatus.textContent).not.toContain("results");
    });

    it("uses plural 'results' for multiple matches", () => {
      (window as { location: Location }).location.search = "?q=sql";
      initSearch();

      expect(searchStatus.textContent).toMatch(/Found \d+ results/);
    });

    it("hides initial search when performing search with query", () => {
      (window as { location: Location }).location.search = "?q=injection";

      initSearch();

      expect(initialSearch.style.display).toBe("none");
    });
  });

  describe("result grouping by collection", () => {
    it("groups results by collection", () => {
      (window as { location: Location }).location.search = "?q=Advanced";
      initSearch();

      const html = resultsContainer.innerHTML;

      // Should have sections for MySQL, PostgreSQL, and MSSQL
      expect(html).toContain("MySQL");
      expect(html).toContain("PostgreSQL");
      expect(html).toContain("MSSQL");
    });

    it("displays collection labels correctly", () => {
      (window as { location: Location }).location.search = "?q=injection";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain("MySQL");
    });

    it("shows count for each collection group", () => {
      (window as { location: Location }).location.search = "?q=Advanced";
      initSearch();

      const html = resultsContainer.innerHTML;

      // Each collection has 1 Advanced entry
      expect(html).toMatch(/MySQL.*\(1\)/s);
      expect(html).toMatch(/PostgreSQL.*\(1\)/s);
      expect(html).toMatch(/MSSQL.*\(1\)/s);
    });

    it("uses alternative labels from COLLECTION_SEARCH_LABELS", () => {
      // Add an "extras" collection entry
      container.dataset.searchEntries = JSON.stringify([
        ...mockSearchData,
        {
          slug: "resources",
          title: "Additional Resources",
          description: "Extra resources",
          category: "Resources",
          tags: [],
          collection: "extras",
        },
      ]);
      (window as { location: Location }).location.search = "?q=resources";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain("Other Resources");
    });
  });

  describe("highlightText", () => {
    it("highlights matching text in results", () => {
      (window as { location: Location }).location.search = "?q=UNION";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('<mark class="highlight-mark">');
      expect(html).toContain("UNION");
    });

    it("highlights multiple occurrences of search term", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "SQL SQL SQL",
          description: "SQL injection SQL",
          category: "Test",
          tags: [],
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=sql";
      initSearch();

      const html = resultsContainer.innerHTML;
      const markCount = (html.match(/<mark class="highlight-mark">/g) || []).length;
      expect(markCount).toBeGreaterThan(1);
    });

    it("performs case-insensitive highlighting", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('<mark class="highlight-mark">UNION</mark>');
    });

    it("escapes HTML in highlighted text", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "<script>alert('xss')</script>",
          description: "Test description",
          category: "Test",
          tags: [],
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=script";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).not.toContain("<script>");
      expect(html).toContain("&lt;");
      expect(html).toContain("&gt;");
    });

    it("does not highlight when query is empty", () => {
      vi.useFakeTimers();
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "Test Title",
          description: "Test description",
          category: "Test",
          tags: [],
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      // Clear search
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));
      vi.advanceTimersByTime(300);

      expect(resultsContainer.innerHTML).toBe("");
    });
  });

  describe("escapeControlChars", () => {
    it("removes control characters from document title", () => {
      (window as { location: Location }).location.search = "?q=test\x00\x01\x1F";
      initSearch();

      expect(document.title).toBe('Search Results for "test" - SQL Injection KB');
      expect(document.title).not.toContain("\x00");
      expect(document.title).not.toContain("\x01");
      expect(document.title).not.toContain("\x1F");
    });

    it("removes DEL character (0x7F)", () => {
      (window as { location: Location }).location.search = "?q=test\x7F";
      initSearch();

      expect(document.title).toBe('Search Results for "test" - SQL Injection KB');
      expect(document.title).not.toContain("\x7F");
    });

    it("removes extended control characters (0x80-0x9F)", () => {
      (window as { location: Location }).location.search = "?q=test\x80\x9F";
      initSearch();

      expect(document.title).toBe('Search Results for "test" - SQL Injection KB');
      expect(document.title).not.toContain("\x80");
      expect(document.title).not.toContain("\x9F");
    });
  });

  describe("debounce utility", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("debounces search input events", () => {
      initSearch();

      searchInput.value = "u";
      searchInput.dispatchEvent(new Event("input"));

      // Should not search immediately
      expect(resultsContainer.innerHTML).toBe("");

      searchInput.value = "un";
      searchInput.dispatchEvent(new Event("input"));

      searchInput.value = "uni";
      searchInput.dispatchEvent(new Event("input"));

      searchInput.value = "union";
      searchInput.dispatchEvent(new Event("input"));

      // Still should not have searched
      expect(resultsContainer.innerHTML).toBe("");

      // Fast-forward time by 300ms
      vi.advanceTimersByTime(300);

      // Now search should have executed
      expect(resultsContainer.innerHTML).toContain("-based SQL Injection");
    });

    it("cancels previous timeout when typing continues", () => {
      initSearch();

      searchInput.value = "test";
      searchInput.dispatchEvent(new Event("input"));

      // Advance time by 200ms (less than 300ms debounce)
      vi.advanceTimersByTime(200);

      // Type more
      searchInput.value = "test2";
      searchInput.dispatchEvent(new Event("input"));

      // Advance another 200ms
      vi.advanceTimersByTime(200);

      // Should not have executed the first search
      // Only after 300ms from the last input should it execute
      expect(resultsContainer.innerHTML).toBe("");

      // Advance another 100ms (total 300ms from last input)
      vi.advanceTimersByTime(100);

      // Now it should have searched for "test2"
      expect(searchStatus.textContent).toContain('for "test2"');
    });

    it("executes debounced function with latest arguments", () => {
      initSearch();

      searchInput.value = "first";
      searchInput.dispatchEvent(new Event("input"));

      vi.advanceTimersByTime(100);

      searchInput.value = "second";
      searchInput.dispatchEvent(new Event("input"));

      vi.advanceTimersByTime(100);

      searchInput.value = "union";
      searchInput.dispatchEvent(new Event("input"));

      vi.advanceTimersByTime(300);

      // Should search for "union", not "first" or "second"
      expect(resultsContainer.innerHTML).toContain("-based SQL Injection");
      expect(searchStatus.textContent).toContain('for "union"');
    });

    it("handles rapid input changes correctly", () => {
      initSearch();

      // Type rapidly
      for (let i = 0; i < 10; i++) {
        searchInput.value = "test" + i;
        searchInput.dispatchEvent(new Event("input"));
        vi.advanceTimersByTime(50);
      }

      // Should not have executed yet
      expect(resultsContainer.innerHTML).toBe("");

      // Wait for debounce
      vi.advanceTimersByTime(300);

      // Should have executed with the last value
      expect(searchStatus.textContent).toContain('for "test9"');
    });
  });

  describe("result rendering", () => {
    it("renders result cards with correct structure", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;

      expect(html).toContain('class="result-section"');
      expect(html).toContain('class="result-list"');
      expect(html).toContain('class="result-card"');
      expect(html).toContain('class="result-title"');
      expect(html).toContain('class="result-category"');
    });

    it("renders description when present", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('class="result-description"');
      // "UNION" is highlighted, so check for surrounding text
      expect(html).toContain("Exploiting");
      expect(html).toContain("queries");
    });

    it("does not render description element when description is missing", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "Test Entry",
          category: "Test",
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).not.toContain('class="result-description"');
    });

    it("renders tags when present", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('class="result-tags"');
      expect(html).toContain('class="tag"');
      expect(html).toContain("union");
      expect(html).toContain("advanced");
    });

    it("does not render tags element when tags are missing", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "Test Entry",
          category: "Test",
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).not.toContain('class="result-tags"');
    });

    it("builds correct href links", () => {
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('href="/mysql/union-attacks"');
    });

    it("uses custom base URL in href links", () => {
      container.dataset.baseUrl = "/sql-kb/";
      (window as { location: Location }).location.search = "?q=union";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).toContain('href="/sql-kb/mysql/union-attacks"');
    });

    it("escapes HTML in href attributes", () => {
      // Note: This test verifies that escapeHtml is called on href.
      // Due to jsdom innerHTML serialization quirks, we verify the href
      // contains the escaped quote character which proves escapeHtml ran.
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: 'test"quote',
          title: "Test",
          category: "Test",
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      reinitSearch();

      const html = resultsContainer.innerHTML;
      // The quote in the slug should be escaped
      expect(html).toContain("&quot;");
      // And the result should render without breaking the HTML structure
      expect(html).toContain('class="result-card"');
    });

    it("escapes HTML in category display", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "Test",
          category: '<img src=x onerror="alert(1)">',
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).not.toContain("<img src=x");
      expect(html).toContain("&lt;");
      expect(html).toContain("&gt;");
    });

    it("escapes HTML in tags", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "test",
          title: "Test",
          category: "Test",
          tags: ["<script>alert(1)</script>"],
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      const html = resultsContainer.innerHTML;
      expect(html).not.toContain("<script>");
      expect(html).toContain("&lt;");
    });
  });

  describe("accessibility", () => {
    it("sets aria-live=polite on search status", () => {
      initSearch();

      expect(searchStatus.getAttribute("aria-live")).toBe("polite");
    });

    it("updates search status with result count", () => {
      (window as { location: Location }).location.search = "?q=injection";
      initSearch();

      expect(searchStatus.textContent).toMatch(/Found \d+ result/);
      expect(searchStatus.textContent).toContain('for "injection"');
    });

    it("clears search status when query is empty", () => {
      vi.useFakeTimers();
      initSearch();

      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      vi.advanceTimersByTime(300);

      expect(searchStatus.textContent).toBe("");
    });
  });

  describe("edge cases", () => {
    it("handles empty search data array", () => {
      container.dataset.searchEntries = "[]";
      (window as { location: Location }).location.search = "?q=test";
      initSearch();

      expect(searchStatus.textContent).toContain("Found 0 results");
      expect(noResults.style.display).toBe("block");
    });

    it("handles entries with missing optional fields", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "minimal",
          title: "Minimal Entry",
          category: "Test",
          collection: "mysql",
        },
      ]);
      (window as { location: Location }).location.search = "?q=minimal";
      reinitSearch();

      expect(searchStatus.textContent).toContain("Found 1 result");
      // "Minimal" is highlighted, check for "Entry"
      expect(resultsContainer.innerHTML).toContain("Entry");
    });

    it("handles special characters in search query", () => {
      (window as { location: Location }).location.search = "?q=SQL%20Injection";
      initSearch();

      // "SQL Injection" appears in multiple entries (Introduction, UNION-based, Blind)
      expect(searchStatus.textContent).toContain("results");
    });

    it("handles very long search queries", () => {
      const longQuery = "a".repeat(1000);
      (window as { location: Location }).location.search = `?q=${longQuery}`;
      initSearch();

      expect(searchStatus.textContent).toContain("Found 0 results");
      expect(document.title).toContain("…");
    });

    it("handles entries with empty title", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "empty-title",
          title: "",
          category: "Test",
          collection: "mysql",
        },
      ]);
      // Search for "test" which should match on category "Test"
      (window as { location: Location }).location.search = "?q=test";

      initSearch();

      // Should not crash and should initialize successfully
      expect(container.dataset.initialized).toBe("true");

      // The entry should be found (matches on category "Test")
      expect(searchStatus.textContent).toContain("Found 1 result");

      // Verify the result card is rendered even with empty title
      const resultCard = resultsContainer.querySelector(".result-card");
      expect(resultCard).not.toBeNull();

      // The title element should exist but be empty
      const resultTitle = resultsContainer.querySelector(".result-title");
      expect(resultTitle).not.toBeNull();

      // The category should be displayed correctly
      const resultCategory = resultsContainer.querySelector(".result-category");
      expect(resultCategory).not.toBeNull();
      expect(resultCategory?.textContent).toContain("Test");
    });

    it("handles collection names not in COLLECTION_SEARCH_LABELS", () => {
      container.dataset.searchEntries = JSON.stringify([
        {
          slug: "unknown",
          title: "Unknown Collection",
          category: "Test",
          collection: "unknown-db",
        },
      ]);
      (window as { location: Location }).location.search = "?q=unknown";
      initSearch();

      const html = resultsContainer.innerHTML;
      // Should fall back to the collection name itself
      expect(html).toContain("unknown-db");
    });
  });
});
