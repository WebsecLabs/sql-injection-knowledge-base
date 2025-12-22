import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { initSidebar } from "../../../src/scripts/sidebar";

describe("sidebar", () => {
  let container: HTMLDivElement;

  beforeEach(() => {
    // Create a realistic sidebar structure
    container = document.createElement("div");
    container.innerHTML = `
      <div class="sidebar">
        <input type="text" id="sidebar-search-input" />

        <div class="sidebar-section active">
          <div class="sidebar-heading" role="button" tabindex="0" aria-expanded="true">
            MySQL
          </div>
          <div class="sidebar-category">
            <div class="category-title">Basics</div>
            <nav class="sidebar-nav">
              <a href="/mysql/intro">Introduction</a>
              <a href="/mysql/basics">SQL Basics</a>
            </nav>
          </div>
          <div class="sidebar-category">
            <div class="category-title">Advanced</div>
            <nav class="sidebar-nav">
              <a href="/mysql/advanced">Advanced Techniques</a>
            </nav>
          </div>
        </div>

        <div class="sidebar-section">
          <div class="sidebar-heading" role="button" tabindex="0" aria-expanded="false">
            PostgreSQL
          </div>
          <div class="sidebar-category">
            <div class="category-title">Basics</div>
            <nav class="sidebar-nav">
              <a href="/postgresql/intro">PostgreSQL Intro</a>
              <a href="/postgresql/timing">Timing Attacks</a>
            </nav>
          </div>
        </div>

        <div class="sidebar-section">
          <div class="sidebar-heading" role="button" tabindex="0" aria-expanded="false">
            Oracle
          </div>
          <div class="sidebar-category">
            <div class="category-title">Basics</div>
            <nav class="sidebar-nav">
              <a href="/oracle/intro">Oracle Intro</a>
            </nav>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(container);
  });

  afterEach(() => {
    // Deterministic cleanup: remove() is a no-op per DOM spec if element is already detached
    // No try/catch needed - any real errors should surface in tests
    if (container) {
      container.remove();
    }
  });

  describe("initSidebar", () => {
    it("attaches click handlers to all sidebar headings", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      expect(headings).toHaveLength(3);

      initSidebar();

      const firstSection = headings[0].closest(".sidebar-section");
      expect(firstSection?.classList.contains("active")).toBe(true);

      // Click to toggle off
      (headings[0] as HTMLElement).click();
      expect(firstSection?.classList.contains("active")).toBe(false);
    });

    it("attaches keydown handlers to all sidebar headings", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      initSidebar();

      const firstSection = headings[0].closest(".sidebar-section");
      expect(firstSection?.classList.contains("active")).toBe(true);

      // Trigger Enter key
      const enterEvent = new KeyboardEvent("keydown", { key: "Enter" });
      headings[0].dispatchEvent(enterEvent);
      expect(firstSection?.classList.contains("active")).toBe(false);
    });

    it("attaches input handler to search input", () => {
      const searchInput = document.getElementById("sidebar-search-input") as HTMLInputElement;
      expect(searchInput).toBeTruthy();

      initSidebar();

      // Initially, all links should be visible
      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      links.forEach((link) => {
        expect(link.style.display).toBe("");
      });

      // Trigger search
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      // Only matching link should be visible
      const timingLink = Array.from(links).find((link) => link.textContent?.includes("Timing"));
      expect(timingLink?.style.display).toBe("");

      const nonMatchingLinks = Array.from(links).filter(
        (link) => !link.textContent?.toLowerCase().includes("timing")
      );
      nonMatchingLinks.forEach((link) => {
        expect(link.style.display).toBe("none");
      });
    });

    it("removes previous event listeners before adding new ones", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstSection = headings[0].closest(".sidebar-section");

      // Get initial state before any initialization
      const initiallyActive = firstSection?.classList.contains("active");
      expect(initiallyActive).toBe(true); // First section starts active

      // Initialize sidebar twice to verify no duplicate handlers
      initSidebar();
      initSidebar();

      // Click the heading once
      (headings[0] as HTMLElement).click();

      // If duplicate handlers were attached, the section would toggle twice
      // (active -> inactive -> active), ending up in the original state.
      // With proper cleanup, it toggles exactly once (active -> inactive).
      const afterClickActive = firstSection?.classList.contains("active");
      expect(afterClickActive).toBe(false);

      // Click again to verify toggle still works correctly
      (headings[0] as HTMLElement).click();
      expect(firstSection?.classList.contains("active")).toBe(true);
    });

    it("handles missing search input gracefully", () => {
      const searchInput = document.getElementById("sidebar-search-input");
      searchInput?.remove();

      // Should not throw
      expect(() => initSidebar()).not.toThrow();
    });
  });

  describe("toggleSection", () => {
    beforeEach(() => {
      initSidebar();
    });

    it("toggles active class when clicking heading", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstSection = headings[0].closest(".sidebar-section");
      const secondSection = headings[1].closest(".sidebar-section");

      expect(firstSection?.classList.contains("active")).toBe(true);
      expect(secondSection?.classList.contains("active")).toBe(false);

      // Click first heading to close
      (headings[0] as HTMLElement).click();
      expect(firstSection?.classList.contains("active")).toBe(false);

      // Click second heading to open
      (headings[1] as HTMLElement).click();
      expect(secondSection?.classList.contains("active")).toBe(true);
    });

    it("updates aria-expanded attribute when toggling", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstHeading = headings[0] as HTMLElement;

      expect(firstHeading.getAttribute("aria-expanded")).toBe("true");

      // Click to close
      firstHeading.click();
      expect(firstHeading.getAttribute("aria-expanded")).toBe("false");

      // Click to open
      firstHeading.click();
      expect(firstHeading.getAttribute("aria-expanded")).toBe("true");
    });

    it("only affects the closest section", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const sections = document.querySelectorAll(".sidebar-section");

      // Click second heading
      (headings[1] as HTMLElement).click();

      // Only second section should be affected
      expect(sections[0].classList.contains("active")).toBe(true);
      expect(sections[1].classList.contains("active")).toBe(true);
      expect(sections[2].classList.contains("active")).toBe(false);
    });
  });

  describe("handleKeyDown", () => {
    beforeEach(() => {
      initSidebar();
    });

    it("toggles section when Enter key is pressed", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstSection = headings[0].closest(".sidebar-section");

      expect(firstSection?.classList.contains("active")).toBe(true);

      const enterEvent = new KeyboardEvent("keydown", { key: "Enter" });
      headings[0].dispatchEvent(enterEvent);

      expect(firstSection?.classList.contains("active")).toBe(false);
    });

    it("toggles section when Space key is pressed", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstSection = headings[0].closest(".sidebar-section");

      expect(firstSection?.classList.contains("active")).toBe(true);

      const spaceEvent = new KeyboardEvent("keydown", { key: " " });
      headings[0].dispatchEvent(spaceEvent);

      expect(firstSection?.classList.contains("active")).toBe(false);
    });

    it("prevents default behavior for Enter and Space keys", () => {
      const headings = document.querySelectorAll(".sidebar-heading");

      // cancelable: true is required for preventDefault() to have effect in jsdom
      const enterEvent = new KeyboardEvent("keydown", { key: "Enter", cancelable: true });
      const preventDefaultSpy = vi.spyOn(enterEvent, "preventDefault");
      headings[0].dispatchEvent(enterEvent);
      expect(preventDefaultSpy).toHaveBeenCalled();

      const spaceEvent = new KeyboardEvent("keydown", { key: " ", cancelable: true });
      const spacePreventDefaultSpy = vi.spyOn(spaceEvent, "preventDefault");
      headings[0].dispatchEvent(spaceEvent);
      expect(spacePreventDefaultSpy).toHaveBeenCalled();
    });

    it("does not toggle for other keys", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstSection = headings[0].closest(".sidebar-section");
      const initialState = firstSection?.classList.contains("active");

      const arrowEvent = new KeyboardEvent("keydown", { key: "ArrowDown" });
      headings[0].dispatchEvent(arrowEvent);

      expect(firstSection?.classList.contains("active")).toBe(initialState);

      const tabEvent = new KeyboardEvent("keydown", { key: "Tab" });
      headings[0].dispatchEvent(tabEvent);

      expect(firstSection?.classList.contains("active")).toBe(initialState);
    });

    it("updates aria-expanded on keyboard toggle", () => {
      const headings = document.querySelectorAll(".sidebar-heading");
      const firstHeading = headings[0] as HTMLElement;

      expect(firstHeading.getAttribute("aria-expanded")).toBe("true");

      const enterEvent = new KeyboardEvent("keydown", { key: "Enter" });
      headings[0].dispatchEvent(enterEvent);

      expect(firstHeading.getAttribute("aria-expanded")).toBe("false");
    });
  });

  describe("handleSearch", () => {
    let searchInput: HTMLInputElement;

    beforeEach(() => {
      initSidebar();
      searchInput = document.getElementById("sidebar-search-input") as HTMLInputElement;
    });

    it("resets display when search term is less than 2 characters", () => {
      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const categories = document.querySelectorAll<HTMLElement>(".sidebar-category");

      // First, perform a search
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      // Some links should be hidden
      const hiddenLinks = Array.from(links).filter((link) => link.style.display === "none");
      expect(hiddenLinks.length).toBeGreaterThan(0);

      // Reset with short search
      searchInput.value = "t";
      searchInput.dispatchEvent(new Event("input"));

      // All elements should have empty display style
      links.forEach((link) => {
        expect(link.style.display).toBe("");
      });
      categories.forEach((category) => {
        expect(category.style.display).toBe("");
      });
    });

    it("resets display when search term is empty", () => {
      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");

      // Perform a search
      searchInput.value = "oracle";
      searchInput.dispatchEvent(new Event("input"));

      // Reset with empty search
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      links.forEach((link) => {
        expect(link.style.display).toBe("");
      });
    });

    it("filters links by search term (case-insensitive)", () => {
      searchInput.value = "TIMING";
      searchInput.dispatchEvent(new Event("input"));

      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const timingLink = Array.from(links).find((link) =>
        link.textContent?.toLowerCase().includes("timing")
      );
      const nonTimingLinks = Array.from(links).filter(
        (link) => !link.textContent?.toLowerCase().includes("timing")
      );

      expect(timingLink?.style.display).toBe("");
      nonTimingLinks.forEach((link) => {
        expect(link.style.display).toBe("none");
      });
    });

    it("trims whitespace from search term", () => {
      searchInput.value = "  timing  ";
      searchInput.dispatchEvent(new Event("input"));

      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const timingLink = Array.from(links).find((link) =>
        link.textContent?.toLowerCase().includes("timing")
      );

      expect(timingLink?.style.display).toBe("");
    });

    it("shows parent category when child link matches", () => {
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      const timingLink = Array.from(document.querySelectorAll<HTMLElement>(".sidebar-nav a")).find(
        (link) => link.textContent?.toLowerCase().includes("timing")
      );

      const category = timingLink?.closest<HTMLElement>(".sidebar-category");
      expect(category?.style.display).toBe("");
    });

    it("hides categories with no matching links", () => {
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      const categories = document.querySelectorAll<HTMLElement>(".sidebar-category");
      const categoriesWithoutTiming = Array.from(categories).filter((category) => {
        const links = category.querySelectorAll<HTMLElement>(".sidebar-nav a");
        return !Array.from(links).some((link) =>
          link.textContent?.toLowerCase().includes("timing")
        );
      });

      categoriesWithoutTiming.forEach((category) => {
        expect(category.style.display).toBe("none");
      });
    });

    it("expands all sections when searching", () => {
      const sections = document.querySelectorAll(".sidebar-section");

      // Initially some sections are collapsed
      expect(sections[1].classList.contains("active")).toBe(false);
      expect(sections[2].classList.contains("active")).toBe(false);

      searchInput.value = "intro";
      searchInput.dispatchEvent(new Event("input"));

      // All sections should be expanded
      sections.forEach((section) => {
        expect(section.classList.contains("active")).toBe(true);
      });
    });

    it("sets aria-expanded to true on all headings when searching", () => {
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");

      searchInput.value = "intro";
      searchInput.dispatchEvent(new Event("input"));

      headings.forEach((heading) => {
        expect(heading.getAttribute("aria-expanded")).toBe("true");
      });
    });

    it("restores previous active states when clearing search", () => {
      const sections = document.querySelectorAll<HTMLElement>(".sidebar-section");
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");

      // Remember initial states
      const initialStates = Array.from(sections).map((s) => s.classList.contains("active"));

      // Perform search (expands all)
      searchInput.value = "intro";
      searchInput.dispatchEvent(new Event("input"));

      // All should be expanded
      sections.forEach((section) => {
        expect(section.classList.contains("active")).toBe(true);
      });

      // Clear search
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      // Should restore to initial states
      sections.forEach((section, index) => {
        expect(section.classList.contains("active")).toBe(initialStates[index]);
      });

      // aria-expanded should also be restored
      headings.forEach((heading, index) => {
        expect(heading.getAttribute("aria-expanded")).toBe(initialStates[index] ? "true" : "false");
      });
    });

    it("syncs aria-expanded with active state on reset", () => {
      const sections = document.querySelectorAll<HTMLElement>(".sidebar-section");
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");

      // Perform search
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      // Clear search
      searchInput.value = "x";
      searchInput.dispatchEvent(new Event("input"));

      // Check sync
      sections.forEach((section, index) => {
        const heading = headings[index];
        const isActive = section.classList.contains("active");
        const ariaExpanded = heading.getAttribute("aria-expanded");
        expect(ariaExpanded).toBe(isActive ? "true" : "false");
      });
    });

    it("preserves wasActive data only on first search", () => {
      const sections = document.querySelectorAll<HTMLElement>(".sidebar-section");

      // First search
      searchInput.value = "intro";
      searchInput.dispatchEvent(new Event("input"));

      // Check that wasActive is set
      const activeSection = sections[0];
      expect(activeSection.dataset.wasActive).toBe("true");

      // Modify search without clearing
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      // wasActive should still exist (not reset)
      expect(activeSection.dataset.wasActive).toBe("true");

      // Clear search
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      // wasActive should be removed - explicitly check the attribute is not present
      expect("wasActive" in activeSection.dataset).toBe(false);
    });

    it("handles search with no matches", () => {
      searchInput.value = "nonexistent";
      searchInput.dispatchEvent(new Event("input"));

      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const categories = document.querySelectorAll<HTMLElement>(".sidebar-category");

      // All links should be hidden
      links.forEach((link) => {
        expect(link.style.display).toBe("none");
      });

      // All categories should be hidden
      categories.forEach((category) => {
        expect(category.style.display).toBe("none");
      });
    });

    it("handles search with substring matching", () => {
      // Sidebar uses simple includes() matching, not word-by-word
      searchInput.value = "sql bas";
      searchInput.dispatchEvent(new Event("input"));

      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const sqlBasicsLink = Array.from(links).find((link) =>
        link.textContent?.toLowerCase().includes("sql bas")
      );

      // "SQL Basics" contains "sql bas" as substring
      expect(sqlBasicsLink?.style.display).toBe("");
    });

    it("handles partial word matching", () => {
      searchInput.value = "advan";
      searchInput.dispatchEvent(new Event("input"));

      const links = document.querySelectorAll<HTMLElement>(".sidebar-nav a");
      const advancedLink = Array.from(links).find((link) =>
        link.textContent?.toLowerCase().includes("advanced")
      );

      expect(advancedLink?.style.display).toBe("");
    });

    it("resets sections to collapsed if they were not active before search", () => {
      const sections = document.querySelectorAll<HTMLElement>(".sidebar-section");

      // Second section starts collapsed
      expect(sections[1].classList.contains("active")).toBe(false);

      // Perform search
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      // All expanded during search
      expect(sections[1].classList.contains("active")).toBe(true);

      // Clear search
      searchInput.value = "";
      searchInput.dispatchEvent(new Event("input"));

      // Should go back to collapsed
      expect(sections[1].classList.contains("active")).toBe(false);
    });

    it("handles consecutive searches correctly", () => {
      // First search
      searchInput.value = "intro";
      searchInput.dispatchEvent(new Event("input"));

      const introLinks = Array.from(
        document.querySelectorAll<HTMLElement>(".sidebar-nav a")
      ).filter((link) => link.textContent?.toLowerCase().includes("intro"));

      introLinks.forEach((link) => {
        expect(link.style.display).toBe("");
      });

      // Second search
      searchInput.value = "timing";
      searchInput.dispatchEvent(new Event("input"));

      const timingLinks = Array.from(
        document.querySelectorAll<HTMLElement>(".sidebar-nav a")
      ).filter((link) => link.textContent?.toLowerCase().includes("timing"));

      const nonTimingLinks = Array.from(
        document.querySelectorAll<HTMLElement>(".sidebar-nav a")
      ).filter((link) => !link.textContent?.toLowerCase().includes("timing"));

      timingLinks.forEach((link) => {
        expect(link.style.display).toBe("");
      });

      nonTimingLinks.forEach((link) => {
        expect(link.style.display).toBe("none");
      });
    });
  });

  describe("aria-expanded attribute updates", () => {
    beforeEach(() => {
      initSidebar();
    });

    it("initializes with correct aria-expanded values", () => {
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");

      expect(headings[0].getAttribute("aria-expanded")).toBe("true");
      expect(headings[1].getAttribute("aria-expanded")).toBe("false");
      expect(headings[2].getAttribute("aria-expanded")).toBe("false");
    });

    it("maintains aria-expanded sync during multiple toggles", () => {
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");
      const section = headings[0].closest(".sidebar-section");

      for (let i = 0; i < 5; i++) {
        (headings[0] as HTMLElement).click();
        const isActive = section?.classList.contains("active");
        expect(headings[0].getAttribute("aria-expanded")).toBe(isActive ? "true" : "false");
      }
    });

    it("updates aria-expanded independently for each section", () => {
      const headings = document.querySelectorAll<HTMLElement>(".sidebar-heading");

      (headings[0] as HTMLElement).click();
      (headings[1] as HTMLElement).click();

      expect(headings[0].getAttribute("aria-expanded")).toBe("false");
      expect(headings[1].getAttribute("aria-expanded")).toBe("true");
      expect(headings[2].getAttribute("aria-expanded")).toBe("false");
    });
  });
});
