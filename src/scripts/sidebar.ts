/**
 * Sidebar functionality for the SQL Injection Knowledge Base
 */

import { debounce } from "../utils/domUtils";

// Module-level handlers with stable references (no `this` binding issues)
const toggleSection = (e: Event): void => {
  const heading = e.currentTarget as HTMLElement;
  const section = heading.closest(".sidebar-section");
  if (section) {
    section.classList.toggle("active");
    const isExpanded = section.classList.contains("active");
    heading.setAttribute("aria-expanded", isExpanded ? "true" : "false");
  }
};

const handleSearch = (): void => {
  const input = document.getElementById("sidebar-search-input") as HTMLInputElement | null;
  if (!input) return;
  const searchTerm = input.value.toLowerCase().trim();

  const emptyState = document.getElementById("sidebar-search-empty");

  if (searchTerm.length < 2) {
    // Exit filtering mode - CSS will restore visibility
    document.body.classList.remove("sidebar-filtering");

    // Hide empty state
    if (emptyState) emptyState.hidden = true;

    // Clean up data-match attributes
    document
      .querySelectorAll<HTMLElement>(".sidebar-nav a[data-match], .sidebar-category[data-match]")
      .forEach((el) => {
        el.removeAttribute("data-match");
      });

    // Restore previous active states with aria-expanded sync
    document.querySelectorAll<HTMLElement>(".sidebar-section").forEach((section) => {
      const heading = section.querySelector<HTMLElement>(".sidebar-heading");
      if (section.dataset.wasActive === "true") {
        section.classList.add("active");
        if (heading) {
          heading.setAttribute("aria-expanded", "true");
        }
        delete section.dataset.wasActive;
      } else {
        // Section was not active before search, collapse it
        section.classList.remove("active");
        if (heading) {
          heading.setAttribute("aria-expanded", "false");
        }
      }
    });

    return;
  }

  // Remember which sections were active before searching (only on first search)
  if (!document.querySelector(".sidebar-section[data-was-active]")) {
    document.querySelectorAll<HTMLElement>(".sidebar-section.active").forEach((section) => {
      section.dataset.wasActive = "true";
    });
  }

  // Enter filtering mode - CSS hides all non-matching elements
  document.body.classList.add("sidebar-filtering");

  // Clear previous matches (scoped to sidebar)
  document
    .querySelectorAll<HTMLElement>(".sidebar-nav a[data-match], .sidebar-category[data-match]")
    .forEach((el) => {
      el.removeAttribute("data-match");
    });

  // Expand all sections for search
  document.querySelectorAll(".sidebar-section").forEach((section) => {
    section.classList.add("active");
    const heading = section.querySelector(".sidebar-heading");
    if (heading) {
      heading.setAttribute("aria-expanded", "true");
    }
  });

  // Mark matching items with data-match attribute
  let matchCount = 0;
  document.querySelectorAll<HTMLAnchorElement>(".sidebar-nav a").forEach((link) => {
    const text = link.textContent?.toLowerCase() || "";

    if (text.includes(searchTerm)) {
      link.setAttribute("data-match", "");
      matchCount++;
      const category = link.closest<HTMLElement>(".sidebar-category");
      if (category) category.setAttribute("data-match", "");
    }
  });

  // Show or hide empty state based on results
  if (emptyState) {
    emptyState.hidden = matchCount > 0;
  }
};

const debouncedSearch = debounce(handleSearch, 150);

export function initSidebar(): void {
  // Add click handlers to sidebar headings
  const headings = document.querySelectorAll(".sidebar-heading");
  headings.forEach((heading) => {
    heading.removeEventListener("click", toggleSection);
    heading.addEventListener("click", toggleSection);
  });

  // Search functionality with debounce to reduce DOM thrashing
  const searchInput = document.getElementById("sidebar-search-input") as HTMLInputElement | null;
  if (searchInput) {
    searchInput.removeEventListener("input", debouncedSearch);
    searchInput.addEventListener("input", debouncedSearch);
  }
}
