/**
 * Sidebar functionality for the SQL Injection Knowledge Base
 */

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

const handleKeyDown = (e: Event): void => {
  const keyEvent = e as KeyboardEvent;
  if (keyEvent.key === "Enter" || keyEvent.key === " ") {
    keyEvent.preventDefault();
    toggleSection(e);
  }
};

const handleSearch = (e: Event): void => {
  const input = e.currentTarget as HTMLInputElement;
  const searchTerm = input.value.toLowerCase().trim();

  if (searchTerm.length < 2) {
    // Exit filtering mode - CSS will restore visibility
    document.body.classList.remove("sidebar-filtering");

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

  // Clear previous matches
  document.querySelectorAll<HTMLElement>("[data-match]").forEach((el) => {
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
  document.querySelectorAll<HTMLAnchorElement>(".sidebar-nav a").forEach((link) => {
    const text = link.textContent?.toLowerCase() || "";

    if (text.includes(searchTerm)) {
      link.setAttribute("data-match", "");
      const category = link.closest<HTMLElement>(".sidebar-category");
      if (category) category.setAttribute("data-match", "");
    }
  });
};

export function initSidebar(): void {
  // Add click handlers to sidebar headings
  const headings = document.querySelectorAll(".sidebar-heading");
  headings.forEach((heading) => {
    heading.removeEventListener("click", toggleSection);
    heading.addEventListener("click", toggleSection);

    heading.removeEventListener("keydown", handleKeyDown);
    heading.addEventListener("keydown", handleKeyDown);
  });

  // Search functionality
  const searchInput = document.getElementById("sidebar-search-input") as HTMLInputElement | null;
  if (searchInput) {
    searchInput.removeEventListener("input", handleSearch);
    searchInput.addEventListener("input", handleSearch);
  }
}
