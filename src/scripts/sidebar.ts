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
    // Reset all elements if search term is too short
    document.querySelectorAll<HTMLElement>(".sidebar-nav a, .sidebar-category").forEach((el) => {
      el.style.display = "";
    });

    // Restore previous active states with aria-expanded sync
    document.querySelectorAll<HTMLElement>(".sidebar-section").forEach((section) => {
      if (section.dataset.wasActive === "true") {
        section.classList.add("active");
        const heading = section.querySelector<HTMLElement>(".sidebar-heading");
        if (heading) {
          heading.setAttribute("aria-expanded", "true");
        }
        delete section.dataset.wasActive;
      } else if (!section.classList.contains("active")) {
        // Ensure collapsed sections have aria-expanded="false"
        const heading = section.querySelector<HTMLElement>(".sidebar-heading");
        if (heading) {
          heading.setAttribute("aria-expanded", "false");
        }
      }
    });

    return;
  }

  // Remember which sections were active before searching
  document.querySelectorAll<HTMLElement>(".sidebar-section.active").forEach((section) => {
    section.dataset.wasActive = "true";
  });

  // Hide all categories initially
  document.querySelectorAll<HTMLElement>(".sidebar-category").forEach((category) => {
    category.style.display = "none";
  });

  // Hide all items initially
  document.querySelectorAll<HTMLElement>(".sidebar-nav a").forEach((link) => {
    link.style.display = "none";
  });

  // Expand all sections for search
  document.querySelectorAll(".sidebar-section").forEach((section) => {
    section.classList.add("active");
    const heading = section.querySelector(".sidebar-heading");
    if (heading) {
      heading.setAttribute("aria-expanded", "true");
    }
  });

  // Show matching items
  document.querySelectorAll<HTMLAnchorElement>(".sidebar-nav a").forEach((link) => {
    const text = link.textContent?.toLowerCase() || "";

    if (text.includes(searchTerm)) {
      link.style.display = "";
      const category = link.closest<HTMLElement>(".sidebar-category");
      if (category) category.style.display = "";
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
