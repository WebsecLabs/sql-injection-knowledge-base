/**
 * NavBar Script Module
 *
 * Handles navbar functionality including:
 * - Mobile menu toggle
 * - Dropdown menus (hover on desktop, click on mobile)
 * - Search functionality
 * - Resize handling for responsive behavior
 *
 * Supports Astro View Transitions by re-initializing on page navigation.
 */

import {
  NAVBAR_MOBILE_BREAKPOINT,
  DROPDOWN_MOBILE_MAX_HEIGHT,
  RESIZE_DEBOUNCE_MS,
  INIT_FALLBACK_DELAY_MS,
} from "../utils/uiConstants";
import { cloneAndReplace } from "../utils/domUtils";

// Global type declarations (only initializeNavbar needs to be global for View Transitions)
declare global {
  interface Window {
    initializeNavbar?: () => void;
    __navbarLastPath?: string;
  }
}

// Re-export for backward compatibility
export const MOBILE_BREAKPOINT = NAVBAR_MOBILE_BREAKPOINT;

// Module-level state for tracking (persists across View Transitions)
let navbarInitialized = false;
let prevIsMobile: boolean | undefined;
let navbarDocumentClickHandler: ((e: Event) => void) | null = null;
let navbarDropdownClickHandler: ((e: Event) => void) | null = null;

/**
 * Toggle dropdown expanded/collapsed state
 */
export function toggleDropdownState(dropdown: Element, toggle: Element): void {
  const isExpanded = dropdown.classList.toggle("show");
  if (toggle instanceof HTMLElement) {
    toggle.setAttribute("aria-expanded", String(isExpanded));
  }

  const menu = dropdown.querySelector(".dropdown-menu") as HTMLElement | null;
  if (!menu) {
    return;
  }

  if (window.innerWidth < MOBILE_BREAKPOINT) {
    menu.style.maxHeight = isExpanded ? DROPDOWN_MOBILE_MAX_HEIGHT : "0px";
  } else {
    menu.style.maxHeight = "";
  }
}

function collapseDropdown(dropdown: Element, isMobileView: boolean): void {
  dropdown.classList.remove("show");
  const toggle = dropdown.querySelector(".dropdown-toggle");
  if (toggle instanceof HTMLElement) {
    toggle.setAttribute("aria-expanded", "false");
  }

  const menu = dropdown.querySelector(".dropdown-menu") as HTMLElement | null;
  if (menu) {
    menu.style.maxHeight = isMobileView ? "0px" : "";
  }
}

function resetDatabaseSections(): void {
  document.querySelectorAll(".database-section").forEach((section) => {
    section.classList.remove("expanded");
    const header = section.querySelector(".database-section-header");
    if (header instanceof HTMLElement) {
      header.setAttribute("aria-expanded", "false");
    }
  });
}

// Main initialization function
window.initializeNavbar = function () {
  // Per-path deduplication: skip re-initialization if we're on the same path
  // This prevents redundant DOM cloning and handler re-attachment during same-route transitions
  const currentPath = window.location.pathname;
  if (window.__navbarLastPath === currentPath && navbarInitialized) {
    return;
  }

  // Initialize navbar functionality
  function initNavbar() {
    // Mobile menu toggle
    const mobileToggle = document.getElementById("mobile-toggle") as HTMLButtonElement | null;
    const navbarMenu = document.getElementById("navbar-menu");

    if (mobileToggle && navbarMenu && mobileToggle.parentNode) {
      // Clone the button to remove all existing event listeners
      const newMobileToggle = cloneAndReplace(mobileToggle) as HTMLButtonElement;

      // Add fresh event listener
      newMobileToggle.addEventListener("click", function (this: HTMLButtonElement, e) {
        e.preventDefault();
        e.stopPropagation();
        const isExpanded = this.getAttribute("aria-expanded") === "true";
        const nextExpanded = !isExpanded;
        this.setAttribute("aria-expanded", String(nextExpanded));
        navbarMenu.classList.toggle("active");
        this.classList.toggle("active");
      });
    }

    // Handle dropdown toggle on mobile and desktop differently
    const isMobile = window.innerWidth < MOBILE_BREAKPOINT;
    const dropdowns = Array.from(document.querySelectorAll(".dropdown"));

    // Clone dropdown containers to clear any existing hover/click handlers.
    // Return value is intentionally not captured because we re-query the DOM
    // below to get fresh references after all dropdowns have been cloned.
    dropdowns.forEach((dropdown) => {
      if (dropdown.parentNode) {
        cloneAndReplace(dropdown);
      }
    });

    // Re-query dropdowns to get fresh references after cloning
    const freshDropdowns = document.querySelectorAll(".dropdown");

    // Add fresh handlers to dropdowns
    freshDropdowns.forEach((dropdown) => {
      const toggle = dropdown.querySelector(".dropdown-toggle");
      if (!toggle) {
        return;
      }

      if (!isMobile) {
        // On desktop, show on hover
        dropdown.addEventListener("mouseenter", function (this: Element) {
          if (window.innerWidth < MOBILE_BREAKPOINT) {
            return;
          }
          this.classList.add("show");
        });

        dropdown.addEventListener("mouseleave", function (this: Element) {
          if (window.innerWidth < MOBILE_BREAKPOINT) {
            return;
          }
          this.classList.remove("show");
        });
      }
    });

    // Delegate dropdown toggle clicks to avoid stale handlers
    if (navbarDropdownClickHandler) {
      document.removeEventListener("click", navbarDropdownClickHandler, true);
    }

    navbarDropdownClickHandler = function (e) {
      const target = e.target as HTMLElement | null;
      const toggle = target?.closest(".dropdown-toggle") as HTMLElement | null;
      if (!toggle) {
        return;
      }

      const dropdown = toggle.closest(".dropdown");
      if (!dropdown) {
        return;
      }

      e.preventDefault();
      e.stopImmediatePropagation();

      const isMobileView = window.innerWidth < MOBILE_BREAKPOINT;

      // Close all other dropdowns
      document.querySelectorAll(".dropdown").forEach((other) => {
        if (other !== dropdown) {
          collapseDropdown(other, isMobileView);
        }
      });

      // On desktop: clicking always opens the dropdown (to avoid hover/click race condition)
      // The hover handlers also show/hide on desktop, but click ensures it opens
      // To close on desktop: hover away or click outside
      // On mobile: toggle behavior (since there's no hover)
      if (isMobileView) {
        // Mobile: toggle the dropdown
        toggleDropdownState(dropdown, toggle);
      } else {
        // Desktop: always open the dropdown on click
        // This avoids the race condition where:
        // 1. mouseenter adds "show" when mouse moves to click
        // 2. click would toggle it OFF if we used toggle behavior
        // Instead, clicking always ensures dropdown is visible
        // UPDATE: We now check aria-expanded to allow closing if already explicitly opened
        const isExpanded = toggle.getAttribute("aria-expanded") === "true";

        if (isExpanded) {
          // If already explicitly expanded, close it
          collapseDropdown(dropdown, false);
        } else {
          // If not explicitly expanded (even if open via hover), expand it explicitly
          dropdown.classList.add("show");
          // toggle is already narrowed to HTMLElement from the cast at line 153
          toggle.setAttribute("aria-expanded", "true");
          const menu = dropdown.querySelector(".dropdown-menu") as HTMLElement | null;
          if (menu) {
            menu.style.maxHeight = "";
          }
        }
      }
    };

    document.addEventListener("click", navbarDropdownClickHandler, true);

    // Close dropdowns when clicking outside
    // Remove any existing document click handler first
    if (navbarDocumentClickHandler) {
      document.removeEventListener("click", navbarDocumentClickHandler);
    }

    // Create and store the new handler
    navbarDocumentClickHandler = function (e) {
      const target = e.target as HTMLElement;
      if (target && !target.closest(".dropdown")) {
        const isMobileView = window.innerWidth < MOBILE_BREAKPOINT;
        document.querySelectorAll(".dropdown").forEach((dropdown) => {
          collapseDropdown(dropdown, isMobileView);
        });
      }
    };

    document.addEventListener("click", navbarDocumentClickHandler);

    // Check viewport boundaries when dropdown is first shown (hidden elements have zero dimensions)
    freshDropdowns.forEach((dropdown) => {
      dropdown.addEventListener(
        "mouseenter",
        function (this: Element) {
          const menu = this.querySelector(".dropdown-menu");
          if (menu) {
            const rect = menu.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
              menu.classList.add("dropdown-menu-right");
            }
          }
        },
        { once: true }
      );
    });

    // Handle database section toggles
    const databaseHeaders = document.querySelectorAll(".database-section-header");
    databaseHeaders.forEach((header) => {
      if (!header.parentNode) return;

      // Clone to remove existing listeners
      const newHeader = cloneAndReplace(header) as HTMLElement;

      newHeader.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();

        const section = this.closest(".database-section");
        if (section) {
          const isExpanded = section.classList.toggle("expanded");
          // Update aria-expanded for accessibility
          this.setAttribute("aria-expanded", String(isExpanded));
        }
      });
    });
  }

  // Initialize search functionality
  function initSearch() {
    const searchContainer = document.querySelector(".search-container") as HTMLElement | null;
    if (!searchContainer || !searchContainer.parentNode) {
      return;
    }

    const freshSearchContainer = cloneAndReplace(searchContainer) as HTMLElement;

    const searchForm = freshSearchContainer.querySelector(
      "#navbar-search-form"
    ) as HTMLFormElement | null;
    const searchInput = freshSearchContainer.querySelector(
      "#navbar-search-input"
    ) as HTMLInputElement | null;
    const searchIcon = freshSearchContainer.querySelector(".search-icon") as HTMLElement | null;

    if (!searchForm || !searchInput) {
      return;
    }

    // Make search icon clickable
    if (searchIcon) {
      searchIcon.addEventListener("click", function () {
        if (searchInput.value.trim()) {
          searchForm.submit();
        } else {
          searchInput.focus();
        }
      });
    }

    // Prevent empty searches - native Enter-to-submit behavior will trigger this handler
    searchForm.addEventListener("submit", function (e) {
      if (!searchInput.value.trim()) {
        e.preventDefault();
        searchInput.focus();
      }
    });
    // Note: Removed redundant keydown listener for Enter key.
    // Native Enter-to-submit behavior triggers the form's submit handler above,
    // which properly validates the input before submission.
  }

  // Handle window resize - only re-initialize when crossing the mobile/desktop breakpoint
  function handleResize() {
    const isMobile = window.innerWidth < MOBILE_BREAKPOINT;

    // Only re-initialize if we've crossed the breakpoint threshold
    if (prevIsMobile !== undefined && isMobile === prevIsMobile) {
      return; // No breakpoint change, skip re-initialization
    }

    prevIsMobile = isMobile;

    if (isMobile) {
      // On mobile, reset all dropdowns
      document.querySelectorAll(".dropdown").forEach((dropdown) => {
        collapseDropdown(dropdown, true);
      });
      resetDatabaseSections();

      // Re-initialize navbar to apply mobile behavior
      initNavbar();
    } else {
      // Close mobile menu if open
      const navbarMenu = document.getElementById("navbar-menu");
      const mobileToggle = document.getElementById("mobile-toggle") as HTMLButtonElement | null;

      if (navbarMenu && navbarMenu.classList.contains("active")) {
        navbarMenu.classList.remove("active");
        if (mobileToggle) {
          mobileToggle.classList.remove("active");
          mobileToggle.setAttribute("aria-expanded", "false");
        }
      }

      document.querySelectorAll(".dropdown").forEach((dropdown) => {
        collapseDropdown(dropdown, false);
      });
      resetDatabaseSections();

      // Re-initialize navbar to apply desktop behavior
      initNavbar();
    }
  }

  // Initialize everything
  // Set initial mobile state to ensure first resize only triggers on actual change
  prevIsMobile = window.innerWidth < MOBILE_BREAKPOINT;
  initNavbar();
  initSearch();

  // Update the last-initialized path after successful initialization
  window.__navbarLastPath = currentPath;

  // Set up resize listener only once
  if (!navbarInitialized) {
    navbarInitialized = true;
    let resizeTimer: ReturnType<typeof setTimeout>;
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(handleResize, RESIZE_DEBOUNCE_MS);
    });
  }
};

// Run initialization on various events

// 1. When DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", window.initializeNavbar);
} else {
  // DOM is already ready
  window.initializeNavbar();
}

// 2. On Astro page load (for View Transitions)
document.addEventListener("astro:page-load", window.initializeNavbar);

// 3. After page swap (for View Transitions)
document.addEventListener("astro:after-swap", window.initializeNavbar);

// 4. As a fallback, also run after a short delay - but only if not already initialized
// This prevents unnecessary re-initialization when DOMContentLoaded or immediate call already ran
setTimeout(() => {
  if (!navbarInitialized && window.initializeNavbar) {
    window.initializeNavbar();
  }
}, INIT_FALLBACK_DELAY_MS);
