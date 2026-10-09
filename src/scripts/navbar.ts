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
} from "../utils/uiConstants";
import {
  cloneAndReplace,
  debounce,
  withTransition,
  handleOpacityTransition,
} from "../utils/domUtils";

// Global type declarations (only initializeNavbar needs to be global for View Transitions)
declare global {
  interface Window {
    initializeNavbar?: () => void;
  }
}

// Re-export for backward compatibility
export const MOBILE_BREAKPOINT = NAVBAR_MOBILE_BREAKPOINT;

// Module-level state for tracking (persists across View Transitions)
let navbarInitialized = false;
let prevIsMobile: boolean | undefined;
let navbarDocumentClickHandler: ((e: Event) => void) | null = null;
let navbarDropdownClickHandler: ((e: Event) => void) | null = null;
let navbarKeydownRegistered = false;

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

/**
 * Close the mobile menu, mirroring the toggle button's behaviour.
 */
function closeMobileMenu(): void {
  const navbarMenu = document.getElementById("navbar-menu");
  const mobileToggle = document.getElementById("mobile-toggle");
  if (!navbarMenu || !mobileToggle || !navbarMenu.classList.contains("active")) {
    return;
  }
  withTransition(navbarMenu, "menu-transitioning", () => {
    mobileToggle.setAttribute("aria-expanded", "false");
    navbarMenu.classList.remove("active");
    mobileToggle.classList.remove("active");
    navbarMenu.inert = true;
  });
}

/**
 * Escape closes the innermost open navigation layer: an open dropdown first,
 * then the mobile menu. Focus returns to the control that opened it, so
 * keyboard users are not stranded inside a hidden menu (WCAG 1.4.13, 2.1.1).
 */
export function handleNavbarEscape(e: KeyboardEvent): void {
  if (e.key !== "Escape" || e.defaultPrevented) {
    return;
  }
  // The search dialog handles its own Escape
  if (document.querySelector("dialog[open]")) {
    return;
  }

  const isMobileView = window.innerWidth < MOBILE_BREAKPOINT;
  const openDropdown = document.querySelector(".dropdown.show");
  if (openDropdown) {
    const hadFocus = openDropdown.contains(document.activeElement);
    collapseDropdown(openDropdown, isMobileView);
    const toggle = openDropdown.querySelector(".dropdown-toggle");
    if (hadFocus && toggle instanceof HTMLElement) {
      toggle.focus();
    }
    e.preventDefault();
    return;
  }

  const navbarMenu = document.getElementById("navbar-menu");
  if (isMobileView && navbarMenu?.classList.contains("active")) {
    closeMobileMenu();
    document.getElementById("mobile-toggle")?.focus();
    e.preventDefault();
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
  // Skip re-initialization when this navbar element is already wired up.
  // Keyed to the DOM rather than the URL: a View Transition swap (even to the
  // same URL) brings in a fresh navbar that needs its handlers attached.
  const navbar = document.querySelector<HTMLElement>(".navbar");
  if (navbar?.dataset.navbarReady === "true" && navbarInitialized) {
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

      // Set initial inert state based on current menu visibility
      const isMobileView = window.innerWidth < MOBILE_BREAKPOINT;
      navbarMenu.inert = isMobileView && !navbarMenu.classList.contains("active");

      // Add fresh event listener
      newMobileToggle.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        const isExpanded = newMobileToggle.getAttribute("aria-expanded") === "true";
        const nextExpanded = !isExpanded;

        withTransition(navbarMenu, "menu-transitioning", () => {
          newMobileToggle.setAttribute("aria-expanded", String(nextExpanded));
          navbarMenu.classList.toggle("active");
          newMobileToggle.classList.toggle("active");
          navbarMenu.inert = !nextExpanded;
        });
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
        // On desktop, close when keyboard focus moves out of the dropdown
        dropdown.addEventListener("focusout", function (this: Element, e: Event) {
          const next = (e as FocusEvent).relatedTarget;
          if (next instanceof Node && this.contains(next)) {
            return;
          }
          if (this.classList.contains("show") && window.innerWidth >= MOBILE_BREAKPOINT) {
            collapseDropdown(this, false);
          }
        });

        // On desktop, show on hover with transitions enabled
        dropdown.addEventListener("mouseenter", function (this: Element) {
          if (window.innerWidth < MOBILE_BREAKPOINT) {
            return;
          }
          // Enable transitions during hover interaction
          this.classList.add("dropdown-transitioning");
          this.classList.add("show");
        });

        dropdown.addEventListener("mouseleave", function (this: Element) {
          if (window.innerWidth < MOBILE_BREAKPOINT) {
            return;
          }
          this.classList.remove("show");
          // Remove transitioning class after animation completes
          const menu = this.querySelector(".dropdown-menu");
          if (menu) {
            handleOpacityTransition(menu, this);
          } else {
            this.classList.remove("dropdown-transitioning");
          }
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

        // Enable transitions during click interaction
        dropdown.classList.add("dropdown-transitioning");

        if (isExpanded) {
          // If already explicitly expanded, close it
          collapseDropdown(dropdown, false);
          // Remove transitioning class after animation completes
          const menu = dropdown.querySelector(".dropdown-menu");
          if (menu) {
            handleOpacityTransition(menu, dropdown);
          }
        } else {
          // If not explicitly expanded (even if open via hover), expand it explicitly
          dropdown.classList.add("show");
          // toggle is already narrowed to HTMLElement from the earlier cast
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
          // Only process dropdowns that are currently shown
          // This prevents redundant calls and ensures transitions only run when needed
          if (dropdown.classList.contains("show")) {
            // Enable transitions for smooth close animation on desktop
            if (!isMobileView) {
              dropdown.classList.add("dropdown-transitioning");
              const menu = dropdown.querySelector(".dropdown-menu");
              if (menu) {
                handleOpacityTransition(menu, dropdown);
              }
            }
            collapseDropdown(dropdown, isMobileView);
          }
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

  // Handle window resize - only re-initialize when crossing the mobile/desktop breakpoint
  function handleResize() {
    const isMobile = window.innerWidth < MOBILE_BREAKPOINT;

    // Only re-initialize if we've crossed the breakpoint threshold
    if (prevIsMobile !== undefined && isMobile === prevIsMobile) {
      return; // No breakpoint change, skip re-initialization
    }

    prevIsMobile = isMobile;

    if (isMobile) {
      // On mobile, reset all dropdowns and remove any stuck transitioning classes
      document.querySelectorAll(".dropdown").forEach((dropdown) => {
        dropdown.classList.remove("dropdown-transitioning");
        collapseDropdown(dropdown, true);
      });
      resetDatabaseSections();

      // Re-initialize navbar to apply mobile behavior
      initNavbar();
    } else {
      // Close mobile menu if open
      const navbarMenu = document.getElementById("navbar-menu");
      const mobileToggle = document.getElementById("mobile-toggle") as HTMLButtonElement | null;

      if (navbarMenu) {
        // Always remove the transitioning class when switching to desktop
        // This safeguards against the class getting stuck if a resize happens during transition
        navbarMenu.classList.remove("menu-transitioning");

        if (navbarMenu.classList.contains("active")) {
          navbarMenu.classList.remove("active");
          if (mobileToggle) {
            mobileToggle.classList.remove("active");
            mobileToggle.setAttribute("aria-expanded", "false");
          }
        }

        // On desktop, menu is always visible so remove inert
        navbarMenu.inert = false;
      }

      // Reset all dropdowns and remove any stuck transitioning classes
      document.querySelectorAll(".dropdown").forEach((dropdown) => {
        dropdown.classList.remove("dropdown-transitioning");
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

  // Mark this navbar element as initialized
  if (navbar) {
    navbar.dataset.navbarReady = "true";
  }

  // Escape handling is document-level and independent of the swapped DOM
  if (!navbarKeydownRegistered) {
    navbarKeydownRegistered = true;
    document.addEventListener("keydown", handleNavbarEscape);
  }

  // Set up resize listener only once
  if (!navbarInitialized) {
    navbarInitialized = true;
    const debouncedHandleResize = debounce(handleResize, RESIZE_DEBOUNCE_MS);
    window.addEventListener("resize", debouncedHandleResize);
  }
};

// Run initialization on various events

// 1. When DOM is ready (for initial page load without View Transitions)
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", window.initializeNavbar);
} else {
  // DOM is already ready
  window.initializeNavbar();
}

// 2. On Astro page load (for View Transitions - fires after the new page is visible)
// Note: astro:after-swap is intentionally not used as it fires before the page is visible,
// and astro:page-load already covers View Transitions. The idempotency guards in
// initializeNavbar ensure multiple calls are safe.
document.addEventListener("astro:page-load", window.initializeNavbar);
