/**
 * Main TypeScript file for the SQL Injection Knowledge Base
 *
 * Orchestrates initialization of:
 * - Sidebar functionality (mobile toggle, resize handling)
 * - Code block copy buttons
 * - Theme toggle
 * - Accessibility fixes
 */

import { initSidebar } from "./sidebar";
import { addCopyButtons } from "./copyCode";
import { setupThemeToggle } from "./themeToggle";
import {
  SIDEBAR_MOBILE_BREAKPOINT,
  SCROLL_HIDE_THRESHOLD,
  SIDEBAR_ATTENTION_DELAY_MS,
  RESIZE_DEBOUNCE_MS,
} from "../utils/uiConstants";
import { cloneAndReplace } from "../utils/domUtils";

// Make this a module
export {};

// Define types for global window properties (only initializeSidebar needs to be global for View Transitions)
declare global {
  interface Window {
    initializeSidebar: () => void;
  }
}

// Module-level state for tracking listener registration (persists across View Transitions)
let lastInitializedPath: string | null = null;
let sidebarResizeListenerAdded = false;
let sidebarScrollListenerAdded = false;
let overlayListenerAdded = false;
let escapeListenerAdded = false;
let resizeDebounceTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Remove tabindex from pre elements for accessibility.
 * Prevents keyboard focus on code blocks that shouldn't be interactive.
 */
function removeTabindexFromPreElements(): void {
  document.querySelectorAll("pre[tabindex]").forEach((pre) => {
    pre.removeAttribute("tabindex");
  });

  document.querySelectorAll(".astro-code[tabindex]").forEach((element) => {
    element.removeAttribute("tabindex");
  });
}

/**
 * Set up mobile sidebar visibility based on viewport.
 */
function initializeSidebarVisibility(
  sidebar: HTMLElement | null,
  buttonContainer: HTMLElement | null
): void {
  if (!sidebar) return;

  if (window.innerWidth > SIDEBAR_MOBILE_BREAKPOINT) {
    sidebar.style.transform = "";
    if (buttonContainer) buttonContainer.style.display = "none";
  } else {
    if (buttonContainer) buttonContainer.style.display = "block";
  }
}

/**
 * Add attention animation to hamburger button on mobile.
 * Uses isConnected checks to avoid operating on detached elements after View Transitions.
 */
function addMobileButtonAttention(toggleButton: HTMLElement | null): void {
  if (!toggleButton || window.innerWidth > SIDEBAR_MOBILE_BREAKPOINT) return;

  setTimeout(() => {
    // Check element is still in DOM before modifying (View Transitions may have removed it)
    if (!toggleButton.isConnected) return;
    toggleButton.classList.add("attention");
    setTimeout(() => {
      if (!toggleButton.isConnected) return;
      toggleButton.classList.remove("attention");
    }, SIDEBAR_ATTENTION_DELAY_MS);
  }, SIDEBAR_ATTENTION_DELAY_MS);
}

/**
 * Set up window resize handler for sidebar responsiveness.
 * Re-queries DOM inside handler to avoid stale references after View Transitions.
 */
function setupResizeHandler(): void {
  if (sidebarResizeListenerAdded) return;
  sidebarResizeListenerAdded = true;

  window.addEventListener("resize", function () {
    // Debounce resize handler to avoid excessive DOM updates
    if (resizeDebounceTimer) {
      clearTimeout(resizeDebounceTimer);
    }

    resizeDebounceTimer = setTimeout(() => {
      // Re-query current DOM elements to handle View Transitions
      const currentButtonContainer = document.querySelector(
        ".button-container"
      ) as HTMLElement | null;
      const currentSidebar = document.querySelector(".sidebar") as HTMLElement | null;
      const currentOverlay = document.getElementById("sidebar-overlay");

      if (!currentButtonContainer) return;

      if (window.innerWidth > SIDEBAR_MOBILE_BREAKPOINT) {
        currentButtonContainer.style.display = "none";
        if (currentSidebar) {
          currentSidebar.classList.remove("mobile-open");
          document.body.style.overflow = "";
        }
        if (currentOverlay) {
          currentOverlay.classList.remove("active");
        }
      } else {
        currentButtonContainer.style.display = "block";
      }
    }, RESIZE_DEBOUNCE_MS);
  });
}

/**
 * Set up scroll handler to hide/show mobile toggle button.
 * The handler is always attached but only takes action on mobile viewports.
 * This ensures the behavior works correctly when resizing from desktop to mobile.
 */
function setupScrollHandler(buttonContainer: HTMLElement | null): void {
  if (!buttonContainer) return;
  if (sidebarScrollListenerAdded) return;

  sidebarScrollListenerAdded = true;
  let lastScrollTop = 0;
  let ticking = false;

  window.addEventListener("scroll", function () {
    // Check viewport width inside the handler so it works after resize
    if (window.innerWidth > SIDEBAR_MOBILE_BREAKPOINT) return;
    if (ticking) return;

    window.requestAnimationFrame(function () {
      const currentScroll = window.scrollY ?? document.documentElement.scrollTop;

      if (currentScroll > lastScrollTop && currentScroll > SCROLL_HIDE_THRESHOLD) {
        buttonContainer.classList.add("hidden");
      } else {
        buttonContainer.classList.remove("hidden");
      }

      lastScrollTop = currentScroll <= 0 ? 0 : currentScroll;
      ticking = false;
    });

    ticking = true;
  });
}

/**
 * Set up sidebar toggle button and related handlers.
 */
function setupSidebarToggle(
  toggleButton: HTMLElement | null,
  sidebar: HTMLElement | null,
  overlay: HTMLElement | null
): void {
  if (!toggleButton || !sidebar || !toggleButton.parentNode) return;

  const newToggleButton = cloneAndReplace(toggleButton);

  newToggleButton.addEventListener("click", function (e: Event) {
    e.preventDefault();
    e.stopPropagation();

    sidebar.classList.toggle("mobile-open");
    if (overlay) overlay.classList.toggle("active");

    document.body.style.overflow = sidebar.classList.contains("mobile-open") ? "hidden" : "";
  });

  // Close sidebar when clicking on overlay
  // Re-query DOM inside handler to avoid stale references after View Transitions
  if (overlay && !overlayListenerAdded) {
    overlayListenerAdded = true;
    overlay.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      // Re-query current DOM elements to handle View Transitions
      const currentSidebar = document.querySelector(".sidebar") as HTMLElement | null;
      const currentOverlay = document.getElementById("sidebar-overlay");
      if (currentSidebar) currentSidebar.classList.remove("mobile-open");
      if (currentOverlay) currentOverlay.classList.remove("active");
      document.body.style.overflow = "";
    });
  }

  // Close sidebar when escape key is pressed
  // Re-query DOM inside handler to avoid stale references after View Transitions
  if (!escapeListenerAdded) {
    escapeListenerAdded = true;
    document.addEventListener("keydown", function (e) {
      // Re-query current DOM elements to handle View Transitions
      const currentSidebar = document.querySelector(".sidebar") as HTMLElement | null;
      const currentOverlay = document.getElementById("sidebar-overlay");
      if (e.key === "Escape" && currentSidebar?.classList.contains("mobile-open")) {
        currentSidebar.classList.remove("mobile-open");
        if (currentOverlay) currentOverlay.classList.remove("active");
        document.body.style.overflow = "";
      }
    });
  }
}

/**
 * Main initialization function for sidebar and related functionality.
 * Attached to window for global access and View Transitions support.
 */
window.initializeSidebar = function (): void {
  // Prevent duplicate initialization for the same page
  const currentPath = window.location.pathname + window.location.search;
  if (lastInitializedPath === currentPath) {
    return;
  }
  lastInitializedPath = currentPath;

  // Accessibility fix
  removeTabindexFromPreElements();

  // Initialize sidebar section toggles, search, and keyboard navigation
  initSidebar();

  // Get DOM elements
  const toggleButton = document.getElementById("sidebar-toggle");
  const buttonContainer = document.querySelector(".button-container") as HTMLElement | null;
  const sidebar = document.querySelector(".sidebar") as HTMLElement | null;
  const overlay = document.getElementById("sidebar-overlay");

  // Initialize mobile sidebar functionality
  initializeSidebarVisibility(sidebar, buttonContainer);
  addMobileButtonAttention(toggleButton);
  setupResizeHandler();
  setupScrollHandler(buttonContainer);
  setupSidebarToggle(toggleButton, sidebar, overlay);

  // Add copy buttons to code blocks
  addCopyButtons();
};

// Initialize on page events
if (typeof document !== "undefined") {
  // When DOM is ready (initial page load)
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", window.initializeSidebar);
  } else {
    window.initializeSidebar();
  }

  // On Astro page load (for View Transitions)
  document.addEventListener("astro:page-load", window.initializeSidebar);
}

// Initialize theme toggle separately
setupThemeToggle();
