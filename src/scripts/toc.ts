/**
 * Table of Contents Script
 * Handles scroll-spy highlighting and toggle functionality
 */

import {
  cloneAndReplace,
  updateToggleAccessibility,
  type ToggleAccessibilityConfig,
} from "../utils/domUtils";
import {
  TOC_STORAGE_KEY,
  TOC_OBSERVER_TOP_MARGIN_PX,
  TOC_OBSERVER_BOTTOM_PERCENT,
  TOC_HEADING_SELECTOR,
} from "../utils/uiConstants";

/** TOC toggle accessibility configuration */
const TOC_TOGGLE_CONFIG: ToggleAccessibilityConfig = {
  expandLabel: "Expand table of contents",
  collapseLabel: "Collapse table of contents",
  expandTitle: "Expand table of contents",
  collapseTitle: "Collapse to gain screen space",
};

/** CSS classes */
const TOC_ACTIVE_CLASS = "toc-link-active";
const TOC_COLLAPSED_CLASS = "toc-collapsed";

/** Module state */
let tocObserver: IntersectionObserver | null = null;
let lastInitializedPath: string | null = null;

/**
 * Initialize TOC functionality
 * Sets up toggle button and scroll-spy
 */
export function initToc(): void {
  const currentPath = window.location.pathname;

  // Avoid re-initialization on the same path (View Transitions)
  if (lastInitializedPath === currentPath) return;

  const toc = document.getElementById("toc");
  if (!toc) return;

  // Restore collapsed state first, then initialize toggle button
  restoreCollapsedState(toc);
  initToggle(toc);
  initScrollSpy();

  // Only mark as initialized after successful setup
  lastInitializedPath = currentPath;
}

/**
 * Set up toggle button with localStorage persistence
 * Horizontal collapse to reclaim screen real estate
 */
function initToggle(toc: HTMLElement): void {
  const toggle = document.getElementById("toc-toggle");
  if (!toggle) return;

  // Clone to remove stale event listeners
  const newToggle = cloneAndReplace(toggle) as HTMLButtonElement;

  newToggle.addEventListener("click", () => {
    const isCollapsed = toc.classList.toggle(TOC_COLLAPSED_CLASS);
    updateToggleAccessibility(newToggle, isCollapsed, TOC_TOGGLE_CONFIG);

    try {
      localStorage.setItem(TOC_STORAGE_KEY, String(isCollapsed));
    } catch {
      // localStorage may be unavailable
    }
  });
}

/**
 * Restore collapsed state from localStorage
 */
function restoreCollapsedState(toc: HTMLElement): void {
  try {
    const isCollapsed = localStorage.getItem(TOC_STORAGE_KEY) === "true";
    const toggle = document.getElementById("toc-toggle");

    if (isCollapsed) {
      toc.classList.add(TOC_COLLAPSED_CLASS);
    }
    if (toggle) {
      updateToggleAccessibility(toggle, isCollapsed, TOC_TOGGLE_CONFIG);
    }
  } catch {
    // localStorage may be unavailable
  }
}

/**
 * Initialize Intersection Observer for scroll-spy
 * Highlights the current section in the TOC as user scrolls
 */
function initScrollSpy(): void {
  // Clean up previous observer
  if (tocObserver) {
    tocObserver.disconnect();
    tocObserver = null;
  }

  // Find all headings with IDs in the main content
  const headings = document.querySelectorAll(TOC_HEADING_SELECTOR);

  if (headings.length === 0) return;

  // Build a map of heading IDs to TOC links
  const tocLinkMap = new Map<string, HTMLAnchorElement>();

  document.querySelectorAll<HTMLAnchorElement>(".toc-link").forEach((link) => {
    const headingId = link.getAttribute("data-heading-id");
    if (headingId) {
      tocLinkMap.set(headingId, link);
    }
  });

  if (tocLinkMap.size === 0) return;

  // Track current active state for efficient updates
  let currentActiveId: string | null = null;
  let currentActiveLink: HTMLAnchorElement | null = null;

  // Compute rootMargin from constants (navbar height + bottom trigger percentage)
  const rootMargin = `-${TOC_OBSERVER_TOP_MARGIN_PX}px 0px -${TOC_OBSERVER_BOTTOM_PERCENT}% 0px`;

  tocObserver = new IntersectionObserver(
    (entries) => {
      // Find visible headings
      const visibleEntries = entries.filter((e) => e.isIntersecting);

      if (visibleEntries.length > 0) {
        // Sort by position in viewport (top to bottom)
        visibleEntries.sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);

        const topHeading = visibleEntries[0].target;
        const id = topHeading.getAttribute("id");

        if (id && id !== currentActiveId) {
          const newActiveLink = tocLinkMap.get(id);

          // Only update if we found a valid link and it's different
          if (newActiveLink && newActiveLink !== currentActiveLink) {
            // Remove previous active state from single tracked element
            currentActiveLink?.classList.remove(TOC_ACTIVE_CLASS);

            // Add new active state
            newActiveLink.classList.add(TOC_ACTIVE_CLASS);

            // Scroll TOC link into view if needed (within the TOC container)
            const tocContent = document.getElementById("toc-content");
            if (tocContent) {
              const linkRect = newActiveLink.getBoundingClientRect();
              const contentRect = tocContent.getBoundingClientRect();

              if (linkRect.top < contentRect.top || linkRect.bottom > contentRect.bottom) {
                newActiveLink.scrollIntoView({
                  block: "nearest",
                  behavior: "smooth",
                });
              }
            }

            currentActiveLink = newActiveLink;
          }

          currentActiveId = id;
        }
      }
    },
    {
      rootMargin,
      threshold: 0,
    }
  );

  // Observe all headings
  headings.forEach((heading) => tocObserver.observe(heading));
}

/**
 * Cleanup function for TOC
 * Disconnects the IntersectionObserver
 */
export function cleanupToc(): void {
  if (tocObserver) {
    tocObserver.disconnect();
    tocObserver = null;
  }
  lastInitializedPath = null;
}
