/**
 * Table of Contents Script
 * Handles scroll-spy highlighting and toggle functionality
 */

import {
  cloneAndReplace,
  updateToggleAccessibility,
  type ToggleAccessibilityConfig,
} from "../utils/domUtils";
import { TOC_STORAGE_KEY } from "../utils/uiConstants";

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
  lastInitializedPath = currentPath;

  const toc = document.getElementById("toc");
  if (!toc) return;

  // Restore collapsed state first, then initialize toggle button
  restoreCollapsedState(toc);
  initToggle(toc);
  initScrollSpy();
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
  const headings = document.querySelectorAll(
    ".entry-content h2[id], .entry-content h3[id], .markdown-body h2[id], .markdown-body h3[id]"
  );

  if (headings.length === 0) return;

  // Build a map of heading IDs to TOC links
  const tocLinks = document.querySelectorAll<HTMLAnchorElement>(".toc-link");
  const tocLinkMap = new Map<string, HTMLAnchorElement>();

  tocLinks.forEach((link) => {
    const headingId = link.getAttribute("data-heading-id");
    if (headingId) {
      tocLinkMap.set(headingId, link);
    }
  });

  if (tocLinkMap.size === 0) return;

  let currentActiveId: string | null = null;

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
          // Remove previous active state
          tocLinks.forEach((link) => link.classList.remove(TOC_ACTIVE_CLASS));

          // Add new active state
          const activeLink = tocLinkMap.get(id);
          if (activeLink) {
            activeLink.classList.add(TOC_ACTIVE_CLASS);

            // Scroll TOC link into view if needed (within the TOC container)
            const tocContent = document.getElementById("toc-content");
            if (tocContent) {
              const linkRect = activeLink.getBoundingClientRect();
              const contentRect = tocContent.getBoundingClientRect();

              if (linkRect.top < contentRect.top || linkRect.bottom > contentRect.bottom) {
                activeLink.scrollIntoView({
                  block: "nearest",
                  behavior: "smooth",
                });
              }
            }
          }

          currentActiveId = id;
        }
      }
    },
    {
      // rootMargin: top accounts for navbar (70px), bottom triggers in top 20% of viewport
      rootMargin: "-70px 0px -80% 0px",
      threshold: 0,
    }
  );

  // Observe all headings
  headings.forEach((heading) => tocObserver!.observe(heading));
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
