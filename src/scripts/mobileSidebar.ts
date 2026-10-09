/**
 * Mobile sidebar drawer state, shared by the sidebar toggle and the search
 * modal (which closes the drawer when it opens).
 */

import { withTransition } from "../utils/domUtils";

/**
 * Open or close the mobile sidebar, keeping the overlay, the toggle button's
 * state and page scrolling in sync. Queries the DOM each time so it works
 * after View Transitions swap the page.
 */
export function setSidebarOpen(open: boolean, { restoreFocus = false } = {}): void {
  const sidebar = document.querySelector(".sidebar") as HTMLElement | null;
  if (!sidebar) return;
  const overlay = document.getElementById("sidebar-overlay");
  const toggle = document.getElementById("sidebar-toggle");

  withTransition(sidebar, "sidebar-transitioning", () => {
    sidebar.classList.toggle("mobile-open", open);
    overlay?.classList.toggle("active", open);
  });
  overlay?.setAttribute("aria-hidden", String(!open));
  toggle?.setAttribute("aria-expanded", String(open));
  toggle?.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  toggle?.classList.toggle("active", open);
  document.body.style.overflow = open ? "hidden" : "";

  if (open) {
    // The toggle sits after the page content; move focus to the drawer so
    // keyboard users continue into its links (without opening the keyboard
    // on touch devices, as focusing the search field would)
    sidebar.focus({ preventScroll: true });
  } else if (restoreFocus && sidebar.contains(document.activeElement)) {
    toggle?.focus();
  }
}
