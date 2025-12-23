/**
 * Theme Toggle Module
 *
 * Handles dark/light theme switching with localStorage persistence.
 * Supports system preference detection as fallback.
 */

import { cloneAndReplace } from "../utils/domUtils";

/**
 * Initialize theme toggle functionality.
 * Clones the toggle button to remove existing listeners, then attaches new handlers.
 */
export function initializeThemeToggle(): void {
  const themeToggle = document.getElementById("theme-toggle");
  if (!themeToggle || !themeToggle.parentNode) return;

  // Clone to remove existing listeners
  const newThemeToggle = cloneAndReplace(themeToggle);

  newThemeToggle.addEventListener("click", () => {
    const html = document.documentElement;
    const currentTheme = localStorage.getItem("theme");

    // Determine current effective theme
    let isDark = false;
    if (currentTheme === "dark") {
      isDark = true;
    } else if (currentTheme === "light") {
      isDark = false;
    } else {
      // No manual override, check system preference
      isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    }

    // Toggle theme
    if (isDark) {
      // Switch to light
      html.classList.remove("dark");
      html.classList.add("light");
      localStorage.setItem("theme", "light");
    } else {
      // Switch to dark
      html.classList.remove("light");
      html.classList.add("dark");
      localStorage.setItem("theme", "dark");
    }
  });
}

// Module-level flag to prevent duplicate event listener registration
let themeToggleInitialized = false;

/**
 * Set up theme toggle initialization on page events.
 * Handles both initial load and Astro View Transitions.
 * Uses a module-level flag to prevent duplicate listener registration.
 */
export function setupThemeToggle(): void {
  // Prevent duplicate listener registration if called multiple times
  if (themeToggleInitialized) {
    return;
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initializeThemeToggle);
    } else {
      initializeThemeToggle();
    }

    // Also initialize on Astro page load for View Transitions
    document.addEventListener("astro:page-load", initializeThemeToggle);

    themeToggleInitialized = true;
  }
}

/**
 * Reset the initialization flag (for testing purposes only).
 * @internal
 */
export function _resetThemeToggleState(): void {
  themeToggleInitialized = false;
}
