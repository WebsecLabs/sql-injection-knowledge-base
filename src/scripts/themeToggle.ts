/**
 * Theme Toggle Module
 *
 * Handles dark/light theme switching with localStorage persistence.
 * Supports system preference detection as fallback.
 */

/** AbortController for theme toggle event listeners — allows clean teardown */
let themeToggleController: AbortController | null = null;

/**
 * Shared theme toggle logic used by both desktop and mobile toggle buttons.
 */
function toggleTheme(): void {
  const html = document.documentElement;
  const currentTheme = localStorage.getItem("theme");

  // Determine current effective theme
  const isDark =
    currentTheme === "dark" ||
    (currentTheme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);

  // Toggle to the opposite theme
  const newTheme = isDark ? "light" : "dark";
  html.classList.remove(isDark ? "dark" : "light");
  html.classList.add(newTheme);
  localStorage.setItem("theme", newTheme);
}

/**
 * Initialize theme toggle functionality.
 * Uses AbortController to cleanly remove previous listeners before attaching new ones.
 */
export function initializeThemeToggle(): void {
  // Abort previous listeners
  themeToggleController?.abort();
  themeToggleController = new AbortController();
  const { signal } = themeToggleController;

  // Desktop theme toggle (inside hamburger menu)
  const themeToggle = document.getElementById("theme-toggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme, { signal });
  }

  // Mobile theme toggle (always visible in navbar)
  const mobileThemeToggle = document.getElementById("mobile-theme-toggle");
  if (mobileThemeToggle) {
    mobileThemeToggle.addEventListener("click", toggleTheme, { signal });
  }
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
