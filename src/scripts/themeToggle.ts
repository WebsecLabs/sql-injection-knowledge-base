/**
 * Theme Toggle Module
 *
 * Handles dark/light theme switching with localStorage persistence.
 * Supports system preference detection as fallback.
 */

/** AbortController for theme toggle event listeners — allows clean teardown */
let themeToggleController: AbortController | null = null;

declare global {
  interface Window {
    /** In-memory theme choice used when localStorage is unavailable */
    __themeFallback?: string;
  }
}

/**
 * Persist the chosen theme. Storage can throw (blocked site data, some private
 * modes), so the choice is also kept in memory for the inline theme script to
 * reapply after View Transitions.
 */
function storeTheme(theme: string): void {
  window.__themeFallback = theme;
  try {
    localStorage.setItem("theme", theme);
  } catch {
    // localStorage may be unavailable; the in-memory fallback still applies
  }
}

/**
 * Shared theme toggle logic used by both desktop and mobile toggle buttons.
 * The classes on <html> reflect the theme being displayed; with neither
 * class set, the page follows the system preference.
 */
function isDarkTheme(): boolean {
  const html = document.documentElement;
  return (
    html.classList.contains("dark") ||
    (!html.classList.contains("light") && window.matchMedia("(prefers-color-scheme: dark)").matches)
  );
}

/** Reflect the displayed theme on the "Dark theme" toggle buttons */
function syncTogglePressed(): void {
  const pressed = String(isDarkTheme());
  for (const id of ["theme-toggle", "mobile-theme-toggle"]) {
    document.getElementById(id)?.setAttribute("aria-pressed", pressed);
  }
}

function toggleTheme(): void {
  const html = document.documentElement;
  const isDark = isDarkTheme();

  // Toggle to the opposite theme
  const newTheme = isDark ? "light" : "dark";
  html.classList.remove(isDark ? "dark" : "light");
  html.classList.add(newTheme);
  storeTheme(newTheme);
  syncTogglePressed();
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

  // While following the system theme, keep the pressed state in step with it
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener?.("change", syncTogglePressed, { signal });
  syncTogglePressed();
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
