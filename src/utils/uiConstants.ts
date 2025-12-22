/**
 * UI Constants for consistent values across the application
 * Centralizes magic numbers and configuration values for better maintainability
 * @module uiConstants
 */

/** Mobile breakpoint for sidebar behavior (pixels) */
export const SIDEBAR_MOBILE_BREAKPOINT = 768;

/** Mobile breakpoint for navbar behavior (pixels) */
export const NAVBAR_MOBILE_BREAKPOINT = 1024;

/** Scroll threshold before hiding mobile sidebar toggle (pixels) */
export const SCROLL_HIDE_THRESHOLD = 100;

/** Debounce delay for search input (milliseconds) */
export const SEARCH_DEBOUNCE_MS = 300;

/** Debounce delay for resize events (milliseconds) */
export const RESIZE_DEBOUNCE_MS = 100;

/** Maximum title length before truncation in search results */
export const SEARCH_TITLE_MAX_LENGTH = 50;

/**
 * Max-height for mobile dropdown menus.
 * Set to a large value to allow CSS max-height transitions to animate smoothly
 * (using 'auto' doesn't work with CSS transitions). Capped at 2000px to avoid
 * performance issues with excessively long transition calculations.
 */
export const DROPDOWN_MOBILE_MAX_HEIGHT = "2000px";

/** Copy button feedback duration (milliseconds) */
export const COPY_FEEDBACK_DURATION_MS = 2000;

/** Attention animation delay for sidebar toggle (milliseconds) */
export const SIDEBAR_ATTENTION_DELAY_MS = 1000;

/** Fallback initialization delay (milliseconds) */
export const INIT_FALLBACK_DELAY_MS = 100;

/** Breakpoint for hiding TOC on smaller screens (pixels) */
export const TOC_HIDE_BREAKPOINT = 1024;

/** localStorage key for TOC collapsed state */
export const TOC_STORAGE_KEY = "toc-collapsed";

/** Minimum number of headings required to show TOC */
export const TOC_MIN_HEADINGS = 2;

/**
 * Fallback timeout for dropdown opacity transitions (milliseconds).
 * Used when listening for transitionend events to ensure cleanup
 * happens even if the event doesn't fire (e.g., transitions disabled).
 */
export const DROPDOWN_TRANSITION_TIMEOUT_MS = 250;
