/**
 * DOM utility functions for browser interactions
 * @module domUtils
 */

/**
 * Symbol used as a namespace for initialization tracking on the window object
 * to avoid collisions with other properties
 */
const INIT_TRACKER_KEY = Symbol.for("__domUtils_initTracker__");

/**
 * Interface for the initialization tracker stored on the window object
 */
interface InitTracker {
  [key: string]: boolean;
}

/**
 * Gets or creates the initialization tracker on the window object
 * @returns The initialization tracker object
 */
function getInitTracker(): InitTracker {
  if (typeof window === "undefined") {
    return {};
  }

  // Use type assertion to add our custom property to window
  const win = window as Window & { [INIT_TRACKER_KEY]?: InitTracker };

  if (!win[INIT_TRACKER_KEY]) {
    win[INIT_TRACKER_KEY] = {};
  }

  return win[INIT_TRACKER_KEY]!;
}

/**
 * Prevents duplicate initialization by tracking on the window object.
 * Useful for ensuring that event listeners or setup code only runs once,
 * even if the function is called multiple times.
 *
 * @param key - Unique identifier for this initialization
 * @param init - Function to call on first initialization
 *
 * @example
 * ```typescript
 * initOnce('myFeature', () => {
 *   console.log('This will only run once');
 *   document.addEventListener('click', handleClick);
 * });
 * ```
 *
 * @remarks
 * - In SSR contexts (where window is undefined), the init function will run every time
 * - Uses a Symbol-based key to avoid property name collisions on window
 * - Initialization state persists across the entire page lifecycle
 */
export function initOnce(key: string, init: () => void): void {
  // In SSR context, always run the init function
  if (typeof window === "undefined") {
    init();
    return;
  }

  const tracker = getInitTracker();

  if (!tracker[key]) {
    tracker[key] = true;
    init();
  }
}

/**
 * Clones an element and replaces it in the DOM to remove all event listeners.
 * This is useful for cleaning up event listeners without having to track references.
 *
 * @param element - The element to clone and replace
 * @returns The cloned element that replaced the original
 *
 * @throws {Error} If the element has no parent node
 *
 * @example
 * ```typescript
 * const button = document.querySelector('button');
 * if (button) {
 *   const cleanButton = cloneAndReplace(button);
 *   // All event listeners have been removed from cleanButton
 *   cleanButton.addEventListener('click', newHandler);
 * }
 * ```
 *
 * @remarks
 * - This creates a deep clone of the element with all descendants
 * - All event listeners attached via addEventListener are removed
 * - Inline event handlers (onclick, etc.) are preserved
 * - The original element reference will no longer be in the DOM
 */
export function cloneAndReplace(element: Element): Element {
  if (!element.parentNode) {
    throw new Error("Element must have a parent node to be replaced");
  }

  const clone = element.cloneNode(true) as Element;
  element.parentNode.replaceChild(clone, element);

  return clone;
}

/**
 * Interface for debounced functions that includes a cancel method
 */
export interface DebouncedFunction<T extends (...args: Parameters<T>) => void> {
  (...args: Parameters<T>): void;
  /** Cancel any pending invocation */
  cancel: () => void;
}

/**
 * Creates a debounced version of a function that delays execution until
 * after the specified wait time has elapsed since the last call.
 *
 * @template T - The function type to debounce
 * @param func - The function to debounce
 * @param wait - The number of milliseconds to delay
 * @returns A debounced version of the function with a cancel method
 *
 * @example
 * ```typescript
 * const handleSearch = (query: string) => {
 *   console.log('Searching for:', query);
 * };
 *
 * const debouncedSearch = debounce(handleSearch, 300);
 *
 * // Only the last call within 300ms will execute
 * debouncedSearch('a');
 * debouncedSearch('ab');
 * debouncedSearch('abc'); // Only this will run after 300ms
 *
 * // Cancel any pending execution (useful for cleanup/unmount)
 * debouncedSearch.cancel();
 * ```
 *
 * @remarks
 * - Useful for rate-limiting expensive operations like API calls or DOM updates
 * - Each call resets the timer, so rapid successive calls will only execute once
 * - The debounced function preserves the original function's type signature
 * - Works in both browser and SSR contexts
 * - The cancel method clears any pending timeout, useful for cleanup during unmount
 */
export function debounce<T extends (...args: Parameters<T>) => void>(
  func: T,
  wait: number
): DebouncedFunction<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const debounced = function (this: unknown, ...args: Parameters<T>): void {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }

    timeoutId = setTimeout(() => {
      func.apply(this, args);
      timeoutId = undefined;
    }, wait);
  } as DebouncedFunction<T>;

  debounced.cancel = function (): void {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
      timeoutId = undefined;
    }
  };

  return debounced;
}

/**
 * Performs a CSS class transition with automatic cleanup of the transitioning class.
 * Adds a transitioning class before performing the action, then removes it after
 * the CSS transform transition completes.
 *
 * This is useful for:
 * - Preventing CSS transitions during resize (by conditionally adding transitioning class)
 * - Ensuring smooth animations for user-initiated actions
 * - Cleaning up transitioning state after animation completes
 *
 * @param element - The element to perform the transition on
 * @param transitioningClass - CSS class to add during transition (e.g., "sidebar-transitioning")
 * @param action - Function that performs the actual state change (e.g., toggle classes)
 *
 * @example
 * ```typescript
 * // Close sidebar with transition
 * withTransition(sidebar, "sidebar-transitioning", () => {
 *   sidebar.classList.remove("mobile-open");
 * });
 *
 * // Toggle menu with transition
 * withTransition(navbarMenu, "menu-transitioning", () => {
 *   navbarMenu.classList.toggle("active");
 * });
 * ```
 *
 * @remarks
 * - Only listens for 'transform' property transitions to avoid multiple triggers
 * - Automatically removes the event listener after handling
 * - If no transition occurs (e.g., transitions disabled), the class remains
 */
export function withTransition(
  element: HTMLElement,
  transitioningClass: string,
  action: () => void
): void {
  // Add transitioning class to enable CSS transitions
  element.classList.add(transitioningClass);

  // Perform the state change
  action();

  // Remove transitioning class after transform animation completes
  element.addEventListener("transitionend", function handler(event: TransitionEvent) {
    // Only handle transform transitions (not visibility or other properties)
    if (event.propertyName === "transform") {
      element.classList.remove(transitioningClass);
      element.removeEventListener("transitionend", handler);
    }
  });
}

/**
 * Configuration for collapsible toggle button accessibility attributes
 */
export interface ToggleAccessibilityConfig {
  /** Label shown when collapsed */
  expandLabel: string;
  /** Label shown when expanded */
  collapseLabel: string;
  /** Title/tooltip shown when collapsed */
  expandTitle: string;
  /** Title/tooltip shown when expanded */
  collapseTitle: string;
}

/**
 * Updates accessibility attributes for a collapsible toggle button.
 * Sets aria-expanded, aria-label, and title based on collapsed state.
 *
 * @param toggle - The toggle button element
 * @param isCollapsed - Whether the target element is currently collapsed
 * @param config - Configuration for labels and titles
 *
 * @example
 * ```typescript
 * // TOC toggle with custom messages
 * updateToggleAccessibility(toggle, isCollapsed, {
 *   expandLabel: "Expand table of contents",
 *   collapseLabel: "Collapse table of contents",
 *   expandTitle: "Expand table of contents",
 *   collapseTitle: "Collapse to gain screen space"
 * });
 * ```
 *
 * @remarks
 * - aria-expanded is set to the opposite of isCollapsed (true when content is visible)
 * - aria-label provides screen reader context
 * - title provides tooltip on hover
 */
export function updateToggleAccessibility(
  toggle: Element,
  isCollapsed: boolean,
  config: ToggleAccessibilityConfig
): void {
  toggle.setAttribute("aria-expanded", String(!isCollapsed));
  toggle.setAttribute("aria-label", isCollapsed ? config.expandLabel : config.collapseLabel);
  toggle.setAttribute("title", isCollapsed ? config.expandTitle : config.collapseTitle);
}
