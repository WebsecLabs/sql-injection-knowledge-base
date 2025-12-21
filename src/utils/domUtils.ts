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
