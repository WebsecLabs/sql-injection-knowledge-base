/**
 * Shared DOM test utilities for unit tests.
 *
 * These utilities help with common DOM manipulation patterns in tests,
 * ensuring consistent behavior and proper cleanup.
 */

/**
 * Creates a temporary container with the given HTML, runs the callback,
 * and ensures cleanup even if the callback throws.
 *
 * This is useful for tests that need a fresh DOM state without polluting
 * the main test container or other tests.
 *
 * @param html - The HTML string to set as the container's innerHTML
 * @param callback - The function to run with the container
 *
 * @example
 * withTemporaryContainer(
 *   '<div class="tabs"><button>Tab 1</button></div>',
 *   (container) => {
 *     initializeTabs();
 *     expect(container.querySelector('.tabs')).toBeTruthy();
 *   }
 * );
 */
export function withTemporaryContainer(
  html: string,
  callback: (container: HTMLElement) => void
): void {
  const container = document.createElement("div");
  container.innerHTML = html;
  document.body.appendChild(container);
  try {
    callback(container);
  } finally {
    // Use remove() instead of removeChild() - it's a no-op if already detached,
    // making cleanup safe even if the callback already removed the element
    container.remove();
  }
}
