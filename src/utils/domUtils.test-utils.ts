/**
 * Test utilities for domUtils module
 * @module domUtils.test-utils
 *
 * This file contains test helpers that should NOT be imported in production code.
 * These utilities expose internal state for testing purposes only.
 */

/**
 * Symbol used as a namespace for initialization tracking on the window object.
 * Must match the symbol in domUtils.ts (using Symbol.for ensures same reference)
 */
const INIT_TRACKER_KEY = Symbol.for("__domUtils_initTracker__");

/**
 * Interface for the initialization tracker stored on the window object
 */
interface InitTracker {
  [key: string]: boolean;
}

/**
 * Resets the initialization tracker. FOR TESTING ONLY.
 * This allows tests to reset the initOnce state between test cases
 * without coupling to the internal Symbol key.
 *
 * @example
 * ```typescript
 * import { _resetInitTracker } from './domUtils.test-utils';
 *
 * beforeEach(() => {
 *   _resetInitTracker();
 * });
 * ```
 */
export function _resetInitTracker(): void {
  if (typeof window === "undefined") {
    return;
  }

  const win = window as Window & { [INIT_TRACKER_KEY]?: InitTracker };
  delete win[INIT_TRACKER_KEY];
}
