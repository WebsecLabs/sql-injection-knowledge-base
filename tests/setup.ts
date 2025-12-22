import { afterEach, vi } from "vitest";

// Restore all mocks after each test.
// vi.restoreAllMocks() clears mock state AND restores original implementations,
// making a separate vi.clearAllMocks() in beforeEach redundant.
afterEach(() => {
  vi.restoreAllMocks();
});
