import { beforeEach, afterEach, vi } from "vitest";

// Clear all mocks before each test
beforeEach(() => {
  vi.clearAllMocks();
});

// Restore all mocks after each test
afterEach(() => {
  vi.restoreAllMocks();
});
