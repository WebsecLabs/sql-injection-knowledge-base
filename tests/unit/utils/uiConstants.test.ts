import { describe, it, expect } from "vitest";
import * as constants from "@/utils/uiConstants";

describe("uiConstants", () => {
  describe("breakpoints", () => {
    it("should export SIDEBAR_MOBILE_BREAKPOINT as a positive number", () => {
      expect(constants.SIDEBAR_MOBILE_BREAKPOINT).toBeGreaterThan(0);
      expect(typeof constants.SIDEBAR_MOBILE_BREAKPOINT).toBe("number");
    });

    it("should export NAVBAR_MOBILE_BREAKPOINT as a positive number", () => {
      expect(constants.NAVBAR_MOBILE_BREAKPOINT).toBeGreaterThan(0);
      expect(typeof constants.NAVBAR_MOBILE_BREAKPOINT).toBe("number");
    });

    it("should have NAVBAR_MOBILE_BREAKPOINT larger than SIDEBAR_MOBILE_BREAKPOINT", () => {
      expect(constants.NAVBAR_MOBILE_BREAKPOINT).toBeGreaterThan(
        constants.SIDEBAR_MOBILE_BREAKPOINT
      );
    });
  });

  describe("timing constants", () => {
    it("should export SCROLL_HIDE_THRESHOLD as a positive number", () => {
      expect(constants.SCROLL_HIDE_THRESHOLD).toBeGreaterThan(0);
    });

    it("should export SEARCH_DEBOUNCE_MS as a positive number", () => {
      expect(constants.SEARCH_DEBOUNCE_MS).toBeGreaterThan(0);
    });

    it("should export RESIZE_DEBOUNCE_MS as a positive number", () => {
      expect(constants.RESIZE_DEBOUNCE_MS).toBeGreaterThan(0);
    });

    it("should export COPY_FEEDBACK_DURATION_MS as a positive number", () => {
      expect(constants.COPY_FEEDBACK_DURATION_MS).toBeGreaterThan(0);
    });

    it("should export SIDEBAR_ATTENTION_DELAY_MS as a positive number", () => {
      expect(constants.SIDEBAR_ATTENTION_DELAY_MS).toBeGreaterThan(0);
    });

    it("should export INIT_FALLBACK_DELAY_MS as a positive number", () => {
      expect(constants.INIT_FALLBACK_DELAY_MS).toBeGreaterThan(0);
    });
  });

  describe("UI constants", () => {
    it("should export SEARCH_TITLE_MAX_LENGTH as a positive number", () => {
      expect(constants.SEARCH_TITLE_MAX_LENGTH).toBeGreaterThan(0);
    });

    it("should export DROPDOWN_MOBILE_MAX_HEIGHT as a string", () => {
      expect(typeof constants.DROPDOWN_MOBILE_MAX_HEIGHT).toBe("string");
      expect(constants.DROPDOWN_MOBILE_MAX_HEIGHT).toMatch(/^\d+px$/);
    });

    it("should export DROPDOWN_TRANSITION_TIMEOUT_MS as a positive number", () => {
      expect(typeof constants.DROPDOWN_TRANSITION_TIMEOUT_MS).toBe("number");
      expect(constants.DROPDOWN_TRANSITION_TIMEOUT_MS).toBeGreaterThan(0);
    });
  });

  describe("TOC constants", () => {
    it("should export TOC_HIDE_BREAKPOINT as a positive number", () => {
      expect(typeof constants.TOC_HIDE_BREAKPOINT).toBe("number");
      expect(constants.TOC_HIDE_BREAKPOINT).toBeGreaterThan(0);
    });

    it("should export TOC_STORAGE_KEY as a non-empty string", () => {
      expect(typeof constants.TOC_STORAGE_KEY).toBe("string");
      expect(constants.TOC_STORAGE_KEY.length).toBeGreaterThan(0);
    });

    it("should export TOC_MIN_HEADINGS as a number >= 1", () => {
      expect(typeof constants.TOC_MIN_HEADINGS).toBe("number");
      expect(constants.TOC_MIN_HEADINGS).toBeGreaterThanOrEqual(1);
    });
  });

  describe("all constants are defined", () => {
    const expectedConstants = [
      "SIDEBAR_MOBILE_BREAKPOINT",
      "NAVBAR_MOBILE_BREAKPOINT",
      "SCROLL_HIDE_THRESHOLD",
      "SEARCH_DEBOUNCE_MS",
      "RESIZE_DEBOUNCE_MS",
      "SEARCH_TITLE_MAX_LENGTH",
      "DROPDOWN_MOBILE_MAX_HEIGHT",
      "COPY_FEEDBACK_DURATION_MS",
      "SIDEBAR_ATTENTION_DELAY_MS",
      "INIT_FALLBACK_DELAY_MS",
      "TOC_HIDE_BREAKPOINT",
      "TOC_STORAGE_KEY",
      "TOC_MIN_HEADINGS",
      "DROPDOWN_TRANSITION_TIMEOUT_MS",
    ];

    // Using it.each improves test reporting by showing each constant as its own test case
    it.each(expectedConstants)("should export %s", (name) => {
      expect(constants).toHaveProperty(name);
      expect(constants[name as keyof typeof constants]).toBeDefined();
    });
  });
});
