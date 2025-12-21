/**
 * Tests for themeToggle module
 * @vitest-environment jsdom
 */
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  initializeThemeToggle,
  setupThemeToggle,
  _resetThemeToggleState,
} from "../../../src/scripts/themeToggle";

describe("themeToggle", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    document.documentElement.className = "";
    localStorage.clear();
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: false }));
    // Reset module-level initialization flag for clean test state
    _resetThemeToggleState();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("initializeThemeToggle", () => {
    it("does nothing if theme toggle button not found", () => {
      document.body.innerHTML = "";

      // Should not throw
      expect(() => initializeThemeToggle()).not.toThrow();
    });

    it("toggles from light to dark when clicking", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.setItem("theme", "light");
      document.documentElement.classList.add("light");

      initializeThemeToggle();

      const button = document.getElementById("theme-toggle")!;
      button.click();

      expect(document.documentElement.classList.contains("dark")).toBe(true);
      expect(document.documentElement.classList.contains("light")).toBe(false);
      expect(localStorage.getItem("theme")).toBe("dark");
    });

    it("toggles from dark to light when clicking", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.setItem("theme", "dark");
      document.documentElement.classList.add("dark");

      initializeThemeToggle();

      const button = document.getElementById("theme-toggle")!;
      button.click();

      expect(document.documentElement.classList.contains("light")).toBe(true);
      expect(document.documentElement.classList.contains("dark")).toBe(false);
      expect(localStorage.getItem("theme")).toBe("light");
    });

    it("respects system preference when no localStorage value", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.clear();

      // System prefers dark
      vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));

      initializeThemeToggle();

      const button = document.getElementById("theme-toggle")!;
      button.click();

      // Should toggle from dark (system preference) to light
      expect(document.documentElement.classList.contains("light")).toBe(true);
      expect(localStorage.getItem("theme")).toBe("light");
    });

    it("respects system preference for light when no localStorage value", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.clear();

      // System prefers light
      vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: false }));

      initializeThemeToggle();

      const button = document.getElementById("theme-toggle")!;
      button.click();

      // Should toggle from light (system preference) to dark
      expect(document.documentElement.classList.contains("dark")).toBe(true);
      expect(localStorage.getItem("theme")).toBe("dark");
    });

    it("removes existing event listeners via cloneAndReplace", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';

      // Track click count from old listener
      let oldListenerCalled = false;
      const originalButton = document.getElementById("theme-toggle")!;
      originalButton.addEventListener("click", () => {
        oldListenerCalled = true;
      });

      // Initialize twice (simulating View Transitions re-init)
      initializeThemeToggle();
      initializeThemeToggle();

      // Get the newest button (after cloneAndReplace)
      const button = document.getElementById("theme-toggle")!;
      button.click();

      // Old listener should NOT fire (removed by cloneAndReplace)
      expect(oldListenerCalled).toBe(false);
      // But theme toggle should still work
      expect(document.documentElement.classList.contains("dark")).toBe(true);
    });
  });

  describe("setupThemeToggle", () => {
    it("sets up event listeners for DOMContentLoaded when DOM is loading", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';

      // Mock document.readyState
      Object.defineProperty(document, "readyState", {
        value: "loading",
        configurable: true,
      });

      const addEventListenerSpy = vi.spyOn(document, "addEventListener");

      setupThemeToggle();

      expect(addEventListenerSpy).toHaveBeenCalledWith("DOMContentLoaded", expect.any(Function));
    });

    it("initializes immediately when DOM is already ready", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.setItem("theme", "light");
      document.documentElement.classList.add("light");

      // Mock document.readyState as complete
      Object.defineProperty(document, "readyState", {
        value: "complete",
        configurable: true,
      });

      setupThemeToggle();

      // Button should be functional
      const button = document.getElementById("theme-toggle")!;
      button.click();

      expect(document.documentElement.classList.contains("dark")).toBe(true);
    });

    it("listens for astro:page-load event", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';

      const addEventListenerSpy = vi.spyOn(document, "addEventListener");

      setupThemeToggle();

      expect(addEventListenerSpy).toHaveBeenCalledWith("astro:page-load", expect.any(Function));
    });
  });

  describe("edge cases", () => {
    it("returns early when #theme-toggle element is not in the DOM", () => {
      // Don't add any button to the document
      // initializeThemeToggle uses getElementById which will return null

      // Should not throw and should return early gracefully
      expect(() => initializeThemeToggle()).not.toThrow();

      // Verify no button exists in DOM
      expect(document.getElementById("theme-toggle")).toBeNull();
    });

    it("persists theme choice across multiple toggles", () => {
      document.body.innerHTML = '<button id="theme-toggle">Toggle</button>';
      localStorage.clear();

      initializeThemeToggle();
      const button = document.getElementById("theme-toggle")!;

      // Toggle to dark
      button.click();
      expect(localStorage.getItem("theme")).toBe("dark");

      // Toggle to light
      button.click();
      expect(localStorage.getItem("theme")).toBe("light");

      // Toggle back to dark
      button.click();
      expect(localStorage.getItem("theme")).toBe("dark");
    });
  });
});
