import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { initOnce, cloneAndReplace, debounce } from "../../../src/utils/domUtils";
import { _resetInitTracker } from "../../../src/utils/domUtils.test-utils";

describe("domUtils", () => {
  describe("initOnce", () => {
    beforeEach(() => {
      // Reset initialization tracker between tests using the exported helper
      // to ensure test isolation without coupling to internal Symbol implementation
      _resetInitTracker();
    });

    it("calls init function on first call", () => {
      const init = vi.fn();
      initOnce("test-key", init);

      expect(init).toHaveBeenCalledTimes(1);
    });

    it("does not call init function on subsequent calls with same key", () => {
      const init = vi.fn();

      initOnce("test-key-2", init);
      initOnce("test-key-2", init);
      initOnce("test-key-2", init);

      expect(init).toHaveBeenCalledTimes(1);
    });

    it("calls init function for different keys", () => {
      const init1 = vi.fn();
      const init2 = vi.fn();

      initOnce("key-a", init1);
      initOnce("key-b", init2);

      expect(init1).toHaveBeenCalledTimes(1);
      expect(init2).toHaveBeenCalledTimes(1);
    });

    it("uses unique namespace to avoid collisions", () => {
      // Set a property that might collide with naive implementations
      (window as unknown as Record<string, unknown>)["test-collision"] = false;

      const init = vi.fn();
      initOnce("test-collision", init);

      // Should still call init because our tracker uses Symbol
      expect(init).toHaveBeenCalledTimes(1);
    });
  });

  describe("cloneAndReplace", () => {
    let container: HTMLDivElement;

    beforeEach(() => {
      container = document.createElement("div");
      document.body.appendChild(container);
    });

    afterEach(() => {
      container.remove();
    });

    it("clones element and replaces it in DOM", () => {
      const button = document.createElement("button");
      button.textContent = "Click me";
      button.id = "test-button";
      container.appendChild(button);

      const cloned = cloneAndReplace(button);

      expect(cloned).toBeInstanceOf(HTMLButtonElement);
      expect(cloned.textContent).toBe("Click me");
      expect(cloned.id).toBe("test-button");
      expect(container.contains(cloned)).toBe(true);
      expect(container.contains(button)).toBe(false);
    });

    it("removes event listeners from original element", () => {
      const button = document.createElement("button");
      container.appendChild(button);

      const handler = vi.fn();
      button.addEventListener("click", handler);

      const cloned = cloneAndReplace(button) as HTMLButtonElement;
      cloned.click();

      // Handler should NOT be called on cloned element
      expect(handler).not.toHaveBeenCalled();
    });

    it("preserves child elements", () => {
      const parent = document.createElement("div");
      const child1 = document.createElement("span");
      child1.textContent = "Child 1";
      const child2 = document.createElement("span");
      child2.textContent = "Child 2";
      parent.appendChild(child1);
      parent.appendChild(child2);
      container.appendChild(parent);

      const cloned = cloneAndReplace(parent);

      expect(cloned.children.length).toBe(2);
      expect(cloned.children[0].textContent).toBe("Child 1");
      expect(cloned.children[1].textContent).toBe("Child 2");
    });

    it("throws error if element has no parent", () => {
      const orphan = document.createElement("div");

      expect(() => cloneAndReplace(orphan)).toThrow(
        "Element must have a parent node to be replaced"
      );
    });

    it("preserves attributes", () => {
      const div = document.createElement("div");
      div.setAttribute("data-test", "value");
      div.setAttribute("aria-label", "Test");
      div.className = "my-class";
      container.appendChild(div);

      const cloned = cloneAndReplace(div);

      expect(cloned.getAttribute("data-test")).toBe("value");
      expect(cloned.getAttribute("aria-label")).toBe("Test");
      expect(cloned.className).toBe("my-class");
    });
  });

  describe("debounce", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("delays function execution", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced();
      expect(func).not.toHaveBeenCalled();

      vi.advanceTimersByTime(100);
      expect(func).toHaveBeenCalledTimes(1);
    });

    it("only executes last call within wait period", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced("first");
      debounced("second");
      debounced("third");

      vi.advanceTimersByTime(100);

      expect(func).toHaveBeenCalledTimes(1);
      expect(func).toHaveBeenCalledWith("third");
    });

    it("resets timer on each call", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced();
      vi.advanceTimersByTime(50);

      debounced();
      vi.advanceTimersByTime(50);

      // Should not have been called yet (timer reset)
      expect(func).not.toHaveBeenCalled();

      vi.advanceTimersByTime(50);
      expect(func).toHaveBeenCalledTimes(1);
    });

    it("allows multiple independent debounced functions", () => {
      const func1 = vi.fn();
      const func2 = vi.fn();
      const debounced1 = debounce(func1, 100);
      const debounced2 = debounce(func2, 200);

      debounced1();
      debounced2();

      vi.advanceTimersByTime(100);
      expect(func1).toHaveBeenCalledTimes(1);
      expect(func2).not.toHaveBeenCalled();

      vi.advanceTimersByTime(100);
      expect(func2).toHaveBeenCalledTimes(1);
    });

    it("preserves function arguments", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced("arg1", 42, { key: "value" });

      vi.advanceTimersByTime(100);

      expect(func).toHaveBeenCalledWith("arg1", 42, { key: "value" });
    });

    it("works with zero delay", () => {
      const func = vi.fn();
      const debounced = debounce(func, 0);

      debounced();
      expect(func).not.toHaveBeenCalled();

      vi.advanceTimersByTime(0);
      expect(func).toHaveBeenCalledTimes(1);
    });

    it("has cancel method that prevents pending execution", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced();
      expect(func).not.toHaveBeenCalled();

      debounced.cancel();

      vi.advanceTimersByTime(100);
      expect(func).not.toHaveBeenCalled();
    });

    it("cancel method is idempotent (safe to call multiple times)", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced();
      debounced.cancel();
      debounced.cancel(); // Should not throw
      debounced.cancel();

      vi.advanceTimersByTime(100);
      expect(func).not.toHaveBeenCalled();
    });

    it("can be called again after cancel", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      debounced("first");
      debounced.cancel();

      debounced("second");
      vi.advanceTimersByTime(100);

      expect(func).toHaveBeenCalledTimes(1);
      expect(func).toHaveBeenCalledWith("second");
    });

    it("cancel has no effect when no pending execution", () => {
      const func = vi.fn();
      const debounced = debounce(func, 100);

      // Cancel before any call
      debounced.cancel();

      debounced();
      vi.advanceTimersByTime(100);

      expect(func).toHaveBeenCalledTimes(1);
    });
  });
});
