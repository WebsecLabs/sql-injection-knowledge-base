import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { initializeTabs } from "../../../src/scripts/tabs";

/**
 * Creates a temporary container with the given HTML, runs the callback,
 * and ensures cleanup even if the callback throws.
 */
function withTemporaryContainer(html: string, callback: (container: HTMLElement) => void): void {
  const container = document.createElement("div");
  container.innerHTML = html;
  document.body.appendChild(container);
  try {
    callback(container);
  } finally {
    document.body.removeChild(container);
  }
}

describe("initializeTabs", () => {
  let container: HTMLElement;

  beforeEach(() => {
    // Create a realistic DOM structure for tabs
    container = document.createElement("div");
    container.innerHTML = `
      <div class="tabs" data-default-tab="tab2">
        <div role="tablist">
          <button class="tab-item" data-tab="tab1">Tab 1</button>
          <button class="tab-item" data-tab="tab2">Tab 2</button>
          <button class="tab-item" data-tab="tab3">Tab 3</button>
        </div>
        <div class="tab-content" data-tab="tab1">Content 1</div>
        <div class="tab-content" data-tab="tab2">Content 2</div>
        <div class="tab-content" data-tab="tab3">Content 3</div>
      </div>
    `;
    document.body.appendChild(container);
  });

  afterEach(() => {
    // Clean up DOM
    document.body.removeChild(container);
  });

  describe("ARIA attribute setup", () => {
    it("sets role=tab on tab items", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");

      tabs.forEach((tab) => {
        expect(tab.getAttribute("role")).toBe("tab");
      });
    });

    it("sets unique IDs on tabs", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const ids = Array.from(tabs).map((tab) => tab.getAttribute("id"));

      // All tabs must have non-empty IDs
      expect(ids).toHaveLength(3);
      ids.forEach((id) => {
        expect(id).toBeTruthy();
        expect(id!.length).toBeGreaterThan(0);
      });

      // All IDs must be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("sets aria-controls on tabs pointing to valid panels", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");

      tabs.forEach((tab) => {
        const ariaControls = tab.getAttribute("aria-controls");

        // aria-controls must be defined and non-empty
        expect(ariaControls).toBeTruthy();
        expect(ariaControls!.length).toBeGreaterThan(0);

        // Must reference an existing panel element
        const panel = document.getElementById(ariaControls!);
        expect(
          panel,
          `aria-controls="${ariaControls}" should reference existing element`
        ).toBeTruthy();
        expect(panel?.getAttribute("role")).toBe("tabpanel");
      });
    });

    it("sets role=tabpanel on panels", () => {
      initializeTabs();
      const panels = container.querySelectorAll(".tab-content");

      panels.forEach((panel) => {
        expect(panel.getAttribute("role")).toBe("tabpanel");
      });
    });

    it("sets unique IDs on panels", () => {
      initializeTabs();
      const panels = container.querySelectorAll(".tab-content");
      const ids = Array.from(panels).map((panel) => panel.getAttribute("id"));

      // All panels must have non-empty IDs
      expect(ids).toHaveLength(3);
      ids.forEach((id) => {
        expect(id).toBeTruthy();
        expect(id!.length).toBeGreaterThan(0);
      });

      // All IDs must be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("sets aria-labelledby on panels matching tab IDs", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const panels = container.querySelectorAll(".tab-content");

      // Match panels to tabs by data-tab attribute instead of relying on DOM order
      panels.forEach((panel) => {
        const dataTab = panel.getAttribute("data-tab");
        const matchingTab = Array.from(tabs).find(
          (tab) => tab.getAttribute("data-tab") === dataTab
        );

        expect(matchingTab, `Tab not found for panel with data-tab="${dataTab}"`).toBeTruthy();

        const panelLabelledBy = panel.getAttribute("aria-labelledby");
        const tabId = matchingTab!.getAttribute("id");
        expect(panelLabelledBy).toBe(tabId);
      });
    });

    it("sets tabindex=0 on panels", () => {
      initializeTabs();
      const panels = container.querySelectorAll(".tab-content");

      panels.forEach((panel) => {
        expect(panel.getAttribute("tabindex")).toBe("0");
      });
    });

    it("matches tab aria-controls with panel IDs", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");

      tabs.forEach((tab) => {
        const ariaControls = tab.getAttribute("aria-controls");
        const dataTab = tab.getAttribute("data-tab");
        const panel = container.querySelector(`.tab-content[data-tab="${dataTab}"]`);

        expect(panel).toBeTruthy();
        expect(panel?.getAttribute("id")).toBe(ariaControls);
      });
    });
  });

  describe("default tab selection", () => {
    it("activates the tab specified by data-default-tab", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const tab2 = tabs[1]; // tab2 is default

      expect(tab2.classList.contains("active")).toBe(true);
      expect(tab2.getAttribute("aria-selected")).toBe("true");
      expect(tab2.getAttribute("tabindex")).toBe("0");
    });

    it("shows the panel matching the default tab", () => {
      initializeTabs();
      const panels = container.querySelectorAll(".tab-content");
      const panel2 = panels[1]; // tab2 is default

      expect(panel2.classList.contains("active")).toBe(true);
      expect(panel2.getAttribute("aria-hidden")).toBe("false");
    });

    it("hides non-default panels", () => {
      initializeTabs();
      const panels = container.querySelectorAll(".tab-content");

      expect(panels[0].classList.contains("active")).toBe(false);
      expect(panels[0].getAttribute("aria-hidden")).toBe("true");
      expect(panels[2].classList.contains("active")).toBe(false);
      expect(panels[2].getAttribute("aria-hidden")).toBe("true");
    });

    it("sets tabindex=-1 on inactive tabs", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");

      expect(tabs[0].getAttribute("tabindex")).toBe("-1");
      expect(tabs[2].getAttribute("tabindex")).toBe("-1");
    });

    it("activates first tab when no default is specified", () => {
      withTemporaryContainer(
        `<div class="tabs">
          <div role="tablist">
            <button class="tab-item" data-tab="a">A</button>
            <button class="tab-item" data-tab="b">B</button>
          </div>
          <div class="tab-content" data-tab="a">Content A</div>
          <div class="tab-content" data-tab="b">Content B</div>
        </div>`,
        (newContainer) => {
          initializeTabs();

          const tabs = newContainer.querySelectorAll(".tab-item");
          expect(tabs[0].classList.contains("active")).toBe(true);
          expect(tabs[0].getAttribute("aria-selected")).toBe("true");
        }
      );
    });

    it("respects pre-existing active class when no default is specified", () => {
      withTemporaryContainer(
        `<div class="tabs">
          <div role="tablist">
            <button class="tab-item" data-tab="a">A</button>
            <button class="tab-item active" data-tab="b">B</button>
          </div>
          <div class="tab-content" data-tab="a">Content A</div>
          <div class="tab-content" data-tab="b">Content B</div>
        </div>`,
        (newContainer) => {
          initializeTabs();

          const tabs = newContainer.querySelectorAll(".tab-item");
          expect(tabs[1].classList.contains("active")).toBe(true);
          expect(tabs[1].getAttribute("aria-selected")).toBe("true");
        }
      );
    });

    it("overrides pre-existing active class with data-default-tab", () => {
      withTemporaryContainer(
        `<div class="tabs" data-default-tab="a">
          <div role="tablist">
            <button class="tab-item" data-tab="a">A</button>
            <button class="tab-item active" data-tab="b">B</button>
          </div>
          <div class="tab-content" data-tab="a">Content A</div>
          <div class="tab-content" data-tab="b">Content B</div>
        </div>`,
        (newContainer) => {
          initializeTabs();

          const tabs = newContainer.querySelectorAll(".tab-item");
          expect(tabs[0].classList.contains("active")).toBe(true);
          expect(tabs[0].getAttribute("aria-selected")).toBe("true");
          expect(tabs[1].classList.contains("active")).toBe(false);
        }
      );
    });
  });

  describe("click handlers", () => {
    it("activates tab on click", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;

      // Initially tab2 is active (from data-default-tab)
      expect(tab1.classList.contains("active")).toBe(false);

      // Click tab1
      tab1.click();

      expect(tab1.classList.contains("active")).toBe(true);
      expect(tab1.getAttribute("aria-selected")).toBe("true");
      expect(tab1.getAttribute("tabindex")).toBe("0");
    });

    it("deactivates previously active tab on click", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;
      const tab2 = tabs[1] as HTMLElement;

      // Initially tab2 is active
      expect(tab2.classList.contains("active")).toBe(true);

      // Click tab1
      tab1.click();

      expect(tab2.classList.contains("active")).toBe(false);
      expect(tab2.getAttribute("aria-selected")).toBe("false");
      expect(tab2.getAttribute("tabindex")).toBe("-1");
    });

    it("shows corresponding panel on tab click", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const panels = container.querySelectorAll(".tab-content");
      const tab3 = tabs[2] as HTMLElement;
      const panel3 = panels[2];

      // Click tab3
      tab3.click();

      expect(panel3.classList.contains("active")).toBe(true);
      expect(panel3.getAttribute("aria-hidden")).toBe("false");
    });

    it("hides other panels when tab is clicked", () => {
      initializeTabs();
      const tabs = container.querySelectorAll(".tab-item");
      const panels = container.querySelectorAll(".tab-content");
      const tab3 = tabs[2] as HTMLElement;

      // Click tab3
      tab3.click();

      expect(panels[0].classList.contains("active")).toBe(false);
      expect(panels[0].getAttribute("aria-hidden")).toBe("true");
      expect(panels[1].classList.contains("active")).toBe(false);
      expect(panels[1].getAttribute("aria-hidden")).toBe("true");
    });
  });

  describe("keyboard navigation", () => {
    beforeEach(() => {
      initializeTabs();
    });

    it("moves to next tab on ArrowRight", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab2 = tabs[1] as HTMLElement;
      const tab3 = tabs[2] as HTMLElement;

      // Focus tab2 (the default active tab)
      tab2.focus();

      // Press ArrowRight
      const event = new KeyboardEvent("keydown", {
        key: "ArrowRight",
        bubbles: true,
      });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab2.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab3.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab3);
    });

    it("wraps to first tab when ArrowRight is pressed on last tab", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;
      const tab3 = tabs[2] as HTMLElement;

      tab3.focus();

      const event = new KeyboardEvent("keydown", {
        key: "ArrowRight",
        bubbles: true,
      });
      tab3.dispatchEvent(event);

      expect(tab1.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab1);
    });

    it("moves to previous tab on ArrowLeft", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;
      const tab2 = tabs[1] as HTMLElement;

      // Focus tab2
      tab2.focus();

      const event = new KeyboardEvent("keydown", {
        key: "ArrowLeft",
        bubbles: true,
      });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab2.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab1.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab1);
    });

    it("wraps to last tab when ArrowLeft is pressed on first tab", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;
      const tab3 = tabs[2] as HTMLElement;

      tab1.focus();

      const event = new KeyboardEvent("keydown", {
        key: "ArrowLeft",
        bubbles: true,
      });
      tab1.dispatchEvent(event);

      expect(tab3.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab3);
    });

    it("moves to first tab on Home key", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;
      const tab2 = tabs[1] as HTMLElement;

      tab2.focus();

      const event = new KeyboardEvent("keydown", { key: "Home", bubbles: true });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab2.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab1.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab1);
    });

    it("moves to last tab on End key", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab2 = tabs[1] as HTMLElement;
      const tab3 = tabs[2] as HTMLElement;

      tab2.focus();

      const event = new KeyboardEvent("keydown", { key: "End", bubbles: true });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab2.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab3.classList.contains("active")).toBe(true);
      expect(document.activeElement).toBe(tab3);
    });

    it("activates current tab on Enter key", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;

      // Make tab1 inactive first
      expect(tab1.classList.contains("active")).toBe(false);

      tab1.focus();

      const event = new KeyboardEvent("keydown", { key: "Enter", bubbles: true });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab1.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab1.classList.contains("active")).toBe(true);
    });

    it("activates current tab on Space key", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab1 = tabs[0] as HTMLElement;

      // Make tab1 inactive first
      expect(tab1.classList.contains("active")).toBe(false);

      tab1.focus();

      const event = new KeyboardEvent("keydown", { key: " ", bubbles: true });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab1.dispatchEvent(event);

      expect(preventDefault).toHaveBeenCalled();
      expect(tab1.classList.contains("active")).toBe(true);
    });

    it("does nothing for other keys", () => {
      const tabs = container.querySelectorAll(".tab-item");
      const tab2 = tabs[1] as HTMLElement;

      tab2.focus();
      const initialActive = tab2.classList.contains("active");

      const event = new KeyboardEvent("keydown", { key: "a", bubbles: true });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tab2.dispatchEvent(event);

      expect(preventDefault).not.toHaveBeenCalled();
      expect(tab2.classList.contains("active")).toBe(initialActive);
    });

    it("ignores keyboard events when no tab is focused", () => {
      const tabList = container.querySelector('[role="tablist"]');

      // Blur all tabs
      const tabs = container.querySelectorAll(".tab-item");
      tabs.forEach((tab) => (tab as HTMLElement).blur());

      const event = new KeyboardEvent("keydown", {
        key: "ArrowRight",
        bubbles: true,
      });
      const preventDefault = vi.spyOn(event, "preventDefault");
      tabList?.dispatchEvent(event);

      // Should not prevent default or change anything
      expect(preventDefault).not.toHaveBeenCalled();
    });
  });

  describe("WeakSet initialization tracking", () => {
    it("prevents duplicate initialization", () => {
      initializeTabs();

      const tabs = container.querySelectorAll(".tab-item");

      // Initialize again
      initializeTabs();

      // We can't directly test listener count, but we can verify behavior
      // by checking that tabs still work correctly after re-initialization
      const tab1 = tabs[0] as HTMLElement;
      tab1.click();
      expect(tab1.classList.contains("active")).toBe(true);
    });

    it("initializes multiple separate tab containers independently", () => {
      // Add a second tab container
      const container2 = document.createElement("div");
      container2.innerHTML = `
        <div class="tabs" data-default-tab="x">
          <div role="tablist">
            <button class="tab-item" data-tab="x">X</button>
            <button class="tab-item" data-tab="y">Y</button>
          </div>
          <div class="tab-content" data-tab="x">Content X</div>
          <div class="tab-content" data-tab="y">Content Y</div>
        </div>
      `;
      document.body.appendChild(container2);

      initializeTabs();

      // Check first container
      const tabs1 = container.querySelectorAll(".tab-item");
      expect(tabs1[1].classList.contains("active")).toBe(true);

      // Check second container
      const tabs2 = container2.querySelectorAll(".tab-item");
      expect(tabs2[0].classList.contains("active")).toBe(true);

      document.body.removeChild(container2);
    });
  });

  describe("edge cases", () => {
    it("handles tabs without data-tab attribute", () => {
      withTemporaryContainer(
        `<div class="tabs">
          <div role="tablist">
            <button class="tab-item">No Data Tab</button>
          </div>
          <div class="tab-content" data-tab="tab-0">Content</div>
        </div>`,
        (newContainer) => {
          // Should not throw
          expect(() => initializeTabs()).not.toThrow();

          const tab = newContainer.querySelector(".tab-item");
          expect(tab?.getAttribute("role")).toBe("tab");
        }
      );
    });

    it("handles missing panel for a tab", () => {
      withTemporaryContainer(
        `<div class="tabs">
          <div role="tablist">
            <button class="tab-item" data-tab="orphan">Orphan Tab</button>
          </div>
        </div>`,
        () => {
          // Should not throw
          expect(() => initializeTabs()).not.toThrow();
        }
      );
    });

    it("handles tabs without tablist", () => {
      withTemporaryContainer(
        `<div class="tabs">
          <button class="tab-item" data-tab="tab1">Tab 1</button>
          <div class="tab-content" data-tab="tab1">Content 1</div>
        </div>`,
        (newContainer) => {
          // Should not throw, but keyboard navigation won't work
          expect(() => initializeTabs()).not.toThrow();

          const tab = newContainer.querySelector(".tab-item");
          expect(tab?.getAttribute("role")).toBe("tab");
        }
      );
    });

    it("handles empty tab container", () => {
      withTemporaryContainer(`<div class="tabs"></div>`, () => {
        // Should not throw
        expect(() => initializeTabs()).not.toThrow();
      });
    });

    it("handles invalid default tab ID by activating first tab", () => {
      withTemporaryContainer(
        `<div class="tabs" data-default-tab="nonexistent">
          <div role="tablist">
            <button class="tab-item" data-tab="a">A</button>
            <button class="tab-item" data-tab="b">B</button>
          </div>
          <div class="tab-content" data-tab="a">Content A</div>
          <div class="tab-content" data-tab="b">Content B</div>
        </div>`,
        (newContainer) => {
          initializeTabs();

          // Should fall back to first tab when default tab ID doesn't exist
          const firstTab = newContainer.querySelector('.tab-item[data-tab="a"]');
          const secondTab = newContainer.querySelector('.tab-item[data-tab="b"]');

          expect(firstTab?.classList.contains("active")).toBe(true);
          expect(firstTab?.getAttribute("aria-selected")).toBe("true");
          expect(secondTab?.classList.contains("active")).toBe(false);
          expect(secondTab?.getAttribute("aria-selected")).toBe("false");
        }
      );
    });
  });

  describe("no tab containers", () => {
    it("does nothing when no .tabs elements exist", () => {
      // Remove all tabs
      const allTabs = document.querySelectorAll(".tabs");
      allTabs.forEach((tab) => tab.remove());

      // Should not throw
      expect(() => initializeTabs()).not.toThrow();
    });
  });
});
