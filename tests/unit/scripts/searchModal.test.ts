/**
 * Tests for searchModal module
 * @vitest-environment jsdom
 *
 * The searchModal module does not export functions directly -- all functions
 * are module-private. We test via DOM interactions:
 * 1. Set up DOM elements that the module expects
 * 2. Import the module (triggers initialization via side effects)
 * 3. Dispatch events and assert DOM state changes
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// ---------------------------------------------------------------------------
// Pagefind mock
// ---------------------------------------------------------------------------

const mockPagefindSearch = vi.fn();
const mockPagefindInit = vi.fn().mockResolvedValue(undefined);

/**
 * Creates a mock Pagefind result with the given data.
 */
function makeMockResult(data: { url: string; title: string; excerpt: string; database?: string }) {
  return {
    data: vi.fn().mockResolvedValue({
      url: data.url,
      meta: { title: data.title },
      excerpt: data.excerpt,
      filters: data.database ? { database: [data.database] } : {},
    }),
  };
}

// We need to mock the dynamic import of pagefind before importing the module.
// The searchModal does: import(`${base}pagefind/pagefind.js`)
// We mock this at the vi.mock level.
vi.mock("/pagefind/pagefind.js", () => ({
  init: mockPagefindInit,
  search: mockPagefindSearch,
}));

// ---------------------------------------------------------------------------
// DOM setup helper
// ---------------------------------------------------------------------------

/**
 * Creates the full DOM structure expected by searchModal.ts
 */
function setupSearchModalDOM(): void {
  document.body.innerHTML = "";
  document.body.style.cssText = "";
  document.documentElement.style.cssText = "";

  const content = document.createDocumentFragment();

  const nav = document.createElement("nav");
  nav.textContent = "Navigation";
  content.appendChild(nav);

  const main = document.createElement("main");
  main.textContent = "Main content";
  content.appendChild(main);

  const footer = document.createElement("footer");
  footer.textContent = "Footer";
  content.appendChild(footer);

  const sidebar = document.createElement("div");
  sidebar.className = "sidebar";
  sidebar.textContent = "Sidebar";
  content.appendChild(sidebar);

  const buttonContainer = document.createElement("div");
  buttonContainer.className = "button-container";
  buttonContainer.textContent = "Buttons";
  content.appendChild(buttonContainer);

  const trigger = document.createElement("button");
  trigger.id = "search-trigger";
  const kbd = document.createElement("span");
  kbd.id = "search-trigger-kbd";
  kbd.textContent = "Ctrl K";
  trigger.appendChild(kbd);
  trigger.appendChild(document.createTextNode(" Search"));
  content.appendChild(trigger);

  const dialog = document.createElement("dialog");
  dialog.id = "search-modal";

  const container = document.createElement("div");
  container.className = "search-modal-container";

  const input = document.createElement("input");
  input.id = "search-modal-input";
  input.type = "text";
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-activedescendant", "");
  input.setAttribute("aria-controls", "search-modal-results");
  container.appendChild(input);

  const resultsList = document.createElement("ul");
  resultsList.id = "search-modal-results";
  resultsList.setAttribute("role", "listbox");
  container.appendChild(resultsList);

  const emptyEl = document.createElement("div");
  emptyEl.id = "search-modal-empty";
  emptyEl.hidden = true;
  emptyEl.textContent = "No results found.";
  container.appendChild(emptyEl);

  const initialEl = document.createElement("div");
  initialEl.id = "search-modal-initial";
  initialEl.textContent = "Type to search...";
  container.appendChild(initialEl);

  const srStatus = document.createElement("div");
  srStatus.id = "search-modal-sr-status";
  srStatus.setAttribute("role", "status");
  srStatus.setAttribute("aria-live", "polite");
  container.appendChild(srStatus);

  dialog.appendChild(container);
  content.appendChild(dialog);

  document.body.appendChild(content);
}

// ---------------------------------------------------------------------------
// Module import helper
//
// Since searchModal.ts sets up listeners on import via initOnce + astro:page-load,
// we need to reset module state between tests and trigger the page-load event.
// ---------------------------------------------------------------------------

async function initModule(): Promise<void> {
  // Reset the initOnce tracker so global listeners re-register
  const INIT_TRACKER_KEY = Symbol.for("__domUtils_initTracker__");
  const win = window as unknown as Record<symbol, Record<string, boolean> | undefined>;
  delete win[INIT_TRACKER_KEY];

  // Dynamically import the module (cache-busted via vi.resetModules)
  await import("../../../src/scripts/searchModal");

  // Fire astro:page-load to trigger bindModalEvents + updateKbdText
  document.dispatchEvent(new Event("astro:page-load"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("searchModal", () => {
  beforeEach(async () => {
    vi.useFakeTimers();
    vi.resetModules();
    setupSearchModalDOM();

    // jsdom doesn't implement HTMLDialogElement.showModal / close
    const dialog = document.getElementById("search-modal") as HTMLDialogElement;
    if (dialog) {
      dialog.showModal = vi.fn(() => {
        dialog.setAttribute("open", "");
        Object.defineProperty(dialog, "open", { value: true, writable: true, configurable: true });
      });
      dialog.close = vi.fn(() => {
        dialog.removeAttribute("open");
        Object.defineProperty(dialog, "open", { value: false, writable: true, configurable: true });
        dialog.dispatchEvent(new Event("close"));
      });
      Object.defineProperty(dialog, "open", { value: false, writable: true, configurable: true });
    }

    // Mock window.scrollY and window.scrollTo
    Object.defineProperty(window, "scrollY", { value: 0, writable: true, configurable: true });
    window.scrollTo = vi.fn();

    // Mock matchMedia for prefers-reduced-motion
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: false }));

    // Mock requestAnimationFrame
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });

    // jsdom doesn't implement scrollIntoView
    Element.prototype.scrollIntoView = vi.fn();

    mockPagefindSearch.mockReset();
    mockPagefindInit.mockReset().mockResolvedValue(undefined);

    await initModule();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    document.body.textContent = "";
  });

  // -------------------------------------------------------------------------
  // Modal open / close
  // -------------------------------------------------------------------------

  describe("modal open/close", () => {
    it("opens modal when search trigger is clicked", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      expect(dialog.showModal).toHaveBeenCalled();
    });

    it("opens modal with Ctrl+K shortcut", () => {
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true })
      );

      expect(dialog.showModal).toHaveBeenCalled();
    });

    it("opens modal with Meta+K shortcut (Mac)", () => {
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true })
      );

      expect(dialog.showModal).toHaveBeenCalled();
    });

    it("does not open modal with plain K key", () => {
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", bubbles: true }));

      expect(dialog.showModal).not.toHaveBeenCalled();
    });

    it("focuses search input when modal opens", () => {
      const trigger = document.getElementById("search-trigger")!;
      const input = document.getElementById("search-modal-input")!;

      trigger.click();

      expect(document.activeElement).toBe(input);
    });

    it("closes modal via dialog close event and cleans up", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      // Open
      trigger.click();
      expect(dialog.showModal).toHaveBeenCalled();

      // Directly fire the close event (simulating dialog.close())
      (dialog as unknown as { close: () => void }).close();

      // Verify cleanup happened
      expect(document.body.style.position).toBe("");
      expect(document.documentElement.style.overflow).toBe("");
    });
  });

  // -------------------------------------------------------------------------
  // Scroll lock
  // -------------------------------------------------------------------------

  describe("scroll lock", () => {
    it("locks scroll when modal opens", () => {
      Object.defineProperty(window, "scrollY", { value: 150, writable: true, configurable: true });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      expect(document.body.style.position).toBe("fixed");
      expect(document.body.style.top).toBe("-150px");
      expect(document.body.style.width).toBe("100%");
      expect(document.documentElement.style.overflow).toBe("hidden");
    });

    it("unlocks scroll when modal closes and restores scroll position", () => {
      Object.defineProperty(window, "scrollY", { value: 200, writable: true, configurable: true });

      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      // Close the dialog
      (dialog as unknown as { close: () => void }).close();

      expect(document.body.style.position).toBe("");
      expect(document.body.style.top).toBe("");
      expect(document.body.style.width).toBe("");
      expect(document.documentElement.style.overflow).toBe("");
      expect(window.scrollTo).toHaveBeenCalledWith(0, 200);
    });
  });

  // -------------------------------------------------------------------------
  // Inert attribute management
  // -------------------------------------------------------------------------

  describe("inert management", () => {
    it("applies inert to main, nav, footer, .sidebar, .button-container on open", () => {
      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      expect(document.querySelector("main")?.hasAttribute("inert")).toBe(true);
      expect(document.querySelector("nav")?.hasAttribute("inert")).toBe(true);
      expect(document.querySelector("footer")?.hasAttribute("inert")).toBe(true);
      expect(document.querySelector(".sidebar")?.hasAttribute("inert")).toBe(true);
      expect(document.querySelector(".button-container")?.hasAttribute("inert")).toBe(true);
    });

    it("removes inert from all elements on close", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      // Verify inert is set
      expect(document.querySelector("main")?.hasAttribute("inert")).toBe(true);

      // Close
      (dialog as unknown as { close: () => void }).close();

      expect(document.querySelector("main")?.hasAttribute("inert")).toBe(false);
      expect(document.querySelector("nav")?.hasAttribute("inert")).toBe(false);
      expect(document.querySelector("footer")?.hasAttribute("inert")).toBe(false);
      expect(document.querySelector(".sidebar")?.hasAttribute("inert")).toBe(false);
      expect(document.querySelector(".button-container")?.hasAttribute("inert")).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Focus management
  // -------------------------------------------------------------------------

  describe("focus management", () => {
    it("restores focus to previously focused element on close", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      // Focus the trigger before opening
      trigger.focus();
      expect(document.activeElement).toBe(trigger);

      trigger.click();

      // Close
      (dialog as unknown as { close: () => void }).close();

      expect(document.activeElement).toBe(trigger);
    });
  });

  // -------------------------------------------------------------------------
  // Search state reset
  // -------------------------------------------------------------------------

  describe("search state reset", () => {
    it("clears input and results when modal closes", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;
      const input = document.getElementById("search-modal-input") as HTMLInputElement;

      trigger.click();

      // Set some state
      input.value = "test query";
      const resultsList = document.getElementById("search-modal-results")!;
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.textContent = "Result";
      resultsList.appendChild(li);

      // Close
      (dialog as unknown as { close: () => void }).close();

      expect(input.value).toBe("");
      expect(resultsList.children.length).toBe(0);
      expect(input.getAttribute("aria-expanded")).toBe("false");
      expect(input.getAttribute("aria-activedescendant")).toBe("");
    });

    it("shows initial state element and hides empty state on reset", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;
      const initialEl = document.getElementById("search-modal-initial")!;
      const emptyEl = document.getElementById("search-modal-empty")!;

      trigger.click();

      // Simulate state change
      initialEl.hidden = true;
      emptyEl.hidden = false;

      // Close
      (dialog as unknown as { close: () => void }).close();

      expect(initialEl.hidden).toBe(false);
      expect(emptyEl.hidden).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Result rendering
  // -------------------------------------------------------------------------

  describe("result rendering", () => {
    async function triggerSearch(query: string, results: ReturnType<typeof makeMockResult>[]) {
      mockPagefindSearch.mockResolvedValue({ results });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = query;
      input.dispatchEvent(new Event("input"));

      // Advance past debounce (200ms)
      await vi.advanceTimersByTimeAsync(200);

      // Flush promises for async search
      await vi.runAllTimersAsync();
    }

    it("renders results with proper structure", async () => {
      await triggerSearch("test", [
        makeMockResult({
          url: "/mysql/injection",
          title: "SQL Injection",
          excerpt: "A test excerpt",
          database: "mysql",
        }),
      ]);

      const resultsList = document.getElementById("search-modal-results")!;
      const items = resultsList.querySelectorAll('[role="option"]');

      expect(items).toHaveLength(1);

      const item = items[0] as HTMLElement;
      expect(item.id).toBe("search-result-0");
      expect(item.getAttribute("tabindex")).toBe("-1");
      expect(item.getAttribute("aria-selected")).toBe("false");
      expect(item.classList.contains("search-result-item")).toBe(true);
      expect(item.dataset.url).toBe("/mysql/injection");
    });

    it("renders title text and database badge", async () => {
      await triggerSearch("test", [
        makeMockResult({
          url: "/mysql/injection",
          title: "SQL Injection",
          excerpt: "excerpt",
          database: "mysql",
        }),
      ]);

      const titleRow = document.querySelector(".search-result-title")!;
      const titleSpan = titleRow.querySelector("span:first-child")!;
      expect(titleSpan.textContent).toBe("SQL Injection");

      const badge = titleRow.querySelector(".search-result-badge")!;
      expect(badge.textContent).toBe("MySQL");
      expect(badge.getAttribute("data-database")).toBe("mysql");
    });

    it("renders result without badge when no database filter", async () => {
      await triggerSearch("test", [
        makeMockResult({
          url: "/extras/resources",
          title: "Resources",
          excerpt: "excerpt",
        }),
      ]);

      const badge = document.querySelector(".search-result-badge");
      expect(badge).toBeNull();
    });

    it("renders excerpt as snippet", async () => {
      await triggerSearch("test", [
        makeMockResult({
          url: "/test",
          title: "Test",
          excerpt: "This is a test excerpt",
        }),
      ]);

      const snippet = document.querySelector(".search-result-snippet")!;
      expect(snippet.textContent).toContain("This is a test excerpt");
    });

    it("renders 'Untitled' when title is missing", async () => {
      const result = {
        data: vi.fn().mockResolvedValue({
          url: "/test",
          meta: {},
          excerpt: "excerpt",
          filters: {},
        }),
      };

      mockPagefindSearch.mockResolvedValue({ results: [result] });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      const titleSpan = document.querySelector(".search-result-title span:first-child")!;
      expect(titleSpan.textContent).toBe("Untitled");
    });

    it("shows empty state when no results found", async () => {
      await triggerSearch("nonexistent", []);

      const emptyEl = document.getElementById("search-modal-empty")!;
      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      const srStatus = document.getElementById("search-modal-sr-status")!;

      expect(emptyEl.hidden).toBe(false);
      expect(input.getAttribute("aria-expanded")).toBe("false");
      expect(srStatus.textContent).toBe("No results found.");
    });

    it("hides empty state and sets aria-expanded when results exist", async () => {
      await triggerSearch("test", [makeMockResult({ url: "/test", title: "Test", excerpt: "e" })]);

      const emptyEl = document.getElementById("search-modal-empty")!;
      const input = document.getElementById("search-modal-input") as HTMLInputElement;

      expect(emptyEl.hidden).toBe(true);
      expect(input.getAttribute("aria-expanded")).toBe("true");
    });

    it("announces result count to screen readers", async () => {
      await triggerSearch("test", [
        makeMockResult({ url: "/a", title: "A", excerpt: "e" }),
        makeMockResult({ url: "/b", title: "B", excerpt: "e" }),
        makeMockResult({ url: "/c", title: "C", excerpt: "e" }),
      ]);

      const srStatus = document.getElementById("search-modal-sr-status")!;
      expect(srStatus.textContent).toBe("3 results found.");
    });

    it("announces singular result to screen readers", async () => {
      await triggerSearch("test", [makeMockResult({ url: "/a", title: "A", excerpt: "e" })]);

      const srStatus = document.getElementById("search-modal-sr-status")!;
      expect(srStatus.textContent).toBe("1 result found.");
    });

    it("hides initial state when query is entered", async () => {
      await triggerSearch("test", [makeMockResult({ url: "/a", title: "A", excerpt: "e" })]);

      const initialEl = document.getElementById("search-modal-initial")!;
      expect(initialEl.hidden).toBe(true);
    });

    it("renders multiple results with sequential IDs", async () => {
      await triggerSearch("test", [
        makeMockResult({ url: "/a", title: "A", excerpt: "e" }),
        makeMockResult({ url: "/b", title: "B", excerpt: "e" }),
      ]);

      const items = document.querySelectorAll('[role="option"]');
      expect(items).toHaveLength(2);
      expect(items[0].id).toBe("search-result-0");
      expect(items[1].id).toBe("search-result-1");
    });
  });

  // -------------------------------------------------------------------------
  // Keyboard navigation
  // -------------------------------------------------------------------------

  describe("keyboard navigation", () => {
    async function setupWithResults() {
      mockPagefindSearch.mockResolvedValue({
        results: [
          makeMockResult({ url: "/a", title: "Result A", excerpt: "e" }),
          makeMockResult({ url: "/b", title: "Result B", excerpt: "e" }),
          makeMockResult({ url: "/c", title: "Result C", excerpt: "e" }),
        ],
      });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      return input;
    }

    it("ArrowDown selects the first result", async () => {
      const input = await setupWithResults();

      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      const items = document.querySelectorAll('[role="option"]');
      expect(items[0].getAttribute("aria-selected")).toBe("true");
      expect(input.getAttribute("aria-activedescendant")).toBe("search-result-0");
    });

    it("ArrowDown wraps from last to first", async () => {
      const input = await setupWithResults();

      // Press ArrowDown 3 times to get to last item
      for (let i = 0; i < 3; i++) {
        input.dispatchEvent(
          new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
        );
      }

      const items = document.querySelectorAll('[role="option"]');
      expect(items[2].getAttribute("aria-selected")).toBe("true");

      // One more ArrowDown should wrap to first
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      expect(items[0].getAttribute("aria-selected")).toBe("true");
      expect(items[2].getAttribute("aria-selected")).toBe("false");
    });

    it("ArrowUp wraps from first to last", async () => {
      const input = await setupWithResults();

      // First ArrowDown to select first item
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      const items = document.querySelectorAll('[role="option"]');
      expect(items[0].getAttribute("aria-selected")).toBe("true");

      // ArrowUp should wrap to last
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true, cancelable: true })
      );

      expect(items[2].getAttribute("aria-selected")).toBe("true");
      expect(items[0].getAttribute("aria-selected")).toBe("false");
      expect(input.getAttribute("aria-activedescendant")).toBe("search-result-2");
    });

    it("ArrowDown deselects previous item", async () => {
      const input = await setupWithResults();

      // Select first
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      // Move to second
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      const items = document.querySelectorAll('[role="option"]');
      expect(items[0].getAttribute("aria-selected")).toBe("false");
      expect(items[1].getAttribute("aria-selected")).toBe("true");
    });

    it("Enter on selected result triggers navigation", async () => {
      const input = await setupWithResults();

      // Select first result
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })
      );

      // Mock location.href setter
      const hrefSetter = vi.fn();
      Object.defineProperty(window, "location", {
        value: { href: "" },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(window.location, "href", {
        set: hrefSetter,
        configurable: true,
      });

      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })
      );

      expect(hrefSetter).toHaveBeenCalledWith("/a");
    });

    it("ArrowDown/Up prevents default", async () => {
      const input = await setupWithResults();

      const downEvent = new KeyboardEvent("keydown", {
        key: "ArrowDown",
        bubbles: true,
        cancelable: true,
      });
      const preventDefaultSpy = vi.spyOn(downEvent, "preventDefault");
      input.dispatchEvent(downEvent);
      expect(preventDefaultSpy).toHaveBeenCalled();

      const upEvent = new KeyboardEvent("keydown", {
        key: "ArrowUp",
        bubbles: true,
        cancelable: true,
      });
      const upPreventDefaultSpy = vi.spyOn(upEvent, "preventDefault");
      input.dispatchEvent(upEvent);
      expect(upPreventDefaultSpy).toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Search error handling
  // -------------------------------------------------------------------------

  describe("search error handling", () => {
    it("shows generic error message on search failure", async () => {
      mockPagefindSearch.mockRejectedValue(new Error("Something went wrong"));

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      const emptyEl = document.getElementById("search-modal-empty")!;
      expect(emptyEl.hidden).toBe(false);
      // The error message depends on pagefindLoadError state. Since the mock
      // import succeeds (init doesn't fail), the error is from search() itself,
      // so we get "Search failed. Please try again."
      expect(emptyEl.textContent).toBe("Search failed. Please try again.");
    });

    it("announces error to screen readers", async () => {
      mockPagefindSearch.mockRejectedValue(new Error("fail"));

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      const srStatus = document.getElementById("search-modal-sr-status")!;
      expect(srStatus.textContent).toBe("Search failed.");
    });
  });

  // -------------------------------------------------------------------------
  // Empty query handling
  // -------------------------------------------------------------------------

  describe("empty query handling", () => {
    it("resets state when input is cleared", async () => {
      // First perform a search
      mockPagefindSearch.mockResolvedValue({
        results: [makeMockResult({ url: "/a", title: "A", excerpt: "e" })],
      });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      // Verify results exist
      const resultsList = document.getElementById("search-modal-results")!;
      expect(resultsList.children.length).toBeGreaterThan(0);

      // Clear input
      input.value = "";
      input.dispatchEvent(new Event("input"));

      // Should immediately reset (no debounce for empty)
      expect(resultsList.children.length).toBe(0);
      expect(input.getAttribute("aria-expanded")).toBe("false");
    });

    it("resets state when input is only whitespace", async () => {
      mockPagefindSearch.mockResolvedValue({
        results: [makeMockResult({ url: "/a", title: "A", excerpt: "e" })],
      });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      // Set whitespace-only
      input.value = "   ";
      input.dispatchEvent(new Event("input"));

      const resultsList = document.getElementById("search-modal-results")!;
      expect(resultsList.children.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Platform-aware kbd text
  // -------------------------------------------------------------------------

  describe("kbd text update", () => {
    it("shows Ctrl K by default (non-Mac)", () => {
      const kbdEl = document.getElementById("search-trigger-kbd")!;
      // In jsdom, navigator.platform is empty and userAgentData is not present,
      // so detectMac() returns false and the text stays as "Ctrl K".
      expect(kbdEl.textContent).toBe("Ctrl K");
    });
  });

  // -------------------------------------------------------------------------
  // View Transitions integration
  // -------------------------------------------------------------------------

  describe("view transitions", () => {
    it("closes modal on astro:before-swap", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();
      expect(dialog.showModal).toHaveBeenCalled();

      // Fire before-swap
      document.dispatchEvent(new Event("astro:before-swap"));

      expect(dialog.close).toHaveBeenCalled();
      expect(document.body.style.position).toBe("");
      expect(document.documentElement.style.overflow).toBe("");
    });

    it("does nothing on astro:before-swap if modal is not open", () => {
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      // Fire before-swap without opening
      document.dispatchEvent(new Event("astro:before-swap"));

      // close should not be called since dialog is not open
      expect(dialog.close).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Backdrop click
  // -------------------------------------------------------------------------

  describe("backdrop click", () => {
    it("closes modal when clicking the dialog element directly (backdrop)", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      // Click on the dialog itself (simulating backdrop click)
      const clickEvent = new MouseEvent("click", { bubbles: true });
      Object.defineProperty(clickEvent, "target", { value: dialog });
      dialog.dispatchEvent(clickEvent);

      // The closeSearchModal uses setTimeout for animation
      vi.advanceTimersByTime(100);

      expect(dialog.close).toHaveBeenCalled();
    });

    it("does not close modal when clicking inside the container", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      // Reset the close mock
      (dialog.close as ReturnType<typeof vi.fn>).mockClear();

      // Click on the input inside the dialog
      const input = document.getElementById("search-modal-input")!;
      const clickEvent = new MouseEvent("click", { bubbles: true });
      Object.defineProperty(clickEvent, "target", { value: input });
      dialog.dispatchEvent(clickEvent);

      vi.advanceTimersByTime(100);

      expect(dialog.close).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Cancel event (Escape key handling)
  // -------------------------------------------------------------------------

  describe("cancel event handling", () => {
    it("prevents default cancel and uses animated close instead", () => {
      const trigger = document.getElementById("search-trigger")!;
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      trigger.click();

      const cancelEvent = new Event("cancel", { cancelable: true });
      const preventDefaultSpy = vi.spyOn(cancelEvent, "preventDefault");
      dialog.dispatchEvent(cancelEvent);

      expect(preventDefaultSpy).toHaveBeenCalled();

      // After delay, dialog should close
      vi.advanceTimersByTime(100);
      expect(dialog.close).toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Result click navigation
  // -------------------------------------------------------------------------

  describe("result click", () => {
    it("navigates when clicking a result", async () => {
      mockPagefindSearch.mockResolvedValue({
        results: [makeMockResult({ url: "/mysql/test", title: "Test", excerpt: "e" })],
      });

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      const input = document.getElementById("search-modal-input") as HTMLInputElement;
      input.value = "test";
      input.dispatchEvent(new Event("input"));
      await vi.advanceTimersByTimeAsync(200);
      await vi.runAllTimersAsync();

      // Mock location.href
      const hrefSetter = vi.fn();
      Object.defineProperty(window, "location", {
        value: { href: "" },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(window.location, "href", {
        set: hrefSetter,
        configurable: true,
      });

      const resultItem = document.querySelector(".search-result-item") as HTMLElement;
      resultItem.click();

      expect(hrefSetter).toHaveBeenCalledWith("/mysql/test");
    });
  });

  // -------------------------------------------------------------------------
  // Mobile sidebar close
  // -------------------------------------------------------------------------

  describe("mobile sidebar", () => {
    it("closes mobile sidebar when opening search modal", () => {
      const sidebar = document.querySelector(".sidebar") as HTMLElement;
      sidebar.classList.add("mobile-open");

      // Add overlay
      const overlay = document.createElement("div");
      overlay.id = "sidebar-overlay";
      overlay.classList.add("active");
      document.body.appendChild(overlay);

      const trigger = document.getElementById("search-trigger")!;
      trigger.click();

      expect(sidebar.classList.contains("mobile-open")).toBe(false);
      expect(overlay.classList.contains("active")).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // initOnce guard
  // -------------------------------------------------------------------------

  describe("initialization", () => {
    it("does not duplicate global listeners on multiple imports", async () => {
      const dialog = document.getElementById("search-modal") as HTMLDialogElement;

      // Import again (simulating View Transition page-load)
      document.dispatchEvent(new Event("astro:page-load"));

      // Trigger Ctrl+K
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true })
      );

      // showModal should be called exactly once (not duplicated)
      expect(dialog.showModal).toHaveBeenCalledTimes(1);
    });
  });
});
