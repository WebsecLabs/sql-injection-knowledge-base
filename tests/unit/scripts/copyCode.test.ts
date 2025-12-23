/**
 * Tests for copyCode module
 * @vitest-environment jsdom
 */
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { addCopyButtons } from "../../../src/scripts/copyCode";

describe("copyCode", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("addCopyButtons", () => {
    it("adds copy button to pre > code blocks", () => {
      document.body.innerHTML = `
        <pre><code>const x = 1;</code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).not.toBeNull();
      expect(button?.textContent).toBe("Copy");
    });

    it("sets correct accessibility attributes on button", () => {
      document.body.innerHTML = `
        <pre><code>test code</code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button?.getAttribute("aria-label")).toBe("Copy code");
      expect(button?.getAttribute("title")).toBe("Copy code to clipboard");
    });

    it("removes existing copy buttons before adding new ones", () => {
      document.body.innerHTML = `
        <pre>
          <code>test</code>
          <button class="copy-button">Old Copy</button>
        </pre>
      `;

      addCopyButtons();

      const buttons = document.querySelectorAll(".copy-button");
      expect(buttons.length).toBe(1);
      expect(buttons[0].textContent).toBe("Copy");
    });

    it("adds copy buttons to multiple code blocks", () => {
      document.body.innerHTML = `
        <pre><code>block 1</code></pre>
        <pre><code>block 2</code></pre>
        <pre><code>block 3</code></pre>
      `;

      addCopyButtons();

      const buttons = document.querySelectorAll(".copy-button");
      expect(buttons.length).toBe(3);
    });

    it("does not add button if parent is not pre or astro-code", () => {
      document.body.innerHTML = `
        <div><code>inline code</code></div>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).toBeNull();
    });

    it("adds copy button to div.astro-code containers", () => {
      document.body.innerHTML = `
        <div class="astro-code"><code>const x = 1;</code></div>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).not.toBeNull();
      expect(button?.textContent).toBe("Copy");
      // Verify button is appended to astro-code div
      const astroCodeDiv = document.querySelector(".astro-code");
      expect(button?.parentNode).toBe(astroCodeDiv);
    });

    it("button is appended to the pre element", () => {
      document.body.innerHTML = `
        <pre><code>test code</code></pre>
      `;

      addCopyButtons();

      const pre = document.querySelector("pre");
      const button = pre?.querySelector(".copy-button");
      expect(button).not.toBeNull();
      expect(button?.parentNode).toBe(pre);
    });
  });

  describe("button click handler", () => {
    it("button has click event listener", () => {
      document.body.innerHTML = `
        <pre><code>test code</code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button") as HTMLButtonElement;

      // This test only verifies that a click handler is attached and doesn't throw.
      // We don't mock navigator.clipboard here because we're not testing clipboard
      // behavior - that's covered by the "copies code to clipboard" test below which
      // properly mocks the clipboard API.
      expect(() => button.click()).not.toThrow();
    });

    it("copies code to clipboard using writeText API", async () => {
      const expectedCode = "const x = 42;";
      document.body.innerHTML = `
        <pre><code>${expectedCode}</code></pre>
      `;

      // Mock the clipboard API
      const mockWriteText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: mockWriteText },
        writable: true,
        configurable: true,
      });

      addCopyButtons();

      const button = document.querySelector(".copy-button") as HTMLButtonElement;
      button.click();

      // Wait for the async clipboard operation
      await vi.waitFor(() => {
        expect(mockWriteText).toHaveBeenCalledWith(expectedCode);
      });
    });
  });

  describe("clipboard fallback behavior", () => {
    it("falls back to execCommand when clipboard API rejects", async () => {
      document.body.innerHTML = `<pre><code>test code</code></pre>`;

      // Mock clipboard to reject
      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: vi.fn().mockRejectedValue(new Error("Denied")) },
        writable: true,
        configurable: true,
      });

      // JSDOM doesn't have execCommand - define it first, then spy
      (document as unknown as { execCommand: (cmd: string) => boolean }).execCommand = vi
        .fn()
        .mockReturnValue(true);
      const execCommandSpy = vi.spyOn(document, "execCommand");

      addCopyButtons();
      const button = document.querySelector(".copy-button") as HTMLButtonElement;
      button.click();

      await vi.waitFor(() => {
        expect(execCommandSpy).toHaveBeenCalledWith("copy");
      });
    });

    it("shows error feedback when both clipboard and execCommand fail", async () => {
      document.body.innerHTML = `<pre><code>test code</code></pre>`;

      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: vi.fn().mockRejectedValue(new Error("Denied")) },
        writable: true,
        configurable: true,
      });

      // JSDOM doesn't have execCommand - define it to throw (using vi.fn for consistency)
      (document as unknown as { execCommand: (cmd: string) => boolean }).execCommand = vi
        .fn()
        .mockImplementation(() => {
          throw new Error("execCommand failed");
        });

      // Suppress expected console.error from legacyCopy
      vi.spyOn(console, "error").mockImplementation(() => {});

      addCopyButtons();
      const button = document.querySelector(".copy-button") as HTMLButtonElement;
      button.click();

      await vi.waitFor(() => {
        expect(button.textContent).toBe("Error!");
      });
    });

    it("reverts button text after feedback duration", async () => {
      vi.useFakeTimers();
      document.body.innerHTML = `<pre><code>test code</code></pre>`;

      // Create a deferred promise to control timing
      let resolveClipboard!: () => void;
      const clipboardPromise = new Promise<void>((resolve) => {
        resolveClipboard = resolve;
      });

      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: vi.fn().mockImplementation(() => clipboardPromise) },
        writable: true,
        configurable: true,
      });

      addCopyButtons();
      const button = document.querySelector(".copy-button") as HTMLButtonElement;
      button.click();

      // Button should still say "Copy" before promise resolves
      expect(button.textContent).toBe("Copy");

      // Resolve the clipboard promise and flush microtasks
      resolveClipboard();
      await vi.advanceTimersByTimeAsync(0);

      // Now it should say "Copied!"
      expect(button.textContent).toBe("Copied!");

      // Advance past COPY_FEEDBACK_DURATION_MS (2000ms)
      await vi.advanceTimersByTimeAsync(2000);

      expect(button.textContent).toBe("Copy");
      vi.useRealTimers();
    });
  });

  describe("edge cases", () => {
    it("handles empty code blocks", () => {
      document.body.innerHTML = `
        <pre><code></code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).not.toBeNull();
    });

    it("handles code with special HTML characters", () => {
      document.body.innerHTML = `
        <pre><code>&lt;script&gt;alert("xss")&lt;/script&gt;</code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).not.toBeNull();
    });

    it("handles nested code structures", () => {
      document.body.innerHTML = `
        <pre><code><span>line 1</span><span>line 2</span></code></pre>
      `;

      addCopyButtons();

      const button = document.querySelector(".copy-button");
      expect(button).not.toBeNull();
    });

    it("calling addCopyButtons multiple times does not duplicate buttons", () => {
      document.body.innerHTML = `
        <pre><code>test</code></pre>
      `;

      addCopyButtons();
      addCopyButtons();
      addCopyButtons();

      const buttons = document.querySelectorAll(".copy-button");
      expect(buttons.length).toBe(1);
    });
  });
});
