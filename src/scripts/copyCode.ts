/**
 * Copy to Clipboard Module
 *
 * Handles code block copy functionality with modern and legacy clipboard APIs.
 * Provides visual feedback on copy success/failure.
 */

import { COPY_FEEDBACK_DURATION_MS } from "../utils/uiConstants";

/**
 * Add copy buttons to all code blocks on the page.
 * Removes existing buttons first to avoid duplicates on re-initialization.
 */
export function addCopyButtons(): void {
  // Remove any existing copy buttons to avoid duplicates
  document.querySelectorAll(".copy-button").forEach((button) => {
    button.remove();
  });

  // Find all code blocks
  const codeBlocks = document.querySelectorAll("pre code, div.astro-code");

  codeBlocks.forEach((block) => {
    // Get the parent element safely with proper type guard
    const parentNode = block.parentNode;
    if (!parentNode || parentNode.nodeType !== Node.ELEMENT_NODE) {
      return;
    }
    // After nodeType check, we know parentNode is an Element (not Document/DocumentFragment)
    const pre = parentNode as Element;

    // Ensure pre has relative positioning
    if (pre.tagName === "PRE" || pre.classList.contains("astro-code")) {
      // Create button
      const button = document.createElement("button");
      button.className = "copy-button";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy code");
      button.setAttribute("title", "Copy code to clipboard");

      // Add button to pre element
      pre.appendChild(button);

      // Add click handler
      button.addEventListener("click", function () {
        copyCode(block, button);
      });
    }
  });
}

/**
 * Copy code to clipboard with fallback for older browsers.
 * Uses modern Clipboard API when available, falls back to execCommand.
 */
function copyCode(codeBlock: Element, button: HTMLElement): void {
  const text = codeBlock.textContent || "";

  // Try modern clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        showCopyFeedback(button, "success");
      })
      .catch(() => {
        // Fall back to older method
        legacyCopy(text, button);
      });
  } else {
    // Use legacy approach
    legacyCopy(text, button);
  }
}

/**
 * Legacy copy method for older browsers or when modern API fails.
 * Uses a temporary textarea element and execCommand.
 */
function legacyCopy(text: string, button: HTMLElement): void {
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;

    // Position off-screen but stay within the viewport
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";

    document.body.appendChild(textarea);
    textarea.select();
    // Legacy fallback for browsers without Clipboard API (Safari < 13.1, older browsers)
    document.execCommand("copy");
    document.body.removeChild(textarea);

    showCopyFeedback(button, "success");
  } catch (err) {
    // Log error for debugging - helps identify copy failures in development
    console.error("[copyCode] Legacy copy failed:", err);
    showCopyFeedback(button, "error");
  }
}

/**
 * Show visual feedback on the copy button.
 */
function showCopyFeedback(button: HTMLElement, status: "success" | "error"): void {
  button.textContent = status === "success" ? "Copied!" : "Error!";
  button.classList.add(status);

  setTimeout(() => {
    button.textContent = "Copy";
    button.classList.remove("success", "error");
  }, COPY_FEEDBACK_DURATION_MS);
}
