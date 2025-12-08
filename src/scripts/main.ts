/**
 * Main TypeScript file for the SQL Injection Knowledge Base
 */

import { initSidebar } from "./sidebar";

// Make this a module
export {};

// Define types for global window properties
declare global {
  interface Window {
    initializeSidebar: () => void;
    sidebarResizeListenerAdded?: boolean;
    sidebarScrollListenerAdded?: boolean;
    overlayListenerAdded?: boolean;
    escapeListenerAdded?: boolean;
  }
}

// Track initialization state per page to prevent duplicate runs
let lastInitializedPath: string | null = null;

// Global initialization function for sidebar
window.initializeSidebar = function (): void {
  // Prevent duplicate initialization for the same page
  const currentPath = window.location.pathname + window.location.search;
  if (lastInitializedPath === currentPath) {
    return;
  }
  lastInitializedPath = currentPath;

  // Remove tabindex from pre elements (accessibility fix)
  removeTabindexFromPreElements();

  // Initialize sidebar section toggles, search, and keyboard navigation
  initSidebar();

  // Handle mobile toggle for sidebar
  const toggleButton = document.getElementById("sidebar-toggle");
  const buttonContainer = document.querySelector(".button-container") as HTMLElement | null;
  const sidebar = document.querySelector(".sidebar") as HTMLElement | null;
  const overlay = document.getElementById("sidebar-overlay");
  const body = document.body;

  // Initialize sidebar visibility
  if (sidebar) {
    // If on desktop, make sure sidebar is visible and reset any transforms
    if (window.innerWidth > 768) {
      sidebar.style.transform = "";
      if (buttonContainer) buttonContainer.style.display = "none";
    } else {
      if (buttonContainer) buttonContainer.style.display = "block";
    }
  }

  // Add a small animation to make the hamburger button more noticeable on mobile
  if (toggleButton && window.innerWidth <= 768) {
    setTimeout(() => {
      toggleButton.classList.add("attention");
      setTimeout(() => {
        toggleButton.classList.remove("attention");
      }, 1000);
    }, 1000);
  }

  // Handle window resize events - only add once
  if (!window.sidebarResizeListenerAdded) {
    window.sidebarResizeListenerAdded = true;
    window.addEventListener("resize", function () {
      if (buttonContainer) {
        if (window.innerWidth > 768) {
          buttonContainer.style.display = "none";
          // Reset sidebar state for desktop
          if (sidebar) {
            sidebar.classList.remove("mobile-open");
            body.style.overflow = "";
          }
          if (overlay) {
            overlay.classList.remove("active");
          }
        } else {
          buttonContainer.style.display = "block";
        }
      }
    });
  }

  // Handle button visibility on scroll - only add once
  if (buttonContainer && window.innerWidth <= 768 && !window.sidebarScrollListenerAdded) {
    window.sidebarScrollListenerAdded = true;
    let lastScrollTop = 0;
    let ticking = false;

    window.addEventListener("scroll", function () {
      if (!ticking) {
        window.requestAnimationFrame(function () {
          const currentScroll = window.pageYOffset || document.documentElement.scrollTop;

          // Hide button when scrolling down, show when scrolling up
          if (currentScroll > lastScrollTop && currentScroll > 100) {
            // Scrolling down
            buttonContainer!.classList.add("hidden");
          } else {
            // Scrolling up or near top
            buttonContainer!.classList.remove("hidden");
          }

          lastScrollTop = currentScroll <= 0 ? 0 : currentScroll;
          ticking = false;
        });

        ticking = true;
      }
    });
  }

  // Handle sidebar toggle button click
  if (toggleButton && sidebar) {
    // Clone the button to remove all existing event listeners
    const newToggleButton = toggleButton.cloneNode(true);
    if (toggleButton.parentNode) {
      toggleButton.parentNode.replaceChild(newToggleButton, toggleButton);
    }

    newToggleButton.addEventListener("click", function (e: Event) {
      e.preventDefault();
      e.stopPropagation();

      sidebar.classList.toggle("mobile-open");
      if (overlay) overlay.classList.toggle("active");

      // Toggle body scrolling when sidebar is open
      if (sidebar.classList.contains("mobile-open")) {
        body.style.overflow = "hidden";
      } else {
        body.style.overflow = "";
      }
    });

    // Close sidebar when clicking on overlay - only add once
    if (overlay && !window.overlayListenerAdded) {
      window.overlayListenerAdded = true;
      overlay.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();

        if (sidebar) sidebar.classList.remove("mobile-open");
        overlay.classList.remove("active");
        body.style.overflow = "";
      });
    }

    // Close sidebar when escape key is pressed - only add once
    if (!window.escapeListenerAdded) {
      window.escapeListenerAdded = true;
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && sidebar && sidebar.classList.contains("mobile-open")) {
          sidebar.classList.remove("mobile-open");
          if (overlay) overlay.classList.remove("active");
          body.style.overflow = "";
        }
      });
    }
  }

  // Add copy buttons to code blocks
  addCopyButtons();
};

// Initialize on various events

if (typeof document !== "undefined") {
  // 1. When DOM is ready (initial page load)
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", window.initializeSidebar);
  } else {
    // DOM is already ready
    window.initializeSidebar();
  }

  // 2. On Astro page load (for View Transitions)
  // This fires after both initial load and client-side navigation
  document.addEventListener("astro:page-load", window.initializeSidebar);
}

// Remove tabindex from pre elements
function removeTabindexFromPreElements(): void {
  // Find all pre elements and remove tabindex attribute
  const preElements = document.querySelectorAll("pre[tabindex]");
  preElements.forEach((pre) => {
    pre.removeAttribute("tabindex");
  });

  // Also check for any astro-code elements with tabindex
  const astroCodeElements = document.querySelectorAll(".astro-code[tabindex]");
  astroCodeElements.forEach((element) => {
    element.removeAttribute("tabindex");
  });
}

// Add copy buttons to code blocks
function addCopyButtons(): void {
  // Remove any existing copy buttons to avoid duplicates
  document.querySelectorAll(".copy-button").forEach((button) => {
    button.remove();
  });

  // Find all code blocks
  const codeBlocks = document.querySelectorAll("pre code, div.astro-code");

  codeBlocks.forEach((block) => {
    // Get the parent element
    const pre = block.parentNode as HTMLElement;

    // Ensure pre has relative positioning
    if (pre && (pre.tagName === "PRE" || pre.classList.contains("astro-code"))) {
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

// Copy code to clipboard with fallback
function copyCode(codeBlock: Element, button: HTMLElement): void {
  const text = codeBlock.textContent || "";

  // Try modern clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        button.textContent = "Copied!";
        button.classList.add("success");
        setTimeout(() => {
          button.textContent = "Copy";
          button.classList.remove("success");
        }, 2000);
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

// Legacy copy method for older browsers or mobile
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
    document.execCommand("copy");
    document.body.removeChild(textarea);

    button.textContent = "Copied!";
    button.classList.add("success");
  } catch {
    button.textContent = "Error!";
    button.classList.add("error");
  }

  setTimeout(() => {
    button.textContent = "Copy";
    button.classList.remove("success", "error");
  }, 2000);
}

// Theme toggle functionality
function initializeThemeToggle(): void {
  const themeToggle = document.getElementById("theme-toggle");
  if (!themeToggle) return;

  // Clone to remove existing listeners
  const newThemeToggle = themeToggle.cloneNode(true);
  if (themeToggle.parentNode) {
    themeToggle.parentNode.replaceChild(newThemeToggle, themeToggle);
  }

  newThemeToggle.addEventListener("click", function () {
    const html = document.documentElement;
    const currentTheme = localStorage.getItem("theme");

    // Determine current effective theme
    let isDark = false;
    if (currentTheme === "dark") {
      isDark = true;
    } else if (currentTheme === "light") {
      isDark = false;
    } else {
      // No manual override, check system preference
      isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    }

    // Toggle theme
    if (isDark) {
      // Switch to light
      html.classList.remove("dark");
      html.classList.add("light");
      localStorage.setItem("theme", "light");
    } else {
      // Switch to dark
      html.classList.remove("light");
      html.classList.add("dark");
      localStorage.setItem("theme", "dark");
    }
  });
}

// Initialize theme toggle on page load
if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeThemeToggle);
  } else {
    initializeThemeToggle();
  }

  // Also initialize on Astro page load for View Transitions
  document.addEventListener("astro:page-load", initializeThemeToggle);
}
