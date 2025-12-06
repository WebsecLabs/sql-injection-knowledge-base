// Main JavaScript file for the SQL Injection Knowledge Base

// Global initialization function for sidebar
window.initializeSidebar = function () {
  // Remove tabindex from pre elements (accessibility fix)
  removeTabindexFromPreElements();

  // Handle mobile toggle for sidebar
  const toggleButton = document.getElementById("sidebar-toggle");
  const buttonContainer = document.querySelector(".button-container");
  const sidebar = document.querySelector(".sidebar");
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
          let currentScroll = window.pageYOffset || document.documentElement.scrollTop;

          // Hide button when scrolling down, show when scrolling up
          if (currentScroll > lastScrollTop && currentScroll > 100) {
            // Scrolling down
            if (buttonContainer) buttonContainer.classList.add("hidden");
          } else {
            // Scrolling up or near top
            if (buttonContainer) buttonContainer.classList.remove("hidden");
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

    newToggleButton.addEventListener("click", function (e) {
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

// 1. When DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", window.initializeSidebar);
} else {
  // DOM is already ready
  window.initializeSidebar();
}

// 2. On Astro page load (for View Transitions)
document.addEventListener("astro:page-load", window.initializeSidebar);

// 3. After page swap (for View Transitions)
document.addEventListener("astro:after-swap", window.initializeSidebar);

// 4. As a fallback, also run after a short delay
setTimeout(window.initializeSidebar, 100);

// Remove tabindex from pre elements
function removeTabindexFromPreElements() {
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
function addCopyButtons() {
  // Remove any existing copy buttons to avoid duplicates
  document.querySelectorAll(".copy-button").forEach((button) => {
    button.remove();
  });

  // Find all code blocks
  const codeBlocks = document.querySelectorAll("pre code, div.astro-code");

  codeBlocks.forEach((block) => {
    // Get the parent element
    const pre = block.parentNode;

    // Ensure pre has relative positioning
    if (pre.tagName === "PRE" || pre.classList.contains("astro-code")) {
      pre.style.position = "relative";

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
function copyCode(codeBlock, button) {
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
function legacyCopy(text, button) {
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

// Run on initial page load
document.addEventListener("DOMContentLoaded", function () {
  // Remove tabindex from pre elements on initial load
  removeTabindexFromPreElements();
});

// CSS for copy button
document.addEventListener("DOMContentLoaded", function () {
  const style = document.createElement("style");
  style.textContent = `
    .copy-button {
      position: absolute;
      top: 5px;
      right: 5px;
      background-color: rgba(0, 0, 0, 0.1);
      color: #fff;
      border: none;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
      opacity: 0;
    }
    
    pre:hover .copy-button {
      opacity: 1;
    }
    
    .copy-button:hover {
      background-color: rgba(0, 0, 0, 0.3);
    }
    
    .copy-button.success {
      background-color: #48bb78;
    }
    
    .copy-button.error {
      background-color: #f56565;
    }
    
    /* Mobile enhancements */
    @media (max-width: 768px) {
      .copy-button {
        opacity: 1;
        padding: 6px 10px;
        font-size: 14px;
      }
    }
  `;
  document.head.appendChild(style);
});
