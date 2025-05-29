// Main JavaScript file for the SQL Injection Knowledge Base

document.addEventListener('astro:page-load', function() {
  // Handle mobile toggle for sidebar
  const toggleButton = document.getElementById('sidebar-toggle');
  const buttonContainer = document.querySelector('.button-container');
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const body = document.body;
  
  // Initialize sidebar visibility
  if (sidebar) {
    // If on desktop, make sure sidebar is visible and reset any transforms
    if (window.innerWidth > 768) {
      sidebar.style.transform = '';
      buttonContainer.style.display = 'none';
    } else {
      buttonContainer.style.display = 'block';
    }
  }
  
  // Add a small animation to make the hamburger button more noticeable on mobile
  if (toggleButton && window.innerWidth <= 768) {
    setTimeout(() => {
      toggleButton.classList.add('attention');
      setTimeout(() => {
        toggleButton.classList.remove('attention');
      }, 1000);
    }, 1000);
  }
  
  // Handle window resize events
  window.addEventListener('resize', function() {
    if (buttonContainer) {
      if (window.innerWidth > 768) {
        buttonContainer.style.display = 'none';
        // Reset sidebar state for desktop
        if (sidebar) {
          sidebar.classList.remove('mobile-open');
          body.style.overflow = '';
        }
        if (overlay) {
          overlay.classList.remove('active');
        }
      } else {
        buttonContainer.style.display = 'block';
      }
    }
  });

  // Handle button visibility on scroll
  if (buttonContainer && window.innerWidth <= 768) {
    let lastScrollTop = 0;
    let ticking = false;
    
    window.addEventListener('scroll', function() {
      if (!ticking) {
        window.requestAnimationFrame(function() {
          let currentScroll = window.pageYOffset || document.documentElement.scrollTop;
          
          // Hide button when scrolling down, show when scrolling up
          if (currentScroll > lastScrollTop && currentScroll > 100) {
            // Scrolling down
            buttonContainer.classList.add('hidden');
          } else {
            // Scrolling up or near top
            buttonContainer.classList.remove('hidden');
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
    // Remove existing event listeners and add a fresh one
    toggleButton.onclick = null;
    
    toggleButton.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      sidebar.classList.toggle('mobile-open');
      if (overlay) overlay.classList.toggle('active');
      
      // Toggle body scrolling when sidebar is open
      if (sidebar.classList.contains('mobile-open')) {
        body.style.overflow = 'hidden';
      } else {
        body.style.overflow = '';
      }
    });
    
    // Close sidebar when clicking on overlay
    if (overlay) {
      overlay.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        
        sidebar.classList.remove('mobile-open');
        overlay.classList.remove('active');
        body.style.overflow = '';
      });
    }
    
    // Close sidebar when escape key is pressed
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape' && sidebar && sidebar.classList.contains('mobile-open')) {
        sidebar.classList.remove('mobile-open');
        if (overlay) overlay.classList.remove('active');
        body.style.overflow = '';
      }
    });
  }
  
  // Add copy buttons to code blocks
  addCopyButtons();
});

// Add copy buttons to code blocks
function addCopyButtons() {
  // Remove any existing copy buttons to avoid duplicates
  document.querySelectorAll('.copy-button').forEach(button => {
    button.remove();
  });
  
  // Find all code blocks
  const codeBlocks = document.querySelectorAll('pre code, div.astro-code');
  
  codeBlocks.forEach(block => {
    // Get the parent element
    const pre = block.parentNode;
    
    // Ensure pre has relative positioning
    if (pre.tagName === 'PRE' || pre.classList.contains('astro-code')) {
      pre.style.position = 'relative';
      
      // Create button
      const button = document.createElement('button');
      button.className = 'copy-button';
      button.textContent = 'Copy';
      button.setAttribute('aria-label', 'Copy code');
      button.setAttribute('title', 'Copy code to clipboard');
      
      // Add button to pre element
      pre.appendChild(button);
      
      // Add click handler
      button.addEventListener('click', function() {
        copyCode(block, button);
      });
    }
  });
}

// Copy code to clipboard with fallback
function copyCode(codeBlock, button) {
  const text = codeBlock.textContent || '';
  
  // Try modern clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => {
        button.textContent = 'Copied!';
        button.classList.add('success');
        setTimeout(() => {
          button.textContent = 'Copy';
          button.classList.remove('success');
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
    const textarea = document.createElement('textarea');
    textarea.value = text;
    
    // Position off-screen but stay within the viewport
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.textContent = 'Copied!';
    button.classList.add('success');
  } catch (err) {
    button.textContent = 'Error!';
    button.classList.add('error');
  }
  
  setTimeout(() => {
    button.textContent = 'Copy';
    button.classList.remove('success', 'error');
  }, 2000);
}

// Run on initial page load
document.addEventListener('DOMContentLoaded', function() {
  document.dispatchEvent(new Event('astro:page-load'));
});

// CSS for copy button
document.addEventListener('DOMContentLoaded', function() {
  const style = document.createElement('style');
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