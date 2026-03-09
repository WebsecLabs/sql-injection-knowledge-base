/**
 * Search Modal Script
 *
 * Handles the Pagefind-powered search modal:
 * - Lazy-loads Pagefind index on first open
 * - Debounced search with result rendering
 * - Full keyboard navigation (ArrowUp/Down, Enter, Escape)
 * - ARIA combobox pattern with live region announcements
 * - Body scroll lock and inert attribute management
 * - Focus trapping and restoration
 * - View Transitions integration (astro:page-load / astro:before-swap)
 * - Global Ctrl/Cmd+K shortcut
 */

import { debounce, initOnce } from "../utils/domUtils";
import { COLLECTION_SEARCH_LABELS, type ValidCollection } from "../utils/constants";

// ---------------------------------------------------------------------------
// Pagefind lazy loading
// ---------------------------------------------------------------------------

/** Pagefind API type - external library with no type definitions */
interface PagefindAPI {
  init: () => Promise<void>;
  search: (query: string) => Promise<{ results: PagefindResult[] }>;
}

interface PagefindResultData {
  url: string;
  meta: { title?: string };
  excerpt: string;
  filters: Record<string, string[]>;
}

interface PagefindResult {
  data: () => Promise<PagefindResultData>;
}

let pagefind: PagefindAPI | null = null;
let pagefindLoadError: string | null = null;

async function loadPagefind(): Promise<PagefindAPI> {
  if (pagefind) return pagefind;
  if (pagefindLoadError) throw new Error(pagefindLoadError);

  try {
    const base = import.meta.env.BASE_URL;
    const pf = (await import(/* @vite-ignore */ `${base}pagefind/pagefind.js`)) as PagefindAPI;
    await pf.init();
    pagefind = pf;
    return pf;
  } catch (err) {
    pagefindLoadError =
      err instanceof Error && err.message.includes("Failed to fetch")
        ? "Search requires a build. Run npm run build first."
        : "Search index failed to load. Try refreshing the page.";
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

function detectMac(): boolean {
  if (typeof navigator === "undefined") return false;

  const agentData = navigator as unknown as { userAgentData?: { platform: string } };
  if (agentData.userAgentData?.platform === "macOS") return true;
  if (/Mac|iPod|iPhone|iPad/.test(navigator.platform)) return true;
  if (navigator.userAgent.includes("Mac") && "ontouchend" in document) return true;

  return false;
}

const isMac = detectMac();

// ---------------------------------------------------------------------------
// Body scroll lock
// ---------------------------------------------------------------------------

let savedScrollY = 0;

function lockScroll(): void {
  savedScrollY = window.scrollY;
  document.documentElement.style.overflow = "hidden";
  document.body.style.position = "fixed";
  document.body.style.top = `-${savedScrollY}px`;
  document.body.style.width = "100%";
}

function unlockScroll(): void {
  document.documentElement.style.overflow = "";
  document.body.style.position = "";
  document.body.style.top = "";
  document.body.style.width = "";
  window.scrollTo(0, savedScrollY);
}

// ---------------------------------------------------------------------------
// Inert attribute management
// ---------------------------------------------------------------------------

const INERT_SELECTORS = ["main", "nav", "footer", ".sidebar", ".button-container"] as const;

function applyInert(): void {
  for (const selector of INERT_SELECTORS) {
    for (const el of document.querySelectorAll(selector)) {
      el.setAttribute("inert", "");
    }
  }
}

function removeInert(): void {
  for (const selector of INERT_SELECTORS) {
    for (const el of document.querySelectorAll(selector)) {
      el.removeAttribute("inert");
    }
  }
}

// ---------------------------------------------------------------------------
// Focus management
// ---------------------------------------------------------------------------

let lastFocusedElement: HTMLElement | null = null;

function returnFocus(): void {
  if (lastFocusedElement && lastFocusedElement.isConnected) {
    lastFocusedElement.focus();
  }
  lastFocusedElement = null;
}

// ---------------------------------------------------------------------------
// Search state
// ---------------------------------------------------------------------------

const MAX_RESULTS = 12;
let activeIndex = -1;

function resetSearchState(): void {
  activeIndex = -1;
  const input = document.getElementById("search-modal-input") as HTMLInputElement | null;
  const resultsList = document.getElementById("search-modal-results");
  const emptyEl = document.getElementById("search-modal-empty");
  const initialEl = document.getElementById("search-modal-initial");
  const srStatus = document.getElementById("search-modal-sr-status");

  if (input) {
    input.value = "";
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-activedescendant", "");
  }
  if (resultsList) resultsList.innerHTML = "";
  if (emptyEl) emptyEl.hidden = true;
  if (initialEl) initialEl.hidden = false;
  if (srStatus) srStatus.textContent = "";
}

// ---------------------------------------------------------------------------
// Result rendering
// ---------------------------------------------------------------------------

function renderResults(results: PagefindResultData[]): void {
  const resultsList = document.getElementById("search-modal-results");
  const emptyEl = document.getElementById("search-modal-empty");
  const initialEl = document.getElementById("search-modal-initial");
  const srStatus = document.getElementById("search-modal-sr-status");
  const input = document.getElementById("search-modal-input") as HTMLInputElement | null;

  if (!resultsList) return;

  // Always hide initial state when we have a query
  if (initialEl) initialEl.hidden = true;

  // Clear previous results
  resultsList.innerHTML = "";
  activeIndex = -1;
  if (input) {
    input.setAttribute("aria-activedescendant", "");
  }

  if (results.length === 0) {
    if (emptyEl) emptyEl.hidden = false;
    if (input) input.setAttribute("aria-expanded", "false");
    if (srStatus) srStatus.textContent = "No results found.";
    return;
  }

  if (emptyEl) emptyEl.hidden = true;
  if (input) input.setAttribute("aria-expanded", "true");

  for (const [index, result] of results.entries()) {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.setAttribute("id", `search-result-${index}`);
    li.setAttribute("tabindex", "-1");
    li.setAttribute("aria-selected", "false");
    li.classList.add("search-result-item");
    li.dataset.url = result.url;

    const titleRow = document.createElement("div");
    titleRow.classList.add("search-result-title");

    const titleText = document.createElement("span");
    titleText.textContent = result.meta?.title || "Untitled";
    titleRow.appendChild(titleText);

    const databases = result.filters?.database;
    if (databases && databases.length > 0) {
      const db = databases[0] as ValidCollection;
      const badge = document.createElement("span");
      badge.classList.add("search-result-badge");
      badge.setAttribute("data-database", db);
      badge.textContent = COLLECTION_SEARCH_LABELS[db] || db;
      titleRow.appendChild(document.createTextNode(" "));
      titleRow.appendChild(badge);
    }

    li.appendChild(titleRow);

    // Pagefind provides pre-sanitized HTML with <mark> tags for highlighting
    if (result.excerpt) {
      const snippet = document.createElement("p");
      snippet.classList.add("search-result-snippet");
      snippet.innerHTML = result.excerpt;
      li.appendChild(snippet);
    }

    li.addEventListener("click", () => {
      navigateToResult(result.url);
    });

    resultsList.appendChild(li);
  }

  // Screen reader announcement
  if (srStatus) {
    srStatus.textContent = `${results.length} result${results.length === 1 ? "" : "s"} found.`;
  }
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

function navigateToResult(url: string): void {
  if (url) {
    // Close modal first, then navigate
    const dialog = document.getElementById("search-modal") as HTMLDialogElement | null;
    if (dialog?.open) {
      dialog.close();
    }
    window.location.href = url;
  }
}

// ---------------------------------------------------------------------------
// Keyboard navigation within results
// ---------------------------------------------------------------------------

function updateActiveResult(newIndex: number): void {
  const resultsList = document.getElementById("search-modal-results");
  const input = document.getElementById("search-modal-input") as HTMLInputElement | null;
  if (!resultsList) return;

  const items = resultsList.querySelectorAll<HTMLElement>('[role="option"]');
  if (items.length === 0) return;

  // Deselect previous
  if (activeIndex >= 0 && activeIndex < items.length) {
    items[activeIndex].setAttribute("aria-selected", "false");
  }

  activeIndex = newIndex;

  // Select new
  if (activeIndex >= 0 && activeIndex < items.length) {
    const activeItem = items[activeIndex];
    activeItem.setAttribute("aria-selected", "true");
    activeItem.scrollIntoView({ block: "nearest" });
    if (input) {
      input.setAttribute("aria-activedescendant", activeItem.id);
    }
  } else {
    if (input) {
      input.setAttribute("aria-activedescendant", "");
    }
  }
}

function handleResultKeydown(e: KeyboardEvent): void {
  const resultsList = document.getElementById("search-modal-results");
  if (!resultsList) return;

  const items = resultsList.querySelectorAll<HTMLElement>('[role="option"]');
  if (items.length === 0) return;

  if (e.key === "ArrowDown") {
    e.preventDefault();
    const next = activeIndex < items.length - 1 ? activeIndex + 1 : 0;
    updateActiveResult(next);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    const prev = activeIndex > 0 ? activeIndex - 1 : items.length - 1;
    updateActiveResult(prev);
  } else if (e.key === "Enter" && activeIndex >= 0 && activeIndex < items.length) {
    e.preventDefault();
    const url = items[activeIndex].dataset.url;
    if (url) navigateToResult(url);
  }
}

// ---------------------------------------------------------------------------
// Search execution
// ---------------------------------------------------------------------------

async function performSearch(query: string): Promise<void> {
  if (!query.trim()) {
    resetSearchState();
    return;
  }

  try {
    const pf = await loadPagefind();
    const search = await pf.search(query);
    const resultData: PagefindResultData[] = await Promise.all(
      search.results.slice(0, MAX_RESULTS).map((r: PagefindResult) => r.data())
    );
    renderResults(resultData);
  } catch (_err) {
    // Show error in empty state
    const emptyEl = document.getElementById("search-modal-empty");
    const initialEl = document.getElementById("search-modal-initial");
    const srStatus = document.getElementById("search-modal-sr-status");

    if (initialEl) initialEl.hidden = true;
    if (emptyEl) {
      emptyEl.textContent = pagefindLoadError || "Search failed. Please try again.";
      emptyEl.hidden = false;
    }
    if (srStatus) {
      srStatus.textContent = pagefindLoadError || "Search failed.";
    }
  }
}

const debouncedSearch = debounce(performSearch, 200);

// ---------------------------------------------------------------------------
// Modal open / close
// ---------------------------------------------------------------------------

function closeMobileSidebar(): void {
  const sidebar = document.querySelector(".sidebar") as HTMLElement | null;
  if (sidebar?.classList.contains("mobile-open")) {
    sidebar.classList.remove("mobile-open");
    const overlay = document.getElementById("sidebar-overlay");
    if (overlay) overlay.classList.remove("active");
    document.body.style.overflow = "";
  }
}

function openSearchModal(): void {
  const dialog = document.getElementById("search-modal") as HTMLDialogElement | null;
  if (!dialog || dialog.open) return;

  // Close mobile sidebar if open
  closeMobileSidebar();

  // Store focus for restoration
  lastFocusedElement = document.activeElement as HTMLElement | null;

  // Lock scroll and apply inert
  lockScroll();
  applyInert();

  // Open dialog
  dialog.showModal();

  // Add animation class after a frame to trigger transition
  requestAnimationFrame(() => {
    dialog.classList.add("is-open");
  });

  // Focus the search input
  const input = document.getElementById("search-modal-input") as HTMLInputElement | null;
  if (input) {
    input.focus();
  }
}

function closeSearchModal(): void {
  const dialog = document.getElementById("search-modal") as HTMLDialogElement | null;
  if (!dialog?.open) return;

  // Remove animation class
  dialog.classList.remove("is-open");

  // Close after transition (match CSS transition duration)
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const delay = prefersReduced ? 0 : 80;

  setTimeout(() => {
    if (dialog.open) {
      dialog.close();
    }
  }, delay);
}

// ---------------------------------------------------------------------------
// Event binding
// ---------------------------------------------------------------------------

function bindModalEvents(): void {
  const dialog = document.getElementById("search-modal") as HTMLDialogElement | null;
  const input = document.getElementById("search-modal-input") as HTMLInputElement | null;

  if (!dialog || !input) return;

  // Input handler for search
  input.addEventListener("input", () => {
    const query = input.value;
    if (!query.trim()) {
      debouncedSearch.cancel();
      resetSearchState();
    } else {
      debouncedSearch(query);
    }
  });

  // Keyboard navigation within input
  input.addEventListener("keydown", handleResultKeydown);

  // Dialog close event - handles all cleanup
  dialog.addEventListener("close", () => {
    dialog.classList.remove("is-open");
    unlockScroll();
    removeInert();
    returnFocus();
    resetSearchState();
  });

  // Prevent dialog from closing via Escape instantly (we want the animation)
  dialog.addEventListener("cancel", (e) => {
    e.preventDefault();
    closeSearchModal();
  });

  // Click on backdrop (the dialog element itself, not the container) to close
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) {
      closeSearchModal();
    }
  });
}

// ---------------------------------------------------------------------------
// Global event listeners (persist across View Transitions)
// ---------------------------------------------------------------------------

function setupGlobalListeners(): void {
  // Global keyboard shortcut: Ctrl/Cmd+K
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      openSearchModal();
    }
  });

  // Delegated click handler for search trigger button
  document.addEventListener("click", (e) => {
    const trigger = (e.target as Element).closest("#search-trigger");
    if (trigger) {
      openSearchModal();
    }
  });

  // Close modal on View Transition navigation
  document.addEventListener("astro:before-swap", () => {
    const dialog = document.getElementById("search-modal") as HTMLDialogElement | null;
    if (dialog?.open) {
      // Force close without animation since page is about to swap
      dialog.classList.remove("is-open");
      unlockScroll();
      removeInert();
      dialog.close();
      resetSearchState();
      lastFocusedElement = null;
    }
  });
}

// ---------------------------------------------------------------------------
// Platform-aware kbd text
// ---------------------------------------------------------------------------

function updateKbdText(): void {
  const kbdEl = document.getElementById("search-trigger-kbd");
  if (kbdEl && isMac) {
    kbdEl.textContent = "\u2318 K";
  }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

function initSearchModal(): void {
  bindModalEvents();
  updateKbdText();
}

if (typeof document !== "undefined") {
  // Global listeners only once (persist across View Transitions)
  initOnce("searchModal:global", setupGlobalListeners);

  // astro:page-load fires on both initial load and View Transition navigations
  // so a single listener handles both cases without duplicate binding
  document.addEventListener("astro:page-load", initSearchModal);
}
