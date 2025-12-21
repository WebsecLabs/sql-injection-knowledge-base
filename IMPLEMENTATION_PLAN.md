# Comprehensive Implementation Plan

## SQL Injection Knowledge Base - Code Quality Improvements

**Created:** 2025-12-21
**Status:** Ready for Review
**Estimated Total Effort:** 3-4 days

---

## Executive Summary

This plan addresses all findings from the comprehensive code review, organized into 6 implementation phases. Each phase is designed to be atomic and testable, with clear success criteria.

---

## Phase 1: Quick Wins - Code Cleanup (Est: 2-3 hours)

### 1.1 Remove Duplicate Debounce Function

**Problem:** Debounce is implemented twice - in `search.ts` and `domUtils.ts`

**Files to modify:**

- `src/scripts/search.ts` (lines 17-27)

**Implementation:**

```typescript
// BEFORE (search.ts lines 1-27)
import { escapeHtml } from "../utils/htmlEscape";
import { COLLECTION_SEARCH_LABELS } from "../utils/constants";

const SEARCH_DEBOUNCE_MS = 300;
// ... interface ...

// Remove this duplicate function (lines 17-27)
function debounce<T extends (...args: Parameters<T>) => void>(func: T, wait: number) {
  // ...
}

// AFTER
import { escapeHtml } from "../utils/htmlEscape";
import { COLLECTION_SEARCH_LABELS } from "../utils/constants";
import { debounce } from "../utils/domUtils";

const SEARCH_DEBOUNCE_MS = 300;
```

**Verification:**

- Run `npm run typecheck`
- Run `npm run test:unit` (search.test.ts should still pass)
- Test search page manually

---

### 1.2 escapeControlChars Function (Retained)

**Status:** This function is NOT dead code and must be retained.

**Location:** `src/scripts/search.ts` (lines 76-79)

**Usage:** The function is used at line 163 to sanitize control characters before setting the document title:

```typescript
document.title = `Search Results for "${escapeControlChars(truncated)}" - SQL Injection KB`;
```

**Purpose:** Removes control characters (ASCII 0x00-0x1F and 0x7F-0x9F) from user input before inserting it into the document title. This prevents potential issues with non-printable characters in the browser's title bar.

**Note:** This is a security-conscious function that should be retained. It does NOT call itself recursively - it is simply called from a different location in the file.

---

### 1.3 Remove Unused navigationData.ts

**Problem:** File appears unused in codebase

**Files to check:**

- `src/data/navigationData.ts`

**Pre-verification:**

```bash
grep -r "navigationData" src/ --include="*.ts" --include="*.astro"
```

If no imports found, delete the file.

**Verification:**

- Run `npm run build`
- All pages should still render

---

### 1.4 Remove Empty Barrel File

**Problem:** `src/components/navbar/index.ts` is just documentation, not functional

**Implementation:**
Delete `src/components/navbar/index.ts` - Astro components can't be re-exported from TypeScript files.

---

## Phase 2: Constants Consolidation (Est: 2-3 hours)

### 2.1 Create UI Constants File

**Problem:** Magic numbers scattered throughout scripts

**New file:** `src/utils/uiConstants.ts`

```typescript
/**
 * UI Constants for consistent values across the application
 * @module uiConstants
 */

/** Mobile breakpoint for sidebar behavior (pixels) */
export const SIDEBAR_MOBILE_BREAKPOINT = 768;

/** Mobile breakpoint for navbar behavior (pixels) */
export const NAVBAR_MOBILE_BREAKPOINT = 1024;

/** Scroll threshold before hiding mobile sidebar toggle (pixels) */
export const SCROLL_HIDE_THRESHOLD = 100;

/** Debounce delay for search input (milliseconds) */
export const SEARCH_DEBOUNCE_MS = 300;

/** Debounce delay for resize events (milliseconds) */
export const RESIZE_DEBOUNCE_MS = 100;

/** Maximum title length before truncation in search results */
export const SEARCH_TITLE_MAX_LENGTH = 50;

/** Max-height for mobile dropdown menus */
export const DROPDOWN_MOBILE_MAX_HEIGHT = "5000px";

/** Copy button feedback duration (milliseconds) */
export const COPY_FEEDBACK_DURATION_MS = 2000;

/** Attention animation delay for sidebar toggle (milliseconds) */
export const SIDEBAR_ATTENTION_DELAY_MS = 1000;
```

### 2.2 Update Scripts to Use Constants

**Files to modify:**

**navbar.ts:**

```typescript
// Add import at top
import {
  NAVBAR_MOBILE_BREAKPOINT,
  RESIZE_DEBOUNCE_MS,
  DROPDOWN_MOBILE_MAX_HEIGHT,
} from "../utils/uiConstants";

// Replace line 25
export const MOBILE_BREAKPOINT = 1024;
// With
export { NAVBAR_MOBILE_BREAKPOINT as MOBILE_BREAKPOINT } from "../utils/uiConstants";

// Replace line 45 "5000px" with DROPDOWN_MOBILE_MAX_HEIGHT
// Replace line 306 "100" with RESIZE_DEBOUNCE_MS
```

**main.ts:**

```typescript
import {
  SIDEBAR_MOBILE_BREAKPOINT,
  SCROLL_HIDE_THRESHOLD,
  COPY_FEEDBACK_DURATION_MS,
  SIDEBAR_ATTENTION_DELAY_MS,
} from "../utils/uiConstants";

// Replace line 49, 58, 72, 90 "768" with SIDEBAR_MOBILE_BREAKPOINT
// Replace line 101 "100" with SCROLL_HIDE_THRESHOLD
// Replace lines 247, 285 "2000" with COPY_FEEDBACK_DURATION_MS
// Replace lines 59, 62 "1000" with SIDEBAR_ATTENTION_DELAY_MS
```

**search.ts:**

```typescript
import { SEARCH_DEBOUNCE_MS, SEARCH_TITLE_MAX_LENGTH } from "../utils/uiConstants";

// Remove line 5 (local constant definition)
// Replace lines 175-176 "50" with SEARCH_TITLE_MAX_LENGTH
```

### 2.3 Add Tests for Constants

**New file:** `tests/unit/utils/uiConstants.test.ts`

```typescript
import { describe, it, expect } from "vitest";
import * as constants from "@/utils/uiConstants";

describe("uiConstants", () => {
  it("should export SIDEBAR_MOBILE_BREAKPOINT as a positive number", () => {
    expect(constants.SIDEBAR_MOBILE_BREAKPOINT).toBeGreaterThan(0);
  });

  it("should have NAVBAR_MOBILE_BREAKPOINT larger than SIDEBAR_MOBILE_BREAKPOINT", () => {
    expect(constants.NAVBAR_MOBILE_BREAKPOINT).toBeGreaterThan(constants.SIDEBAR_MOBILE_BREAKPOINT);
  });

  it("should export all required constants", () => {
    expect(constants.SCROLL_HIDE_THRESHOLD).toBeDefined();
    expect(constants.SEARCH_DEBOUNCE_MS).toBeDefined();
    expect(constants.RESIZE_DEBOUNCE_MS).toBeDefined();
    expect(constants.SEARCH_TITLE_MAX_LENGTH).toBeDefined();
    expect(constants.DROPDOWN_MOBILE_MAX_HEIGHT).toBeDefined();
    expect(constants.COPY_FEEDBACK_DURATION_MS).toBeDefined();
  });
});
```

---

## Phase 3: Use Existing Utilities (Est: 1-2 hours)

### 3.1 Replace Clone-and-Replace Pattern with Utility

**Problem:** Pattern repeated 6+ times instead of using `cloneAndReplace` from domUtils

**Pattern to replace:**

```typescript
// Current pattern (repeated in multiple files)
const newElement = element.cloneNode(true);
if (element.parentNode) {
  element.parentNode.replaceChild(newElement, element);
}
```

**Files and locations to update:**

**navbar.ts:**

- Lines 61-64 (mobileToggle)
- Lines 83-87 (dropdowns loop)
- Lines 193-196 (databaseHeaders)
- Lines 219-220 (searchContainer)

```typescript
// Add import
import { cloneAndReplace } from "../utils/domUtils";

// Replace pattern with:
const newMobileToggle = cloneAndReplace(mobileToggle) as HTMLButtonElement;
```

**main.ts:**

- Lines 121-124 (toggleButton)
- Lines 297-300 (themeToggle)

```typescript
import { cloneAndReplace } from "../utils/domUtils";

// Replace patterns
const newToggleButton = cloneAndReplace(toggleButton);
const newThemeToggle = cloneAndReplace(themeToggle);
```

### 3.2 Handle Error Case in cloneAndReplace

The utility throws if element has no parent. Add null checks before calling:

```typescript
// Safe pattern
if (element.parentNode) {
  const freshElement = cloneAndReplace(element);
  // use freshElement
}
```

Or update the utility to handle null parent gracefully:

```typescript
// In domUtils.ts - update cloneAndReplace
export function cloneAndReplace(element: Element): Element | null {
  if (!element.parentNode) {
    return null; // or return element unchanged
  }
  const clone = element.cloneNode(true) as Element;
  element.parentNode.replaceChild(clone, element);
  return clone;
}
```

---

## Phase 4: Script Decomposition (Est: 4-6 hours)

### 4.1 Decompose navbar.ts

**Problem:** `initNavbar()` function is 156 lines with cyclomatic complexity ~18

**New structure:**

```
src/scripts/navbar/
├── index.ts           # Main entry point and exports
├── mobileMenu.ts      # Mobile toggle functionality
├── dropdowns.ts       # Dropdown hover/click behavior
├── databaseSections.ts # Database section expand/collapse
├── navSearch.ts       # Navbar search form handling
├── resize.ts          # Responsive resize handling
└── types.ts           # Shared types and interfaces
```

**types.ts:**

```typescript
export interface NavbarState {
  isMobile: boolean;
  initialized: boolean;
}

export interface DropdownElements {
  container: HTMLElement;
  toggle: HTMLElement;
  menu: HTMLElement | null;
}
```

**mobileMenu.ts:**

```typescript
import { cloneAndReplace } from "../../utils/domUtils";

export function initMobileMenu(): void {
  const mobileToggle = document.getElementById("mobile-toggle") as HTMLButtonElement | null;
  const navbarMenu = document.getElementById("navbar-menu");

  if (!mobileToggle || !navbarMenu) return;

  const freshToggle = cloneAndReplace(mobileToggle) as HTMLButtonElement;
  if (!freshToggle) return;

  freshToggle.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const isExpanded = freshToggle.getAttribute("aria-expanded") === "true";
    freshToggle.setAttribute("aria-expanded", String(!isExpanded));
    navbarMenu.classList.toggle("active");
    freshToggle.classList.toggle("active");
  });
}

export function closeMobileMenu(): void {
  const navbarMenu = document.getElementById("navbar-menu");
  const mobileToggle = document.getElementById("mobile-toggle") as HTMLButtonElement | null;

  if (navbarMenu?.classList.contains("active")) {
    navbarMenu.classList.remove("active");
    if (mobileToggle) {
      mobileToggle.classList.remove("active");
      mobileToggle.setAttribute("aria-expanded", "false");
    }
  }
}
```

**dropdowns.ts:**

```typescript
import { NAVBAR_MOBILE_BREAKPOINT, DROPDOWN_MOBILE_MAX_HEIGHT } from "../../utils/uiConstants";
import { cloneAndReplace } from "../../utils/domUtils";

export function toggleDropdownState(dropdown: Element, toggle: Element): void {
  const isExpanded = dropdown.classList.toggle("show");
  if (toggle instanceof HTMLElement) {
    toggle.setAttribute("aria-expanded", String(isExpanded));
  }

  const menu = dropdown.querySelector(".dropdown-menu") as HTMLElement | null;
  if (!menu) return;

  if (window.innerWidth < NAVBAR_MOBILE_BREAKPOINT) {
    menu.style.maxHeight = isExpanded ? DROPDOWN_MOBILE_MAX_HEIGHT : "0px";
  } else {
    menu.style.maxHeight = "";
  }
}

export function initDropdowns(isMobile: boolean): void {
  // Clone dropdowns to clear handlers
  const dropdowns = Array.from(document.querySelectorAll(".dropdown"));
  dropdowns.forEach((dropdown) => {
    if (dropdown.parentNode) {
      cloneAndReplace(dropdown);
    }
  });

  // Get fresh references
  const freshDropdowns = document.querySelectorAll(".dropdown");

  freshDropdowns.forEach((dropdown) => {
    const toggle = dropdown.querySelector(".dropdown-toggle");
    if (!toggle) return;

    if (!isMobile) {
      setupDesktopHover(dropdown);
    }
  });

  setupDropdownClickHandler();
  setupOutsideClickHandler();
  setupViewportBoundaryCheck(freshDropdowns);
}

function setupDesktopHover(dropdown: Element): void {
  dropdown.addEventListener("mouseenter", function (this: Element) {
    if (window.innerWidth < NAVBAR_MOBILE_BREAKPOINT) return;
    this.classList.add("show");
  });

  dropdown.addEventListener("mouseleave", function (this: Element) {
    if (window.innerWidth < NAVBAR_MOBILE_BREAKPOINT) return;
    this.classList.remove("show");
  });
}

// ... additional helper functions
```

**index.ts:**

```typescript
import { initMobileMenu, closeMobileMenu } from "./mobileMenu";
import { initDropdowns } from "./dropdowns";
import { initDatabaseSections } from "./databaseSections";
import { initNavSearch } from "./navSearch";
import { setupResizeHandler } from "./resize";
import { NAVBAR_MOBILE_BREAKPOINT } from "../../utils/uiConstants";

let initialized = false;
let prevIsMobile: boolean | undefined;

export function initializeNavbar(): void {
  const isMobile = window.innerWidth < NAVBAR_MOBILE_BREAKPOINT;

  // Initialize all sub-modules
  initMobileMenu();
  initDropdowns(isMobile);
  initDatabaseSections();
  initNavSearch();

  // Set up resize handler once
  if (!initialized) {
    initialized = true;
    prevIsMobile = isMobile;
    setupResizeHandler(() => {
      const nowMobile = window.innerWidth < NAVBAR_MOBILE_BREAKPOINT;
      if (nowMobile === prevIsMobile) return;
      prevIsMobile = nowMobile;

      if (nowMobile) {
        closeAllDropdowns();
        initDropdowns(true);
      } else {
        closeMobileMenu();
        initDropdowns(false);
      }
    });
  }
}

// Set up event listeners
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeNavbar);
} else {
  initializeNavbar();
}

document.addEventListener("astro:page-load", initializeNavbar);
document.addEventListener("astro:after-swap", initializeNavbar);
```

### 4.2 Decompose main.ts

**Problem:** `initializeSidebar` function is 144 lines mixing multiple concerns

**New structure:**

```
src/scripts/
├── main.ts            # Entry point, imports and coordinates
├── sidebar/
│   ├── index.ts       # Re-exports
│   ├── toggle.ts      # Mobile sidebar toggle
│   ├── visibility.ts  # Responsive visibility
│   └── overlay.ts     # Overlay and escape handlers
├── copyButton.ts      # Code block copy functionality
└── themeToggle.ts     # Theme switching
```

**copyButton.ts:**

```typescript
import { COPY_FEEDBACK_DURATION_MS } from "../utils/uiConstants";

export function addCopyButtons(): void {
  // Remove existing buttons
  document.querySelectorAll(".copy-button").forEach((btn) => btn.remove());

  // Find all code blocks
  const codeBlocks = document.querySelectorAll("pre code, div.astro-code");

  codeBlocks.forEach((block) => {
    const pre = block.parentNode as HTMLElement;
    if (!pre || (pre.tagName !== "PRE" && !pre.classList.contains("astro-code"))) {
      return;
    }

    const button = createCopyButton();
    pre.appendChild(button);
    button.addEventListener("click", () => copyCode(block, button));
  });
}

function createCopyButton(): HTMLButtonElement {
  const button = document.createElement("button");
  button.className = "copy-button";
  button.textContent = "Copy";
  button.setAttribute("aria-label", "Copy code");
  button.setAttribute("title", "Copy code to clipboard");
  return button;
}

async function copyCode(codeBlock: Element, button: HTMLElement): Promise<void> {
  const text = codeBlock.textContent || "";

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      showSuccess(button);
    } else {
      legacyCopy(text, button);
    }
  } catch {
    legacyCopy(text, button);
  }
}

function showSuccess(button: HTMLElement): void {
  button.textContent = "Copied!";
  button.classList.add("success");
  setTimeout(() => {
    button.textContent = "Copy";
    button.classList.remove("success");
  }, COPY_FEEDBACK_DURATION_MS);
}

function legacyCopy(text: string, button: HTMLElement): void {
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.cssText = "position:fixed;left:-9999px;top:0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
    showSuccess(button);
  } catch {
    button.textContent = "Error!";
    button.classList.add("error");
    setTimeout(() => {
      button.textContent = "Copy";
      button.classList.remove("error");
    }, COPY_FEEDBACK_DURATION_MS);
  }
}
```

**themeToggle.ts:**

```typescript
import { cloneAndReplace } from "../utils/domUtils";

export function initializeThemeToggle(): void {
  const themeToggle = document.getElementById("theme-toggle");
  if (!themeToggle) return;

  const freshToggle = cloneAndReplace(themeToggle);
  if (!freshToggle) return;

  freshToggle.addEventListener("click", toggleTheme);
}

function toggleTheme(): void {
  const html = document.documentElement;
  const currentTheme = localStorage.getItem("theme");
  const systemPrefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;

  const isDark = currentTheme === "dark" || (!currentTheme && systemPrefersDark);

  if (isDark) {
    html.classList.remove("dark");
    html.classList.add("light");
    localStorage.setItem("theme", "light");
  } else {
    html.classList.remove("light");
    html.classList.add("dark");
    localStorage.setItem("theme", "dark");
  }
}
```

---

## Phase 5: Type System Improvements (Est: 2-3 hours)

### 5.1 Create Centralized Types File

**New file:** `src/utils/types.ts`

```typescript
/**
 * Centralized type definitions for the SQL Injection Knowledge Base
 * @module types
 */

import type { CollectionEntry } from "astro:content";
import type { ValidCollection, DatabaseCollection } from "./constants";

/**
 * Generic collection entry that works with any valid collection
 */
export type AnyEntry = CollectionEntry<ValidCollection>;

/**
 * Database-specific collection entry (excludes extras)
 */
export type DatabaseEntry = CollectionEntry<DatabaseCollection>;

/**
 * Search entry structure for client-side search
 */
export interface SearchEntry {
  slug: string;
  title: string;
  description?: string;
  category: string;
  tags?: string[];
  collection: ValidCollection;
}

/**
 * Adjacent entry for prev/next navigation
 */
export interface AdjacentEntry {
  slug: string;
  title: string;
  category: string;
  collection: ValidCollection;
}

/**
 * Collection entries map for component props
 * Each key is `${collectionName}Entries`
 */
export type CollectionEntriesMap = {
  [K in ValidCollection as `${K}Entries`]?: CollectionEntry<K>[];
};
```

### 5.2 Update Components to Use Centralized Types

**Update entryUtils.ts:**

```typescript
// Remove local type definition, import from types.ts
import type { AnyEntry, AdjacentEntry } from "./types";
export type { AnyEntry, AdjacentEntry };
```

**Update NavBar.astro props:**

```typescript
// BEFORE
interface Props {
  currentPath: string;
  mysqlEntries?: CollectionEntry<"mysql">[];
  mariadbEntries?: CollectionEntry<"mariadb">[];
  // ... 6 more
}

// AFTER
import type { CollectionEntriesMap } from "../utils/types";

interface Props extends CollectionEntriesMap {
  currentPath: string;
}
```

**Update Sidebar.astro props:**

```typescript
import type { CollectionEntriesMap } from "../utils/types";

interface Props extends CollectionEntriesMap {
  currentPath: string;
}
```

**Update Layout.astro props:**

```typescript
import type { CollectionEntriesMap } from "../utils/types";

interface Props {
  title: string;
  description?: string;
  collections?: CollectionEntriesMap;
}
```

### 5.3 Create Collection Loader Utility

**New file:** `src/utils/collectionLoader.ts`

```typescript
import { getCollection } from "astro:content";
import { COLLECTION_TYPES, type ValidCollection } from "./constants";
import type { CollectionEntriesMap } from "./types";

/**
 * Load all collections in parallel
 * Returns a map of collection entries keyed by `${collectionName}Entries`
 */
export async function loadAllCollections(): Promise<CollectionEntriesMap> {
  const results = await Promise.all(
    COLLECTION_TYPES.map(async (collection) => {
      const entries = await getCollection(collection);
      return [collection, entries] as const;
    })
  );

  const map: CollectionEntriesMap = {};
  for (const [collection, entries] of results) {
    const key = `${collection}Entries` as keyof CollectionEntriesMap;
    (map as Record<string, unknown>)[key] = entries;
  }

  return map;
}

/**
 * Map collection entries to search data format
 */
export function mapToSearchEntries(entries: CollectionEntriesMap): SearchEntry[] {
  const result: SearchEntry[] = [];

  for (const collection of COLLECTION_TYPES) {
    const key = `${collection}Entries` as keyof CollectionEntriesMap;
    const collectionEntries = entries[key];

    if (collectionEntries) {
      for (const entry of collectionEntries) {
        result.push({
          slug: entry.slug,
          title: entry.data.title,
          description: entry.data.description,
          category: entry.data.category,
          tags: entry.data.tags,
          collection,
        });
      }
    }
  }

  return result;
}
```

### 5.4 Update search.astro to Use Loader

```astro
---
import Layout from "../layouts/Layout.astro";
import { loadAllCollections, mapToSearchEntries } from "../utils/collectionLoader";

const collections = await loadAllCollections();
const searchData = mapToSearchEntries(collections);
---
```

---

## Phase 6: Refactor Global State (Est: 2-3 hours)

### 6.1 Replace Window State with Module State

**Problem:** Scripts use `window` as global state container, making testing difficult

**Current pattern in navbar.ts:**

```typescript
declare global {
  interface Window {
    navbarInitialized?: boolean;
    initializeNavbar?: () => void;
    navbarDocumentClickHandler?: (e: Event) => void;
    navbarDropdownClickHandler?: (e: Event) => void;
    navbarPrevIsMobile?: boolean;
  }
}
```

**New pattern using module state:**

```typescript
// navbar/state.ts
interface NavbarState {
  initialized: boolean;
  prevIsMobile: boolean | undefined;
  documentClickHandler: ((e: Event) => void) | null;
  dropdownClickHandler: ((e: Event) => void) | null;
}

const state: NavbarState = {
  initialized: false,
  prevIsMobile: undefined,
  documentClickHandler: null,
  dropdownClickHandler: null,
};

export function getState(): Readonly<NavbarState> {
  return state;
}

export function setState(updates: Partial<NavbarState>): void {
  Object.assign(state, updates);
}

export function resetState(): void {
  state.initialized = false;
  state.prevIsMobile = undefined;

  // Clean up event handlers
  if (state.documentClickHandler) {
    document.removeEventListener("click", state.documentClickHandler);
  }
  if (state.dropdownClickHandler) {
    document.removeEventListener("click", state.dropdownClickHandler, true);
  }

  state.documentClickHandler = null;
  state.dropdownClickHandler = null;
}
```

### 6.2 Use initOnce from domUtils

The existing `initOnce` utility in `domUtils.ts` provides a clean pattern for one-time initialization:

```typescript
import { initOnce } from "../utils/domUtils";

// Instead of manual window flag checks
initOnce("navbar-resize-listener", () => {
  window.addEventListener("resize", handleResize);
});
```

### 6.3 Update Scripts to Use Module State

**main.ts refactored:**

```typescript
import { initOnce } from "./utils/domUtils";
import { initSidebar } from "./sidebar";
import { addCopyButtons } from "./copyButton";
import { initializeThemeToggle } from "./themeToggle";
import {
  initSidebarToggle,
  initSidebarResize,
  initSidebarScroll,
  initOverlayHandler,
  initEscapeHandler,
} from "./sidebar";

let lastInitializedPath: string | null = null;

function initialize(): void {
  const currentPath = window.location.pathname + window.location.search;
  if (lastInitializedPath === currentPath) return;
  lastInitializedPath = currentPath;

  removeTabindexFromPreElements();
  initSidebar();
  initSidebarToggle();
  addCopyButtons();

  // One-time global listeners
  initOnce("sidebar-resize", initSidebarResize);
  initOnce("sidebar-scroll", initSidebarScroll);
  initOnce("sidebar-overlay", initOverlayHandler);
  initOnce("sidebar-escape", initEscapeHandler);
}

// Event listeners
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initialize);
} else {
  initialize();
}

document.addEventListener("astro:page-load", initialize);
```

---

## Phase 7: Testing Improvements (Est: 4-6 hours)

### 7.1 Add Unit Tests for main.ts Functions

**New file:** `tests/unit/scripts/main.test.ts`

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { JSDOM } from "jsdom";

describe("main.ts", () => {
  let dom: JSDOM;

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <pre><code>const x = 1;</code></pre>
          <button id="theme-toggle"></button>
        </body>
      </html>
    `);
    global.document = dom.window.document;
    global.window = dom.window as unknown as Window & typeof globalThis;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("addCopyButtons", () => {
    it("should add copy button to code blocks", async () => {
      const { addCopyButtons } = await import("@/scripts/copyButton");
      addCopyButtons();

      const buttons = document.querySelectorAll(".copy-button");
      expect(buttons.length).toBe(1);
    });

    it("should not duplicate buttons on re-initialization", async () => {
      const { addCopyButtons } = await import("@/scripts/copyButton");
      addCopyButtons();
      addCopyButtons();

      const buttons = document.querySelectorAll(".copy-button");
      expect(buttons.length).toBe(1);
    });
  });

  describe("copyCode", () => {
    it("should copy text using clipboard API", async () => {
      const mockWriteText = vi.fn().mockResolvedValue(undefined);
      Object.assign(navigator, {
        clipboard: { writeText: mockWriteText },
      });

      // Test copy functionality
    });

    it("should fall back to legacy copy on API failure", async () => {
      // Test fallback
    });
  });
});
```

### 7.2 Add Unit Tests for navbar.ts Functions

**New file:** `tests/unit/scripts/navbar.test.ts`

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { JSDOM } from "jsdom";

describe("navbar", () => {
  describe("toggleDropdownState", () => {
    it("should toggle dropdown visibility", () => {
      // Test implementation
    });

    it("should update aria-expanded attribute", () => {
      // Test implementation
    });

    it("should set max-height on mobile", () => {
      // Test implementation
    });
  });

  describe("initMobileMenu", () => {
    it("should toggle menu on button click", () => {
      // Test implementation
    });
  });
});
```

### 7.3 Add Security Tests

**New file:** `tests/security/xss.test.ts`

```typescript
import { describe, it, expect } from "vitest";
import { escapeHtml } from "@/utils/htmlEscape";

describe("XSS Prevention", () => {
  const xssPayloads = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<iframe src="javascript:alert(1)">',
  ];

  xssPayloads.forEach((payload) => {
    it(`should escape: ${payload.substring(0, 30)}...`, () => {
      const escaped = escapeHtml(payload);
      expect(escaped).not.toContain("<script");
      expect(escaped).not.toContain("onerror=");
      expect(escaped).not.toContain("onload=");
      expect(escaped).not.toContain("javascript:");
    });
  });
});
```

### 7.4 Add Integration Tests

**New file:** `tests/integration/search.test.ts`

```typescript
import { describe, it, expect } from "vitest";
// Test search algorithm with various inputs
```

---

## Verification Checklist

After each phase, run:

```bash
# Type checking
npm run typecheck

# Linting
npm run lint

# Unit tests
npm run test:unit

# E2E tests
npm run test:e2e

# Build
npm run build
```

---

## Implementation Order

1. **Phase 1:** Quick Wins (2-3 hours)
   - Immediate value, low risk
   - Sets foundation for other phases

2. **Phase 2:** Constants (2-3 hours)
   - Enables cleaner Phase 4 refactoring
   - Improves maintainability

3. **Phase 3:** Use Utilities (1-2 hours)
   - Quick wins using existing code
   - Reduces duplication

4. **Phase 4:** Script Decomposition (4-6 hours)
   - Largest effort, highest impact
   - Should be done after Phases 1-3

5. **Phase 5:** Type System (2-3 hours)
   - Can be parallelized with Phase 4
   - Improves developer experience

6. **Phase 6:** State Refactor (2-3 hours)
   - Depends on Phase 4
   - Improves testability

7. **Phase 7:** Testing (4-6 hours)
   - Can start in parallel after Phase 1
   - Continuous throughout

---

## Success Criteria

- [ ] All linting passes (`npm run lint`)
- [ ] All type checks pass (`npm run typecheck`)
- [ ] All unit tests pass (`npm run test:unit`)
- [ ] All E2E tests pass (`npm run test:e2e`)
- [ ] Build succeeds (`npm run build`)
- [ ] No regression in functionality
- [ ] Code coverage maintained or improved (>96%)
- [ ] Cyclomatic complexity reduced (target: <10 per function)
- [ ] No duplicate code patterns
- [ ] All magic numbers replaced with constants
