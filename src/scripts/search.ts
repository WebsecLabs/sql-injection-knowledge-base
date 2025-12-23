import { escapeHtml } from "../utils/htmlEscape";
import { COLLECTION_SEARCH_LABELS } from "../utils/constants";
import { debounce } from "../utils/domUtils";
import { SEARCH_DEBOUNCE_MS, SEARCH_TITLE_MAX_LENGTH } from "../utils/uiConstants";

interface SearchEntry {
  slug: string;
  title: string;
  description?: string;
  category: string;
  tags?: string[];
  collection: string;
}

export function initSearch() {
  const container = document.querySelector(".search-results") as HTMLElement;
  if (!container) return;

  // Prevent duplicate initialization on the same container
  if (container.dataset.initialized === "true") return;

  const baseUrl = container.dataset.baseUrl || "/";
  const searchDataJson = container.dataset.searchEntries || "[]";

  let searchData: SearchEntry[] = [];
  try {
    searchData = JSON.parse(searchDataJson);
  } catch {
    console.error("Failed to parse search data");
  }

  const searchInput = container.querySelector('input[name="q"]') as HTMLInputElement | null;
  const searchStatus = container.querySelector("#search-status") as HTMLElement | null;
  const noResults = container.querySelector("#no-results") as HTMLElement | null;
  const initialSearch = container.querySelector("#initial-search") as HTMLElement | null;
  const resultsContainer = container.querySelector("#results-container") as HTMLElement | null;

  if (!searchInput || !searchStatus || !noResults || !initialSearch || !resultsContainer) {
    console.error("Missing search DOM elements");
    return;
  }

  // Ensure status region is polite for screen readers
  searchStatus.setAttribute("aria-live", "polite");

  // Highlight matching text
  function highlightText(text: string, query: string): string {
    if (!query || !text) return escapeHtml(text || "");
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();

    const matches: Array<{ start: number; end: number }> = [];
    let pos = 0;
    while ((pos = lowerText.indexOf(lowerQuery, pos)) !== -1) {
      matches.push({ start: pos, end: pos + lowerQuery.length });
      pos += lowerQuery.length;
    }

    if (matches.length === 0) return escapeHtml(text);

    let result = "";
    let lastEnd = 0;
    for (const match of matches) {
      result += escapeHtml(text.slice(lastEnd, match.start));
      result +=
        `<mark class="highlight-mark">` +
        escapeHtml(text.slice(match.start, match.end)) +
        "</mark>";
      lastEnd = match.end;
    }
    result += escapeHtml(text.slice(lastEnd));
    return result;
  }

  // Escape control characters for safe text insertion
  function escapeControlChars(text: string): string {
    // eslint-disable-next-line no-control-regex
    return text.replace(/[\x00-\x1F\x7F-\x9F]/g, "");
  }

  // Search function
  function performSearch(query: string) {
    const normalizedQuery = query.toLowerCase().trim();

    if (!normalizedQuery) {
      searchStatus!.textContent = "";
      noResults!.style.display = "none";
      initialSearch!.style.display = "block";
      resultsContainer!.innerHTML = "";
      return;
    }

    initialSearch!.style.display = "none";

    // Filter entries
    const matches = searchData.filter((entry) => {
      const titleMatch = entry.title.toLowerCase().includes(normalizedQuery);
      const descMatch = entry.description?.toLowerCase().includes(normalizedQuery) || false;
      const categoryMatch = entry.category.toLowerCase().includes(normalizedQuery);
      const tagsMatch = entry.tags?.some((t) => t.toLowerCase().includes(normalizedQuery)) || false;
      return titleMatch || descMatch || categoryMatch || tagsMatch;
    });

    // Group by collection
    const grouped: Record<string, SearchEntry[]> = {};
    for (const entry of matches) {
      if (!grouped[entry.collection]) grouped[entry.collection] = [];
      grouped[entry.collection].push(entry);
    }

    // Update UI
    searchStatus!.textContent = `Found ${matches.length} ${matches.length === 1 ? "result" : "results"} for "${query}"`;

    if (matches.length === 0) {
      noResults!.style.display = "block";
      resultsContainer!.innerHTML = "";
      return;
    }

    noResults!.style.display = "none";

    // Render results
    let html = "";
    for (const [collection, entries] of Object.entries(grouped)) {
      const label =
        COLLECTION_SEARCH_LABELS[collection as keyof typeof COLLECTION_SEARCH_LABELS] || collection;
      html += `<div class="result-section">
        <h2>${escapeHtml(label)} (${entries.length})</h2>
        <ul class="result-list">`;

      for (const entry of entries) {
        const href = escapeHtml(`${baseUrl}${collection}/${entry.slug}`);
        html += `<li>
          <a href="${href}" class="result-card">
            <div class="result-title">${highlightText(entry.title, normalizedQuery)}</div>
            <div class="result-category">${escapeHtml(entry.category)}</div>
            ${entry.description ? `<div class="result-description">${highlightText(entry.description, normalizedQuery)}</div>` : ""}
            ${entry.tags?.length ? `<div class="result-tags">${entry.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
          </a>
        </li>`;
      }

      html += `</ul></div>`;
    }

    resultsContainer!.innerHTML = html;
  }

  // Debounced search handler
  const performSearchDebounced = debounce(performSearch, SEARCH_DEBOUNCE_MS);

  // Get query from URL
  const urlParams = new URLSearchParams(window.location.search);
  const queryParam = urlParams.get("q") || "";

  // Set input value and perform search immediately if URL param exists
  searchInput.value = queryParam;
  if (queryParam) {
    performSearch(queryParam);
    // Update title
    const maxLen = SEARCH_TITLE_MAX_LENGTH;
    const truncated = queryParam.length > maxLen ? queryParam.slice(0, maxLen) + "…" : queryParam;
    document.title = `Search Results for "${escapeControlChars(truncated)}" - SQL Injection KB`;
  }
  // Note: No else branch needed - UI starts in initial state and performSearch("")
  // would just reset to the same initial state, which is redundant

  // Add input listener with debounce
  searchInput.addEventListener("input", (e) => {
    const target = e.target as HTMLInputElement;
    performSearchDebounced(target.value);
  });

  // Mark as initialized only after successful setup
  container.dataset.initialized = "true";
}

// Note: Event listeners are set up in search.astro to ensure the module is not tree-shaken
