import { escapeHtml } from "../utils/htmlEscape";

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

  const baseUrl = container.dataset.baseUrl || "/";
  const searchDataJson = container.dataset.searchEntries || "[]";

  let searchData: SearchEntry[] = [];
  try {
    searchData = JSON.parse(searchDataJson);
  } catch {
    console.error("Failed to parse search data");
  }

  const searchInput = document.getElementById("search-input") as HTMLInputElement;
  const searchStatus = document.getElementById("search-status") as HTMLElement;
  const noResults = document.getElementById("no-results") as HTMLElement;
  const initialSearch = document.getElementById("initial-search") as HTMLElement;
  const resultsContainer = document.getElementById("results-container") as HTMLElement;

  if (!searchInput || !searchStatus || !noResults || !initialSearch || !resultsContainer) {
    console.error("Missing search DOM elements");
    return;
  }

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
      searchStatus.textContent = "";
      noResults.style.display = "none";
      initialSearch.style.display = "block";
      resultsContainer.innerHTML = "";
      return;
    }

    initialSearch.style.display = "none";

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
    searchStatus.textContent = `Found ${matches.length} ${matches.length === 1 ? "result" : "results"} for "${query}"`;

    if (matches.length === 0) {
      noResults.style.display = "block";
      resultsContainer.innerHTML = "";
      return;
    }

    noResults.style.display = "none";

    // Render results
    const collectionLabels: Record<string, string> = {
      mysql: "MySQL",
      mssql: "MSSQL",
      oracle: "Oracle",
      extras: "Other Resources",
    };

    let html = "";
    for (const [collection, entries] of Object.entries(grouped)) {
      html += `<div class="result-section">
        <h2>${escapeHtml(collectionLabels[collection] || collection)} (${entries.length})</h2>
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

    resultsContainer.innerHTML = html;
  }

  // Get query from URL
  const urlParams = new URLSearchParams(window.location.search);
  const queryParam = urlParams.get("q") || "";

  // Set input value and perform search
  searchInput.value = queryParam;
  performSearch(queryParam);

  // Update title if query exists
  if (queryParam) {
    const maxLen = 50;
    const truncated = queryParam.length > maxLen ? queryParam.slice(0, maxLen) + "…" : queryParam;
    document.title = `Search Results for "${escapeControlChars(truncated)}" - SQL Injection KB`;
  }
}

// Run on load
document.addEventListener("DOMContentLoaded", initSearch);
