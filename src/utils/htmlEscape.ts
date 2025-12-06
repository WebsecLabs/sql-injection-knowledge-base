/**
 * HTML Escape Utility for XSS Prevention
 *
 * Escapes user-controlled content before inserting into HTML strings.
 */

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "/": "&#x2F;",
};

const HTML_ESCAPE_PATTERN = /[&<>"'/]/g;

/**
 * Escape HTML special characters to prevent XSS.
 *
 * @param text - Text to escape (null/undefined returns empty string)
 * @returns HTML-escaped text safe for insertion into HTML
 *
 * @example
 * escapeHtml('<script>alert("xss")</script>')
 * // Returns: '&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;'
 */
export function escapeHtml(text: string | null | undefined): string {
  if (text == null) {
    return "";
  }
  return text.replace(HTML_ESCAPE_PATTERN, (char) => HTML_ESCAPE_MAP[char] || char);
}
