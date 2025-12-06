/**
 * HTML escape utility for preventing XSS attacks.
 * Use this when inserting untrusted content into HTML.
 */

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
};

const HTML_ESCAPE_REGEX = /[&<>"']/g;

/**
 * Escapes HTML special characters to prevent XSS.
 *
 * @example
 * escapeHtml('<script>alert("xss")</script>')
 * // Returns: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
 */
export function escapeHtml(text: string | null | undefined): string {
  if (text == null) return "";
  return text.replace(HTML_ESCAPE_REGEX, (char) => {
    const escaped = HTML_ESCAPE_MAP[char];
    if (escaped === undefined) {
      throw new Error(`Unmapped character in escapeHtml: ${char}`);
    }
    return escaped;
  });
}
