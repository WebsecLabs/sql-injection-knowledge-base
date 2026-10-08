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
  return text.replace(HTML_ESCAPE_PATTERN, (char) => HTML_ESCAPE_MAP[char]);
}

const SCRIPT_JSON_ESCAPE_MAP: Record<string, string> = {
  "<": "\\u003c",
  ">": "\\u003e",
  "&": "\\u0026",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029",
};

const SCRIPT_JSON_ESCAPE_PATTERN = /[<>&\u2028\u2029]/g;

/**
 * Serialize a value as JSON that is safe to embed inside a <script> element,
 * such as a JSON-LD block.
 *
 * JSON.stringify alone leaves "<" intact, so a string containing "</script>"
 * would end the element early. Escaping these characters as \uXXXX keeps the
 * output valid JSON with identical parsed values.
 *
 * @example
 * serializeJsonForScript({ name: "</script>" })
 * // Returns: '{"name":"\\u003c/script\\u003e"}'
 */
export function serializeJsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(
    SCRIPT_JSON_ESCAPE_PATTERN,
    (char) => SCRIPT_JSON_ESCAPE_MAP[char]
  );
}
