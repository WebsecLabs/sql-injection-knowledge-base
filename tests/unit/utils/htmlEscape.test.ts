import { describe, it, expect } from "vitest";
import { escapeHtml } from "../../../src/utils/htmlEscape";

describe("escapeHtml", () => {
  describe("XSS prevention", () => {
    it("escapes script tags", () => {
      const input = '<script>alert("xss")</script>';
      const result = escapeHtml(input);

      expect(result).toBe("&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;");
      expect(result).not.toContain("<script>");
      expect(result).not.toContain("</script>");
    });

    it("escapes HTML event handlers", () => {
      const input = '<img onerror="alert(1)" src="x">';
      const result = escapeHtml(input);

      // The function escapes HTML special chars, preventing injection
      expect(result).toBe("&lt;img onerror=&quot;alert(1)&quot; src=&quot;x&quot;&gt;");
      // The < and > are escaped, preventing HTML parsing
      expect(result).not.toContain("<img");
      expect(result).not.toContain(">");
    });

    it("escapes embedded JavaScript URLs", () => {
      const input = '<a href="javascript:alert(1)">Click</a>';
      const result = escapeHtml(input);

      // HTML chars are escaped, preventing the anchor from being parsed as HTML
      expect(result).not.toContain("<a");
      expect(result).not.toContain("</a>");
      expect(result).toContain("&lt;a");
    });
  });

  describe("character escaping", () => {
    it("escapes ampersand", () => {
      expect(escapeHtml("foo & bar")).toBe("foo &amp; bar");
    });

    it("escapes less than", () => {
      expect(escapeHtml("a < b")).toBe("a &lt; b");
    });

    it("escapes greater than", () => {
      expect(escapeHtml("a > b")).toBe("a &gt; b");
    });

    it("escapes double quotes", () => {
      expect(escapeHtml('say "hello"')).toBe("say &quot;hello&quot;");
    });

    it("escapes single quotes", () => {
      expect(escapeHtml("it's fine")).toBe("it&#39;s fine");
    });

    it("escapes forward slash (defensive - optional per OWASP)", () => {
      // Note: Forward slash escaping is a defense-in-depth measure, not strictly
      // required by current OWASP guidance. However, this implementation escapes
      // slashes to prevent potential edge cases like closing script tags (</script>)
      // in certain contexts. This is a deliberate security-first design choice.
      expect(escapeHtml("path/to/file")).toBe("path&#x2F;to&#x2F;file");
    });

    it("treats entity-like strings as literal text and escapes their ampersands", () => {
      // The function treats all input as literal text, including strings that
      // look like HTML entities. This means "&amp;" is treated as the literal
      // characters '&', 'a', 'm', 'p', ';' - and the '&' gets escaped to "&amp;".
      // This prevents double-decoding attacks where pre-escaped input could be
      // decoded multiple times.
      expect(escapeHtml("&amp;")).toBe("&amp;amp;");
      expect(escapeHtml("&lt;script&gt;")).toBe("&amp;lt;script&amp;gt;");
    });

    it("escapes multiple special characters", () => {
      expect(escapeHtml('<a href="test">Link</a>')).toBe(
        "&lt;a href=&quot;test&quot;&gt;Link&lt;&#x2F;a&gt;"
      );
    });
  });

  describe("null/undefined handling", () => {
    it("returns empty string for null", () => {
      expect(escapeHtml(null)).toBe("");
    });

    it("returns empty string for undefined", () => {
      expect(escapeHtml(undefined)).toBe("");
    });
  });

  describe("safe input passthrough", () => {
    it("returns empty string unchanged", () => {
      expect(escapeHtml("")).toBe("");
    });

    it("returns alphanumeric text unchanged", () => {
      expect(escapeHtml("Hello World 123")).toBe("Hello World 123");
    });

    it("returns unicode text unchanged", () => {
      expect(escapeHtml("Caf\u00e9 \ud83d\udc4d")).toBe("Caf\u00e9 \ud83d\udc4d");
    });
  });
});
