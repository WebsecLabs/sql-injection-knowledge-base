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

    it("escapes forward slash", () => {
      expect(escapeHtml("path/to/file")).toBe("path&#x2F;to&#x2F;file");
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
