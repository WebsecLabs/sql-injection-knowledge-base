/**
 * Tests for the build-time Content-Security-Policy
 * @vitest-environment node
 */
import { describe, expect, it } from "vitest";
import { buildContentSecurityPolicy } from "../../../src/plugins/csp-integration.mjs";

const HASH = "'sha256-abc='";

function directive(policy: string, name: string): string | undefined {
  return policy.split("; ").find((part) => part.startsWith(`${name} `));
}

describe("buildContentSecurityPolicy", () => {
  it("allows only same-origin scripts and connections by default", () => {
    const policy = buildContentSecurityPolicy([HASH]);

    expect(directive(policy, "script-src")).toBe(`script-src 'self' 'wasm-unsafe-eval' ${HASH}`);
    expect(directive(policy, "connect-src")).toBe("connect-src 'self'");
    expect(policy).not.toContain("cloudflareinsights");
  });

  it("allows the Cloudflare Web Analytics beacon when enabled", () => {
    const policy = buildContentSecurityPolicy([HASH], { cloudflareAnalytics: true });

    expect(directive(policy, "script-src")).toBe(
      `script-src 'self' 'wasm-unsafe-eval' https://static.cloudflareinsights.com ${HASH}`
    );
    expect(directive(policy, "connect-src")).toBe(
      "connect-src 'self' https://cloudflareinsights.com"
    );
  });

  it("keeps the other directives unchanged when analytics is enabled", () => {
    const strict = buildContentSecurityPolicy([HASH]).split("; ");
    const withAnalytics = buildContentSecurityPolicy([HASH], { cloudflareAnalytics: true }).split(
      "; "
    );

    const others = (parts: string[]) =>
      parts.filter((part) => !/^(script|connect)-src /.test(part));
    expect(others(withAnalytics)).toEqual(others(strict));
  });
});
