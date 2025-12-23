/**
 * Dynamic robots.txt endpoint
 *
 * Generates robots.txt at build time with the correct sitemap URL
 * based on the configured site URL from environment variables.
 * This replaces the static /public/robots.txt file.
 */

import type { APIRoute } from "astro";
import { requireSiteUrl } from "../utils/siteUtils";

export const GET: APIRoute = ({ site }) => {
  const siteUrl = requireSiteUrl(site);

  // Build the sitemap URL based on the configured site
  const sitemapUrl = new URL("sitemap-index.xml", siteUrl).href;

  const robotsTxt = `# SQL Injection Knowledge Base - robots.txt
# https://developers.google.com/search/docs/crawling-indexing/robots/intro

User-agent: *
Allow: /

# Sitemap location (auto-generated from site configuration)
Sitemap: ${sitemapUrl}
`;

  return new Response(robotsTxt, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
};
