/**
 * Dynamic robots.txt endpoint
 *
 * Generated at build time. Only the canonical deployment advertises a
 * sitemap, so copies of the site deployed elsewhere do not compete with the
 * official home. On websec.ca this file sits under the base path, so the
 * site's root robots.txt must also list the sitemap URL below.
 */

import type { APIRoute } from "astro";
import { CANONICAL_URL } from "astro:env/server";
import { requireSiteUrl, toCanonicalUrl } from "../utils/siteUtils";

export const GET: APIRoute = ({ site }) => {
  const siteUrl = requireSiteUrl(site);
  const baseUrl = import.meta.env.BASE_URL;
  const ownRoot = new URL(baseUrl, siteUrl).href;
  const isCanonical = ownRoot === toCanonicalUrl(baseUrl, baseUrl, CANONICAL_URL);

  const sitemap = isCanonical
    ? `# Sitemap location (auto-generated from site configuration)\nSitemap: ${ownRoot}sitemap-index.xml\n`
    : `# This copy is not the canonical deployment (${CANONICAL_URL}); no sitemap is advertised\n`;

  const robotsTxt = `# SQL Injection Knowledge Base - robots.txt
# https://developers.google.com/search/docs/crawling-indexing/robots/intro

User-agent: *
Allow: /

${sitemap}`;

  return new Response(robotsTxt, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
};
