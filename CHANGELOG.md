# Changelog

All notable changes to the SQL Injection Knowledge Base.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `handleOpacityTransition()` utility in `domUtils.ts` for DRY transition handling
- `DROPDOWN_TRANSITION_TIMEOUT_MS` constant in `uiConstants.ts` (eliminates magic number 250)
- Unit tests for `collectionLoader.ts` with mocked `astro:content`

### Changed

- Refactored navbar.ts to use shared transition utility (3 duplicate patterns removed)
- Upgraded to Astro 7, ESLint 10, Vitest 5, TypeScript 6 and current releases of all other dependencies
- Markdown is now processed by Astro's native Sätteri processor; the base-path link plugin was ported to a Sätteri hast plugin and `rehype-slug` was dropped in favour of built-in heading IDs
- SmartyPants is disabled so SQL syntax such as `--` and quotes renders literally in prose and headings
- CI now builds both modes and runs E2E and accessibility tests against the integrated build served by the production nginx image
- CI actions are pinned to commit SHAs; Dependabot now also tracks GitHub Actions and the Docker base image
- The nginx base image is pinned by version and digest

### SEO and performance

- Canonical URLs, Open Graph URLs and structured data always point at the official home on websec.ca; set `CANONICAL_URL` to make another deployment canonical. Only the canonical deployment publishes a sitemap
- Real 404 responses with a dedicated, non-indexed 404 page; unknown URLs no longer return the home page
- Every internal link ends with a trailing slash, matching the canonical URLs, so no link goes through a redirect (`trailingSlash: "always"`)
- Build-time link checker fails the build on internal links to missing pages, headings or slashless page URLs
- Sitemap excludes redirect and error pages and reports each entry's `lastUpdated` date
- robots.txt points to the sitemap under the base path
- Fonts are served through Astro's Fonts API from the installed Fontsource packages, Latin subsets only, with metric-matched fallbacks and `font-display: optional`, so text never shifts while loading
- Page CSS is inlined, and per-card view-transition styles were replaced with native `view-transition-name` values, cutting the home page from 1.3 MB to 200 KB
- The logo is served as sized WebP at 1x and 2x
- The search page bundles the Pagefind UI, so it is served from hashed, long-cached URLs
- nginx sends long-lived caching headers for hashed assets
- Lighthouse: 100 for accessibility, best practices, SEO and agentic browsing on every page; performance 100 on desktop and 96-98 on simulated mobile

### Security

- Content-Security-Policy generated at build time from the site's inline script hashes, embedded in every page as a `<meta>` tag and sent by the nginx image as a header with `frame-ancestors` and violation reporting
- Build-time content guard: raw HTML in Markdown is parsed and the build fails on executable elements, inline event handlers or script-capable URLs
- Structured data is serialized with `<`, `>` and `&` escaped for safe embedding in `<script>` elements
- The Docker image runs nginx as an unprivileged user and no longer advertises the nginx version
- Assets and scripts are emitted as files rather than inlined, so the CSP needs no `data:` script or font sources

### Fixed

- Full search page (`/search`) failed to load results when the site is served under a base path
- Theme toggle no longer breaks when browser storage is unavailable
- Broken internal links in the PostgreSQL, MySQL and MariaDB articles
- Copy button text contrast on code blocks, and previous/next link names that did not match their visible text
- The search page script no longer runs on other pages after visiting search

## [1.1.0] - 2025-01

### Added

- Retractable table of contents for content pages
- MariaDB SQL injection knowledge base (complete collection)
- Collection index redirects for cleaner URLs

### Changed

- Improved accessibility with proper ARIA attributes
- Enhanced code quality and View Transitions stability

### Fixed

- Navbar not covering headings on TOC navigation
- Dropdown menu race condition on desktop hover/click interaction
- MariaDB documentation accuracy corrections
- Node.js version pinning for consistent builds

## [1.0.0] - 2024-12

### Added

- Initial release with MySQL, MSSQL, Oracle, PostgreSQL coverage
- Full-text search with highlighted results
- Dark/light theme toggle with localStorage persistence
- Responsive sidebar with mobile hamburger menu
- Code block copy functionality
- Comprehensive E2E test suite with Playwright
- Unit test coverage with Vitest

### Features

- 4 database collections: MySQL, MSSQL, Oracle, PostgreSQL
- Extras collection for additional resources
- Category-based navigation
- Previous/next article navigation
- Mobile-first responsive design

### Technical

- Built with Astro 5.x and TypeScript
- View Transitions API for smooth navigation
- Docker support for development and testing
- GitHub Actions CI/CD pipeline
