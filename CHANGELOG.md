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
