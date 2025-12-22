---
description: Repository Information Overview
alwaysApply: true
---

# SQL Injection Knowledge Base Information

## Summary

A modern, comprehensive educational resource for SQL injection techniques, vulnerabilities, and defenses across multiple database platforms (MySQL, MariaDB, MSSQL, Oracle, PostgreSQL). Built as a fast, responsive static site with Astro, designed for security professionals and developers.

## Structure

- **`src/`** - Main Astro source directory
  - **`components/`** - Reusable Astro components
  - **`layouts/`** - Page layout templates
  - **`pages/`** - Route-based pages and API endpoints
  - **`content/`** - Markdown files for knowledge base articles
  - **`assets/`** - Images, fonts, and static resources
  - **`data/`** - Data files for site configuration
  - **`scripts/`** - Client-side utility scripts
  - **`styles/`** - CSS styling
  - **`plugins/`** - Custom Astro plugins (e.g., remark-base-path)
  - **`utils/`** - Utility functions and helpers
- **`public/`** - Static assets (favicon, etc.)
- **`dist/`** - Built static site output
- **`tests/`** - Test suites
  - **`unit/`** - Unit tests (Vitest)
  - **`e2e/`** - End-to-end tests (Playwright)
- **`docs/`** - Development documentation (linting config)

## Language & Runtime

**Language**: TypeScript / JavaScript
**Node.js Version**: 20.0.0+ (LTS recommended, see `.nvmrc`)
**Build System**: Astro with Vite  
**Package Manager**: npm  
**TypeScript Config**: Strict mode with path aliases (`@/*` → `./src/*`)

## Dependencies

**Main Dependencies**:

- `astro@^5.16.4` - Static site generator and framework
- `@astrojs/sitemap@^3.6.0` - Sitemap generation integration
- `@fontsource/inter@^5.2.8` - Inter font
- `@fontsource/jetbrains-mono@^5.2.8` - JetBrains Mono font

**Development Dependencies**:

- `@astrojs/check@^0.9.6` - TypeScript checking for Astro
- `typescript@^5.9.3` - TypeScript compiler
- `eslint@^9.39.1` + `eslint-plugin-astro@^1.5.0` - Linting
- `prettier@^3.6.2` + `prettier-plugin-astro@^0.14.1` - Code formatting
- `stylelint@^16.26.1` - CSS linting
- `markdownlint-cli@^0.46.0` - Markdown linting
- `typescript-eslint@^8.48.0` - TypeScript ESLint integration
- `cross-env@^10.1.0` - Cross-platform environment variables
- `vite-tsconfig-paths@^5.1.4` - Vite TypeScript path resolution
- `vitest@^4.0.16` + `@vitest/coverage-v8` - Unit testing framework
- `@playwright/test@^1.57.0` - E2E browser testing
- `jsdom@^27.3.0` - DOM environment for unit tests

## Build & Installation

```bash
# Install dependencies
npm install

# Development server (port 3000)
npm run dev
npm run start

# Production build
npm run build

# Standalone build (self-contained, requires SITE_URL)
SITE_URL=http://localhost:3000 npm run build:standalone

# Preview production build
npm run preview
```

## Docker

**Dockerfile**: `./Dockerfile`
**Base Image**: `nginx:alpine`
**Configuration**: Custom Nginx config at `./nginx.conf`
**Build**: Copies pre-built static files from `dist/` to Nginx html directory
**Container Port**: 80 (Nginx listens inside the container)
**Startup**: Nginx with `daemon off` for container process management

**Docker Script**: `./docker-run.sh`

- Supports integrated and standalone modes
- Checks prerequisites (Node, npm, Docker) before building
- **Port Mapping**: `SQLI_KB_PORT` (host) → container port 80
  - Default: `localhost:8080` → container:80
  - Access the site at `http://localhost:8080` (or custom `SQLI_KB_PORT`)
- **Environment Variables**:
  - `SQLI_KB_PORT` - Host port to expose (default: 8080)
  - `SQLI_KB_NETWORK` - Docker network to join (default: websec-site_websec-network)
  - `SQLI_KB_SITE_URL` - Site URL for standalone mode (default: `http://localhost:$PORT`)

## Code Quality & Validation

**Linting**:

```bash
npm run lint       # Run all linters (ESLint, Stylelint, MarkdownLint, Prettier)
npm run lint:fix   # Fix all linting issues
```

**Type Checking**:

```bash
npm run typecheck  # Astro TypeScript validation
```

**Linters**:

- **ESLint**: JavaScript/TypeScript linting with Astro plugin support
- **Stylelint**: CSS validation (standard config)
- **MarkdownLint**: Markdown content validation in `src/content/**/*.md`
- **Prettier**: Code formatting
- **Configuration files**: `.eslintignore`, `.stylelintrc.json`, `.markdownlint.json`, `.prettierrc.json`

## Testing

**Test Frameworks**:

- **Vitest** - Unit testing framework (fast, Vite-native)
- **Playwright** - End-to-end browser testing

**Test Locations**:

- **`tests/unit/`** - Unit tests (Vitest)
  - `tests/unit/scripts/` - Client-side script tests
  - `tests/unit/utils/` - Utility function tests
- **`tests/e2e/`** - End-to-end tests (Playwright)
- **`tests/mocks/`** - Shared test mocks
- **`tests/setup.ts`** - Test setup configuration

**Test Commands**:

```bash
# Unit tests
npm run test:unit           # Run unit tests once
npm run test:unit:watch     # Run in watch mode
npm run test:unit:coverage  # Run with coverage report
npm run test:unit:ui        # Run with Vitest UI

# E2E tests (requires built site)
npm run test:e2e            # Run E2E tests
npm run test:e2e:ui         # Run with Playwright UI
npm run test:e2e:headed     # Run in headed browser mode

# All tests
npm run test:all            # Run unit + E2E tests
```

**E2E Test Prerequisites**:

```bash
# Install Playwright browsers (first time only)
npx playwright install

# Build the site before running E2E tests
npm run build:standalone
# Or use Docker: ./docker-run.sh
```

## CI/CD

**Workflow File**: `.github/workflows/ci.yml`

The CI pipeline runs automatically on push/PR to `main` branch:

| Job | Description | Commands |
|-----|-------------|----------|
| **Lint & Type Check** | Code quality validation | `npm run lint`, `npm run typecheck` |
| **Unit Tests** | Vitest with coverage | `npm run test:unit:coverage` |
| **Build** | Production build (after lint/unit pass) | `npm run build:standalone` |
| **E2E Tests** | Playwright browser tests (after build) | `npx playwright test` |

**CI Environment Variables**:

- `SITE_URL` - Repository variable for sitemap generation (defaults to `https://ci.example.com`)
- `BASE_URL` - Set to `http://localhost:8080/` for E2E tests

**Artifacts**: Coverage reports and build artifacts are uploaded and retained for 7 days.

## Configuration Files

- **`astro.config.mjs`** - Astro build config, dual-mode support (standalone/integrated), base path configuration, sitemap integration
- **`tsconfig.json`** - TypeScript strict mode, path aliases, include/exclude rules
- **`package.json`** - Dependencies, scripts, project metadata
- **`eslint.config.js`** - ESLint rules for JS, TS, Astro files
- **`.prettierrc.json`** - Code formatting rules
- **`.stylelintrc.json`** - CSS linting rules
- **`.markdownlint.json`** - Markdown validation rules
- **`nginx.conf`** - Nginx web server configuration
- **`vitest.config.ts`** - Vitest unit test configuration
- **`playwright.config.ts`** - Playwright E2E test configuration
- **`.gitignore`** - Git exclusions
- **`.github/workflows/ci.yml`** - CI/CD pipeline configuration
- **`.github/dependabot.yml`** - Automated dependency updates

## Main Entry Points

- **Development**: `npm run dev` starts Astro dev server on `http://localhost:3000`
- **Production**: Static site generated in `dist/` directory, served via Nginx
- **Routes**: Defined in `src/pages/` directory
- **Content**: Markdown articles in `src/content/` (collections-based)
