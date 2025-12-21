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
**Port**: 80 (exposed)  
**Startup**: Nginx with `daemon off` for container process management

**Docker Script**: `./docker-run.sh`

- Supports integrated and standalone modes
- Configurable via environment variables: `SQLI_KB_NETWORK`, `SQLI_KB_PORT`, `SQLI_KB_SITE_URL`
- Checks prerequisites (Node, npm, Docker) before building
- Default port: 8080

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

## Configuration Files

- **`astro.config.mjs`** - Astro build config, dual-mode support (standalone/integrated), base path configuration, sitemap integration
- **`tsconfig.json`** - TypeScript strict mode, path aliases, include/exclude rules
- **`package.json`** - Dependencies, scripts, project metadata
- **`eslint.config.js`** - ESLint rules for JS, TS, Astro files
- **`.prettierrc.json`** - Code formatting rules
- **`.stylelintrc.json`** - CSS linting rules
- **`.markdownlint.json`** - Markdown validation rules
- **`nginx.conf`** - Nginx web server configuration
- **`.gitignore`** - Git exclusions
- **`.github/dependabot.yml`** - Automated dependency updates

## Main Entry Points

- **Development**: `npm run dev` starts Astro dev server on `http://localhost:3000`
- **Production**: Static site generated in `dist/` directory, served via Nginx
- **Routes**: Defined in `src/pages/` directory
- **Content**: Markdown articles in `src/content/` (collections-based)
