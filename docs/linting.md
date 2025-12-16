# Linting Configuration

This document explains the linting rules that have been disabled or modified in this project.

## Markdownlint Disabled Rules

Configuration file: `.markdownlint.json`

| Rule  | Name                | Status   | Rationale                                                                                                               |
| ----- | ------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| MD013 | Line length         | Disabled | SQL injection payloads and code examples frequently exceed 80 characters; breaking them reduces readability             |
| MD033 | No inline HTML      | Disabled | Astro/MDX components require HTML elements for custom styling and interactive features                                  |
| MD041 | First line heading  | Disabled | All content files use YAML frontmatter (`---`), so the first line is never a heading                                    |
| MD060 | Code block language | Disabled | Some payload examples and generic text blocks don't fit a specific language identifier                                  |
| MD024 | Duplicate headings  | Modified | Set to `siblings_only: true` to allow same heading text in different sections (e.g., "Examples" under multiple parents) |

## ESLint Configuration

Configuration file: `eslint.config.js`

Uses the flat config format with TypeScript and Astro support.

**Ignored paths:**

- `node_modules/`, `dist/`, `.astro/`, `public/`, `**/*.min.js`

**Applied configurations:**

| Config                            | Scope                   | Description                        |
| --------------------------------- | ----------------------- | ---------------------------------- |
| `@eslint/js` recommended          | `*.js`, `*.ts`, `*.tsx` | Standard JavaScript best practices |
| `typescript-eslint` recommended   | `*.ts`, `*.tsx`         | TypeScript-specific rules          |
| `eslint-plugin-astro` recommended | `*.astro`               | Astro component linting            |

**Custom rules:**

| Rule                                | Setting                                              | Rationale                                                                |
| ----------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------ |
| `@typescript-eslint/no-unused-vars` | `argsIgnorePattern: "^_"`, `varsIgnorePattern: "^_"` | Variables prefixed with `_` are intentionally unused (common convention) |

**Global variables:**

- Browser, Node.js, and ES2021 globals enabled
- `Astro` defined as readonly global

## Prettier Configuration

Configuration file: `.prettierrc.json`

**Formatting standards:**

| Option          | Value   | Description                                          |
| --------------- | ------- | ---------------------------------------------------- |
| `printWidth`    | `100`   | Line width before wrapping                           |
| `tabWidth`      | `2`     | 2-space indentation                                  |
| `semi`          | `true`  | Always use semicolons                                |
| `singleQuote`   | `false` | Use double quotes for strings                        |
| `trailingComma` | `es5`   | Trailing commas where valid in ES5 (objects, arrays) |

**Astro support:**

Uses `prettier-plugin-astro` with the `astro` parser for `.astro` files.
