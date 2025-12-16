# Linting Configuration

This document explains the linting rules that have been disabled or modified in this project.

## Markdownlint Disabled Rules

Configuration file: `.markdownlint.json`

| Rule  | Name                | Status               | Rationale                                                                                                               |
| ----- | ------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| MD013 | Line length         | Disabled (line 3)    | SQL injection payloads and code examples frequently exceed 80 characters; breaking them reduces readability             |
| MD033 | No inline HTML      | Disabled (line 4)    | Astro/MDX components require HTML elements for custom styling and interactive features                                  |
| MD041 | First line heading  | Disabled (line 5)    | All content files use YAML frontmatter (`---`), so the first line is never a heading                                    |
| MD060 | Code block language | Disabled (line 6)    | Some payload examples and generic text blocks don't fit a specific language identifier                                  |
| MD024 | Duplicate headings  | Modified (lines 7-9) | Set to `siblings_only: true` to allow same heading text in different sections (e.g., "Examples" under multiple parents) |

## ESLint Configuration

Configuration file: `eslint.config.js`

Standard ESLint configuration for JavaScript/TypeScript files. No notable disabled rules.

## Prettier Configuration

Configuration file: `.prettierrc.json`

Standard Prettier configuration for code formatting. Uses project defaults.
