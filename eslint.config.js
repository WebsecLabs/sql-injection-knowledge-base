import js from "@eslint/js";
import astroPlugin from "eslint-plugin-astro";
import astroParser from "astro-eslint-parser";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  // Ignore patterns
  {
    ignores: ["node_modules/", "dist/", ".astro/", "public/", "**/*.min.js"],
  },
  // Apply to all JS/TS files
  {
    files: ["**/*.js", "**/*.ts", "**/*.tsx"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.es2021,
        Astro: "readonly",
      },
    },
    rules: {
      ...js.configs.recommended.rules,
    },
  },
  // TypeScript files - use typescript-eslint recommended config
  ...tseslint.configs.recommended,
  // TypeScript-specific overrides for unused vars
  {
    files: ["**/*.ts", "**/*.tsx"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
  // Astro files
  ...astroPlugin.configs.recommended,
  {
    files: ["**/*.astro"],
    languageOptions: {
      parser: astroParser,
      parserOptions: {
        parser: tseslint.parser,
        extraFileExtensions: [".astro"],
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
    rules: {
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
];
